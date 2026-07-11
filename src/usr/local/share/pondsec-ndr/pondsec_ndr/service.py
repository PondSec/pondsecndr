"""PondSec NDR backend service."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
import grp
import os
from pathlib import Path
import pwd
import resource
import signal
import time
from typing import Any

from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.collectors.filterlog import FilterLogCollector
from pondsec_ndr.config import PondSecConfig, ensure_directories, load_config
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import default_detectors
from pondsec_ndr.features.aggregator import aggregate_features
from pondsec_ndr.logging_json import configure_logging
from pondsec_ndr.response.engine import ResponseDenied, activate_block, propose_block_for_incident
from pondsec_ndr.storage.database import EventStore


class PondSecService:
    def __init__(self, config: PondSecConfig | None = None) -> None:
        self.config = config or load_config()
        ensure_directories(self.config)
        self.logger = configure_logging(self.config.log_dir, self.config.debug_logging)
        self.store = EventStore(self.config.data_dir / "pondsec-ndr.db")
        self.store.migrate()
        self._ensure_learning_started_at()
        self.stop_requested = False
        self.started_at = time.time()
        self.counters: dict[str, Any] = {
            "events": 0,
            "detections": 0,
            "incidents": 0,
            "parser_errors": 0,
            "queue_drops": 0,
            "last_collector_errors": [],
            "last_optional_collector_errors": [],
            "last_ml_errors": [],
            "last_response_errors": [],
            "incident_rate_timestamps": [],
            "pf_action_rate_timestamps": [],
        }

    def _ensure_learning_started_at(self) -> None:
        if self.config.detection.learning_started_at:
            return
        marker = self.config.data_dir / "learning_started_at"
        try:
            value = marker.read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if value:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                value = ""
        if not value:
            value = self.store.learning_started_at_candidate() or datetime.now(timezone.utc).isoformat()
            try:
                marker.write_text(value + "\n", encoding="utf-8")
                self._chown_to_service_user(marker)
            except OSError as exc:
                self.logger.warning(
                    "learning start marker cannot be saved",
                    extra={"component": "service", "event": "learning_marker_error", "error": str(exc)},
                )
        self.config.detection.learning_started_at = value

    @staticmethod
    def _chown_to_service_user(path: Path) -> None:
        if os.geteuid() != 0:
            return
        try:
            user = pwd.getpwnam("pondsecndr")
            group = grp.getgrnam("pondsecndr")
        except KeyError:
            return
        try:
            os.chown(path, user.pw_uid, group.gr_gid)
        except OSError:
            return

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)

    def _request_stop(self, signum: int, frame: Any) -> None:
        del signum, frame
        self.stop_requested = True

    def run_forever(self, interval: float = 2.0) -> None:
        self.install_signal_handlers()
        self._write_health("healthy")
        while not self.stop_requested:
            try:
                self.run_once()
            except Exception as exc:
                message = f"service loop error: {exc}"
                self.counters["last_collector_errors"] = ([message] + self.counters["last_collector_errors"])[:5]
                self.logger.exception(message, extra={"component": "service", "event": "loop_error", "error_code": "service_loop_error"})
                self._write_health("degraded", {"last_error": message})
            time.sleep(interval)
        self._write_health("stopped")

    def run_once(self, max_lines: int = 1000) -> dict[str, Any]:
        started_wall = time.time()
        started_cpu = time.process_time()
        collector_queue_limit = min(self.config.max_event_rate, 100000)
        collector = EveCollector(
            Path(self.config.suricata_eve_path),
            self.config.data_dir / "collector_offsets" / "suricata_eve.json",
            queue_limit=collector_queue_limit,
        )
        events, stats = collector.read_once(max_lines=max_lines)
        filter_collector = FilterLogCollector(
            Path("/var/log/filter/latest.log"),
            self.config.data_dir / "collector_offsets" / "opnsense_filterlog.json",
            queue_limit=collector_queue_limit,
        )
        filter_events, filter_stats = filter_collector.read_once(max_lines=max_lines)
        events.extend(filter_events)
        events = self._filter_events(events)
        events, backpressure_drops = self._apply_queue_backpressure(events)
        parser_errors = stats.parser_errors + (filter_stats.parser_errors if filter_stats else 0)
        normalization_errors = stats.normalization_errors + (filter_stats.normalization_errors if filter_stats else 0)
        queue_drops = stats.queue_drops + (filter_stats.queue_drops if filter_stats else 0) + backpressure_drops
        self.counters["parser_errors"] += parser_errors
        self.counters["queue_drops"] += queue_drops
        if stats.last_error:
            self.counters["last_collector_errors"] = ([stats.last_error] + self.counters["last_collector_errors"])[:5]
        if filter_stats and filter_stats.last_error:
            self.counters["last_optional_collector_errors"] = (
                [filter_stats.last_error] + self.counters["last_optional_collector_errors"]
            )[:5]

        if self._database_over_limit():
            cleaned = self.store.cleanup(self.config.retention_days)
            if self._database_over_limit():
                self.counters["queue_drops"] += len(events)
                resource_usage = self._resource_usage(started_wall, started_cpu)
                self._write_health("degraded", {
                    "backpressure": "database_size_limit",
                    "dropped_events": len(events),
                    "cleanup_deleted": cleaned,
                    "queue_size": len(events),
                    "resource_usage": resource_usage,
                    "resource_warnings": self._resource_warnings(resource_usage),
                })
                return {
                    "status": "degraded",
                    "reason": "database_size_limit",
                    "dropped_events": len(events),
                    "cleanup_deleted": cleaned,
                }

        inserted_events = self.store.insert_events(events)
        features = self.store.score_features_against_baselines(
            aggregate_features(events),
            minimum_observations=self.config.detection.minimum_observations,
        )
        self.store.insert_features(features)

        learning_status = self.config.detection.learning_status()
        detections: list[dict[str, Any]] = []
        if learning_status.get("active"):
            learning_suppressed_detectors = [getattr(detector, "detector_id", "") for detector in default_detectors()]
            enabled_detectors = []
        else:
            enabled_detectors, learning_suppressed_detectors = self._enabled_detectors(learning_status)
            for detector in enabled_detectors:
                detections.extend(detector.detect(events, features))
        inserted_detections = self.store.insert_detections(detections)

        incidents = correlate_detections(detections, window_seconds=self.config.detection.correlation_window_minutes * 60)
        incidents, suppressed_incidents = self._limit_rate(
            incidents,
            "incident_rate_timestamps",
            self.config.incident_rate_limit_per_minute,
        )
        inserted_incidents = self.store.insert_incidents(incidents)
        anomalous_sources = self._baseline_skip_sources(detections)
        baseline_updates = self.store.update_host_baselines(features, skip_sources=anomalous_sources)
        response_actions = self._auto_response(incidents)
        cleaned = self.store.cleanup(self.config.retention_days)
        resource_usage = self._resource_usage(started_wall, started_cpu)
        resource_warnings = self._resource_warnings(resource_usage)

        self.counters["events"] += inserted_events
        self.counters["detections"] += inserted_detections
        self.counters["incidents"] += inserted_incidents
        status = "healthy"
        if stats.last_error and not events:
            status = "degraded"
        if suppressed_incidents or backpressure_drops:
            status = "degraded" if status == "healthy" else status
        self._write_health(status, {
            "read_lines": stats.read_lines + (filter_stats.read_lines if filter_stats else 0),
            "accepted_events": stats.accepted_events + (filter_stats.accepted_events if filter_stats else 0),
            "inserted_events": inserted_events,
            "inserted_detections": inserted_detections,
            "inserted_incidents": inserted_incidents,
            "suppressed_incidents": suppressed_incidents,
            "response_actions": response_actions,
            "baseline_updates": baseline_updates,
            "cleanup_deleted": cleaned,
            "parser_errors": self.counters["parser_errors"],
            "normalization_errors": normalization_errors,
            "queue_drops": self.counters["queue_drops"],
            "queue_size": len(events),
            "max_queue_length": self.config.max_queue_length,
            "resource_usage": resource_usage,
            "resource_warnings": resource_warnings,
            "learning_status": learning_status,
            "learning_collection_only": bool(learning_status.get("active")),
            "learning_suppressed_detectors": learning_suppressed_detectors,
            "optional_collector_warnings": self.counters["last_optional_collector_errors"],
            "limits": {
                "max_event_rate": self.config.max_event_rate,
                "max_queue_length": self.config.max_queue_length,
                "max_database_mb": self.config.max_database_mb,
                "incident_rate_limit_per_minute": self.config.incident_rate_limit_per_minute,
                "pf_action_rate_limit_per_minute": self.config.pf_action_rate_limit_per_minute,
            },
            "rotation_detected": stats.rotation_detected or (filter_stats.rotation_detected if filter_stats else False),
            "collector_sources": {
                "suricata_eve": asdict(stats),
                "opnsense_filterlog": asdict(filter_stats) if filter_stats else None,
            },
        })
        return {
            "status": status,
            "collector": {
                "suricata_eve": asdict(stats),
                "opnsense_filterlog": asdict(filter_stats) if filter_stats else None,
            },
            "inserted_events": inserted_events,
            "detections": inserted_detections,
            "incidents": inserted_incidents,
            "suppressed_incidents": suppressed_incidents,
            "response_actions": response_actions,
            "baseline_updates": baseline_updates,
            "resource_warnings": resource_warnings,
            "learning_status": learning_status,
            "learning_collection_only": bool(learning_status.get("active")),
            "learning_suppressed_detectors": learning_suppressed_detectors,
            "optional_collector_warnings": self.counters["last_optional_collector_errors"],
        }

    def _enabled_detectors(self, learning_status: dict[str, Any]) -> tuple[list[Any], list[str]]:
        ai_detector_ids = {"pondsec.host_baseline_anomaly", "pondsec.pretrained_ids_model"}
        enabled = []
        suppressed = []
        for detector in default_detectors():
            detector_id = getattr(detector, "detector_id", "")
            if detector_id in ai_detector_ids and not self.config.detection.machine_learning:
                suppressed.append(detector_id)
                continue
            if detector_id in ai_detector_ids and learning_status.get("active"):
                suppressed.append(detector_id)
                continue
            enabled.append(detector)
        return enabled, suppressed

    def _apply_queue_backpressure(self, events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
        limit = max(1, self.config.max_queue_length)
        if len(events) <= limit:
            return events, 0
        return events[:limit], len(events) - limit

    def _database_over_limit(self) -> bool:
        path = self.store.db_path
        if not path.exists():
            return False
        return path.stat().st_size > self.config.max_database_mb * 1024 * 1024

    def _limit_rate(self, items: list[dict[str, Any]], counter_key: str, limit: int) -> tuple[list[dict[str, Any]], int]:
        limit = max(0, limit)
        now = time.time()
        timestamps = [timestamp for timestamp in self.counters.get(counter_key, []) if now - float(timestamp) < 60]
        available = max(0, limit - len(timestamps))
        accepted = items[:available]
        timestamps.extend([now] * len(accepted))
        self.counters[counter_key] = timestamps
        return accepted, max(0, len(items) - len(accepted))

    def _consume_rate(self, counter_key: str, limit: int) -> bool:
        accepted, _suppressed = self._limit_rate([{"rate": "token"}], counter_key, limit)
        return bool(accepted)

    def _resource_usage(self, started_wall: float, started_cpu: float) -> dict[str, Any]:
        wall_seconds = max(0.001, time.time() - started_wall)
        cpu_percent = round(max(0.0, ((time.process_time() - started_cpu) / wall_seconds) * 100), 2)
        max_rss = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        rss_mb = round(max_rss / (1024 * 1024), 2) if max_rss > 1_000_000 else round(max_rss / 1024, 2)
        return {
            "inference_and_detection_wall_ms": round(wall_seconds * 1000, 2),
            "cpu_percent": cpu_percent,
            "rss_mb": rss_mb,
        }

    def _resource_warnings(self, usage: dict[str, Any]) -> list[str]:
        warnings = []
        if float(usage.get("rss_mb") or 0) > self.config.memory_warning_mb:
            warnings.append("memory_warning_threshold_exceeded")
        if (
            float(usage.get("inference_and_detection_wall_ms") or 0) >= 1000
            and float(usage.get("cpu_percent") or 0) > self.config.cpu_warning_percent
        ):
            warnings.append("cpu_warning_threshold_exceeded")
        return warnings

    def _filter_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        include = set(self.config.interfaces.monitored) | set(self.config.interfaces.monitored_devices)
        exclude = set(self.config.interfaces.excluded_interfaces) | set(self.config.interfaces.excluded_devices)
        direction = self.config.interfaces.direction
        filtered = []
        for event in events:
            interface = event.get("source", {}).get("interface")
            if interface and interface in exclude:
                continue
            if include and interface and interface not in include:
                continue
            if direction != "both" and event.get("direction") != direction:
                continue
            filtered.append(event)
        return filtered

    def _auto_response(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not incidents or not self.config.response.automatic_blocking:
            return []
        if self.config.response.mode == "observe":
            actions = []
            for incident in incidents:
                decision = {
                    "status": "observe",
                    "reason": "response policy is in observe mode",
                    "response_mode": self.config.response.mode,
                    "automatic": True,
                }
                self.store.audit_response_decision(incident.get("incident_id"), "observe", decision, actor="auto-response")
                actions.append({
                    "incident_id": incident.get("incident_id"),
                    "source_ip": incident.get("source_ip"),
                    "status": "observed",
                    "reason": decision["reason"],
                    "mode": self.config.response.mode,
                })
            return actions
        actions: list[dict[str, Any]] = []
        mass_isolation_safety = len(incidents) > self.config.response.max_auto_isolation_candidates_per_run
        for incident in incidents:
            incident_id = incident.get("incident_id")
            if not incident_id:
                continue
            if not self._consume_rate("pf_action_rate_timestamps", self.config.pf_action_rate_limit_per_minute):
                actions.append({
                    "incident_id": incident_id,
                    "source_ip": incident.get("source_ip"),
                    "status": "skipped",
                    "reason": "pf_action_rate_limit_exceeded",
                    "mode": self.config.response.mode,
                })
                continue
            if self._requires_manual_response(incident):
                actions.append({
                    "incident_id": incident_id,
                    "source_ip": incident.get("source_ip"),
                    "status": "skipped",
                    "reason": "baseline-only anomaly requires manual confirmation",
                    "mode": self.config.response.mode,
                })
                continue
            try:
                proposal = propose_block_for_incident(
                    self.store,
                    self.config,
                    incident_id,
                    actor="auto-prevent",
                    automatic=True,
                )
                action: dict[str, Any] = {
                    "incident_id": incident_id,
                    "source_ip": proposal.get("source_ip"),
                    "block_id": proposal.get("block_id"),
                    "mode": self.config.response.mode,
                    "status": proposal.get("status"),
                    "automatic": True,
                }
                policy_decision = proposal.get("policy_decision") if isinstance(proposal.get("policy_decision"), dict) else {}
                activation_allowed = bool(policy_decision.get("activation_allowed", self.config.response.mode == "enforce"))
                if mass_isolation_safety:
                    action["status"] = "recommended"
                    action["reason"] = "too many automatic response candidates; falling back to recommend"
                    self.store.audit_response_decision(incident_id, "mass_isolation_safety", action, actor="auto-response")
                elif self.config.response.mode == "enforce" and not activation_allowed:
                    action["status"] = "recommended"
                    action["reason"] = "; ".join(policy_decision.get("activation_reasons") or policy_decision.get("reasons") or ["response policy requires recommendation before activation"])
                    self.store.audit_response_decision(incident_id, "activation_fallback", action, actor="auto-response")
                elif self.config.response.mode == "enforce" and proposal.get("status") != "active":
                    activation = activate_block(self.store, self.config, proposal["block_id"], actor="auto-prevent")
                    action["status"] = activation["status"]
                    action["activation"] = {
                        "pf_table": activation.get("pf_table"),
                        "pf_rule_present": activation.get("pf_rule_present"),
                        "pf_verify": activation.get("pf_verify"),
                    }
                elif self.config.response.mode == "recommend":
                    action["status"] = "recommended"
                    action["reason"] = "response policy is in recommend mode"
                actions.append(action)
            except ResponseDenied as exc:
                message = f"{incident_id}: {exc}"
                if not self._is_expected_response_denial(str(exc)):
                    self.counters["last_response_errors"] = ([message] + self.counters["last_response_errors"])[:5]
                actions.append({"incident_id": incident_id, "status": "denied", "reason": str(exc)})
            except Exception as exc:
                message = f"{incident_id}: response error: {exc}"
                self.counters["last_response_errors"] = ([message] + self.counters["last_response_errors"])[:5]
                self.logger.exception(message, extra={"component": "response", "event": "auto_response_error", "error_code": "auto_response_error"})
                actions.append({"incident_id": incident_id, "status": "error", "reason": str(exc)})
        return actions

    @staticmethod
    def _requires_manual_response(incident: dict[str, Any]) -> bool:
        detections = incident.get("evidence", {}).get("detections", [])
        detector_ids = {item.get("detector_id") for item in detections if isinstance(item, dict)}
        return detector_ids == {"pondsec.host_baseline_anomaly"}

    def _baseline_skip_sources(self, detections: list[dict[str, Any]]) -> set[str]:
        anomalous_sources = {detection["source_ip"] for detection in detections if detection.get("source_ip")}
        if not anomalous_sources:
            return set()
        feedback_sources = self.store.false_positive_feedback_sources(self.config.detection.false_positive_feedback_days)
        return anomalous_sources - feedback_sources

    @staticmethod
    def _is_expected_response_denial(reason: str) -> bool:
        if reason.startswith("response policy denied:"):
            return True
        return reason in {
            "source IP is protected",
            "source IP is allowlisted",
            "incident risk score is below response threshold",
            "incident confidence is below response threshold",
            "automatic internal isolation is disabled",
            "automatic internal isolation is disabled during learning mode",
            "automatic external blocking is disabled",
        }

    def _write_health(self, status: str, detail: dict[str, Any] | None = None) -> None:
        payload = {
            "uptime_seconds": int(time.time() - self.started_at),
            "event_rate_per_second": 0,
            "queue_size": 0,
            "queue_drops": self.counters["queue_drops"],
            "parser_errors": self.counters["parser_errors"],
            "last_collector_errors": self.counters["last_collector_errors"],
            "last_optional_collector_errors": self.counters["last_optional_collector_errors"],
            "last_ml_errors": self.counters["last_ml_errors"],
            "last_response_errors": self.counters["last_response_errors"],
        }
        if detail:
            payload.update(detail)
        self.store.set_health(status, None if status == "stopped" else os.getpid(), payload)
