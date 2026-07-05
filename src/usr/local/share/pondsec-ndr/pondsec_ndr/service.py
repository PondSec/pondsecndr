"""PondSec NDR backend service."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
import os
from pathlib import Path
import signal
import time
from typing import Any

from pondsec_ndr.collectors.eve import EveCollector
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
        self.stop_requested = False
        self.started_at = time.time()
        self.counters: dict[str, Any] = {
            "events": 0,
            "detections": 0,
            "incidents": 0,
            "parser_errors": 0,
            "queue_drops": 0,
            "last_collector_errors": [],
            "last_ml_errors": [],
            "last_response_errors": [],
        }

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
        collector = EveCollector(
            Path(self.config.suricata_eve_path),
            self.config.data_dir / "collector_offsets" / "suricata_eve.json",
            queue_limit=min(self.config.max_event_rate, 100000),
        )
        events, stats = collector.read_once(max_lines=max_lines)
        self.counters["parser_errors"] += stats.parser_errors
        self.counters["queue_drops"] += stats.queue_drops
        if stats.last_error:
            self.counters["last_collector_errors"] = ([stats.last_error] + self.counters["last_collector_errors"])[:5]

        inserted_events = self.store.insert_events(events)
        features = self.store.score_features_against_baselines(
            aggregate_features(events),
            minimum_observations=self.config.detection.minimum_observations,
        )
        self.store.insert_features(features)

        detections: list[dict[str, Any]] = []
        for detector in default_detectors():
            detections.extend(detector.detect(events, features))
        inserted_detections = self.store.insert_detections(detections)

        incidents = correlate_detections(detections)
        inserted_incidents = self.store.insert_incidents(incidents)
        anomalous_sources = {detection["source_ip"] for detection in detections if detection.get("source_ip")}
        baseline_updates = self.store.update_host_baselines(features, skip_sources=anomalous_sources)
        response_actions = self._auto_response(incidents)
        cleaned = self.store.cleanup(self.config.retention_days)

        self.counters["events"] += inserted_events
        self.counters["detections"] += inserted_detections
        self.counters["incidents"] += inserted_incidents
        status = "healthy"
        if stats.last_error and not events:
            status = "degraded"
        self._write_health(status, {
            "read_lines": stats.read_lines,
            "accepted_events": stats.accepted_events,
            "inserted_events": inserted_events,
            "inserted_detections": inserted_detections,
            "inserted_incidents": inserted_incidents,
            "response_actions": response_actions,
            "baseline_updates": baseline_updates,
            "cleanup_deleted": cleaned,
            "parser_errors": self.counters["parser_errors"],
            "normalization_errors": stats.normalization_errors,
            "queue_drops": self.counters["queue_drops"],
            "rotation_detected": stats.rotation_detected,
        })
        return {
            "status": status,
            "collector": asdict(stats),
            "inserted_events": inserted_events,
            "detections": inserted_detections,
            "incidents": inserted_incidents,
            "response_actions": response_actions,
            "baseline_updates": baseline_updates,
        }

    def _auto_response(self, incidents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not incidents or not self.config.response.automatic_blocking or self.config.mode not in {"interactive", "prevent"}:
            return []
        actions: list[dict[str, Any]] = []
        for incident in incidents:
            incident_id = incident.get("incident_id")
            if not incident_id:
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
                    "mode": self.config.mode,
                    "status": proposal.get("status"),
                    "automatic": True,
                }
                if self.config.mode == "prevent" and proposal.get("status") != "active":
                    activation = activate_block(self.store, self.config, proposal["block_id"], actor="auto-prevent")
                    action["status"] = activation["status"]
                    action["activation"] = {
                        "pf_table": activation.get("pf_table"),
                        "pf_rule_present": activation.get("pf_rule_present"),
                        "pf_verify": activation.get("pf_verify"),
                    }
                actions.append(action)
            except ResponseDenied as exc:
                message = f"{incident_id}: {exc}"
                self.counters["last_response_errors"] = ([message] + self.counters["last_response_errors"])[:5]
                actions.append({"incident_id": incident_id, "status": "denied", "reason": str(exc)})
            except Exception as exc:
                message = f"{incident_id}: response error: {exc}"
                self.counters["last_response_errors"] = ([message] + self.counters["last_response_errors"])[:5]
                self.logger.exception(message, extra={"component": "response", "event": "auto_response_error", "error_code": "auto_response_error"})
                actions.append({"incident_id": incident_id, "status": "error", "reason": str(exc)})
        return actions

    def _write_health(self, status: str, detail: dict[str, Any] | None = None) -> None:
        payload = {
            "uptime_seconds": int(time.time() - self.started_at),
            "event_rate_per_second": 0,
            "queue_size": 0,
            "queue_drops": self.counters["queue_drops"],
            "parser_errors": self.counters["parser_errors"],
            "last_collector_errors": self.counters["last_collector_errors"],
            "last_ml_errors": self.counters["last_ml_errors"],
            "last_response_errors": self.counters["last_response_errors"],
        }
        if detail:
            payload.update(detail)
        self.store.set_health(status, None if status == "stopped" else os.getpid(), payload)
