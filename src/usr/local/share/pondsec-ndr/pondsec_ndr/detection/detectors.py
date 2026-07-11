"""Initial deterministic detectors for PondSec NDR."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Any

from pondsec_ndr.detection.base import Detector, make_detection
from pondsec_ndr.features.aggregator import shannon_entropy
from pondsec_ndr.models.runtime import MODEL_ID, ModelRuntimeUnavailable, SaidimnIdsCnnRuntime
from pondsec_ndr.schema import is_private_ip


class PortScanDetector(Detector):
    detector_id = "pondsec.portscan"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            port_count = int(item.get("port_count") or 0)
            dest_count = int(item.get("destination_count") or 0)
            failed = int(item.get("failed_connections") or 0)
            if port_count >= 12 and failed >= 3:
                detections.append(make_detection(
                    self.detector_id,
                    "reconnaissance",
                    "Possible port scan",
                    "Host contacted an unusual number of ports with failed connections.",
                    item["source_ip"],
                    None,
                    7,
                    min(0.98, 0.65 + port_count / 100 + failed / 100),
                    min(1.0, port_count / 50),
                    {
                        "unique_ports": port_count,
                        "unique_destinations": dest_count,
                        "failed_connections": failed,
                        "thresholds": [
                            {"feature": "unique_ports", "operator": ">=", "threshold": 12, "observed": port_count},
                            {"feature": "failed_connections", "operator": ">=", "threshold": 3, "observed": failed},
                        ],
                    },
                ))
        return detections


class VerticalScanDetector(Detector):
    detector_id = "pondsec.vertical_scan"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
        for event in events:
            src = event.get("source", {}).get("ip")
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            if src and dst and port is not None:
                by_pair[(src, dst)].add(port)
        detections = []
        for (src, dst), ports in by_pair.items():
            if len(ports) >= 10:
                detections.append(make_detection(
                    self.detector_id,
                    "reconnaissance",
                    "Possible vertical scan",
                    "Host contacted many ports on one destination.",
                    src,
                    dst,
                    7,
                    min(0.95, 0.6 + len(ports) / 80),
                    min(1.0, len(ports) / 40),
                    {
                        "unique_ports": len(ports),
                        "sample_ports": sorted(ports)[:20],
                        "thresholds": [
                            {"feature": "unique_ports_to_single_destination", "operator": ">=", "threshold": 10, "observed": len(ports)},
                        ],
                    },
                ))
        return detections


class HorizontalScanDetector(Detector):
    detector_id = "pondsec.horizontal_scan"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source_port: dict[tuple[str, int], set[str]] = defaultdict(set)
        for event in events:
            src = event.get("source", {}).get("ip")
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            if src and dst and port is not None:
                by_source_port[(src, port)].add(dst)
        detections = []
        for (src, port), destinations in by_source_port.items():
            if len(destinations) >= 10:
                detections.append(make_detection(
                    self.detector_id,
                    "reconnaissance",
                    "Possible horizontal scan",
                    "Host contacted the same service across many destinations.",
                    src,
                    f"port:{port}",
                    7,
                    min(0.95, 0.6 + len(destinations) / 80),
                    min(1.0, len(destinations) / 40),
                    {
                        "destination_count": len(destinations),
                        "port": port,
                        "thresholds": [
                            {"feature": "destinations_on_same_port", "operator": ">=", "threshold": 10, "observed": len(destinations)},
                        ],
                    },
                ))
        return detections


class DNSTunnelingDetector(Detector):
    detector_id = "pondsec.dns_tunneling"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            entropy = float(item.get("dns_entropy") or 0)
            name_length = int(item.get("dns_name_length") or 0)
            query_rate = float(item.get("dns_query_rate") or 0)
            nxdomain = float(item.get("dns_nxdomain_rate") or 0)
            if entropy >= 3.8 and name_length >= 45 and (query_rate >= 0.2 or nxdomain >= 0.3):
                detections.append(make_detection(
                    self.detector_id,
                    "command_and_control",
                    "Possible DNS tunneling",
                    "DNS metadata shows long high-entropy names with unusual rate or NXDOMAIN behavior.",
                    item["source_ip"],
                    None,
                    8,
                    min(0.97, 0.55 + entropy / 10 + min(query_rate, 1) / 5),
                    min(1.0, entropy / 5),
                    {
                        "dns_entropy": entropy,
                        "dns_name_length": name_length,
                        "dns_query_rate": query_rate,
                        "dns_nxdomain_rate": nxdomain,
                        "thresholds": [
                            {"feature": "dns_entropy", "operator": ">=", "threshold": 3.8, "observed": entropy},
                            {"feature": "dns_name_length", "operator": ">=", "threshold": 45, "observed": name_length},
                            {"feature": "dns_query_rate_or_nxdomain_rate", "operator": "query_rate>=0.2 OR nxdomain_rate>=0.3", "threshold": "0.2/0.3", "observed": {"dns_query_rate": query_rate, "dns_nxdomain_rate": nxdomain}},
                        ],
                    },
                ))
        return detections


class BeaconingDetector(Detector):
    detector_id = "pondsec.beaconing"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_tuple: dict[tuple[str, str, int | None], list[float]] = defaultdict(list)
        for event in events:
            src = event.get("source", {}).get("ip")
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            if not src or not dst:
                continue
            timestamp = event.get("timestamp", "").replace("Z", "+00:00")
            try:
                from datetime import datetime
                by_tuple[(src, dst, port)].append(datetime.fromisoformat(timestamp).timestamp())
            except ValueError:
                continue
        detections = []
        for (src, dst, port), timestamps in by_tuple.items():
            if len(timestamps) < 5:
                continue
            timestamps.sort()
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            avg = mean(intervals)
            if avg <= 0 or avg < 15:
                continue
            spread = pstdev(intervals) if len(intervals) > 1 else 0
            periodicity = max(0.0, 1.0 - (spread / avg))
            if periodicity >= 0.85:
                detections.append(make_detection(
                    self.detector_id,
                    "command_and_control",
                    "Possible command-and-control beaconing",
                    "Connections recur at regular intervals to the same destination.",
                    src,
                    dst,
                    8,
                    min(0.96, 0.6 + periodicity / 3),
                    periodicity,
                    {
                        "connections": len(timestamps),
                        "average_interval_seconds": round(avg, 2),
                        "interval_stddev": round(spread, 2),
                        "port": port,
                        "periodicity": round(periodicity, 4),
                        "thresholds": [
                            {"feature": "connections", "operator": ">=", "threshold": 5, "observed": len(timestamps)},
                            {"feature": "average_interval_seconds", "operator": ">=", "threshold": 15, "observed": round(avg, 2)},
                            {"feature": "periodicity", "operator": ">=", "threshold": 0.85, "observed": round(periodicity, 4)},
                        ],
                    },
                ))
        return detections


class LateralMovementDetector(Detector):
    detector_id = "pondsec.lateral_movement"
    watched_ports = {22, 135, 139, 445, 3389, 5985, 5986}

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, set[str]] = defaultdict(set)
        for event in events:
            src = event.get("source", {}).get("ip")
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            if src and dst and is_private_ip(src) and is_private_ip(dst) and port in self.watched_ports:
                by_source[src].add(dst)
        detections = []
        for src, destinations in by_source.items():
            if len(destinations) >= 5:
                detections.append(make_detection(
                    self.detector_id,
                    "lateral_movement",
                    "Possible lateral movement",
                    "Host contacted multiple internal administration or file-sharing services.",
                    src,
                    "internal",
                    8,
                    min(0.95, 0.6 + len(destinations) / 20),
                    min(1.0, len(destinations) / 15),
                    {
                        "destination_count": len(destinations),
                        "ports": sorted(self.watched_ports),
                        "thresholds": [
                            {"feature": "internal_admin_service_destinations", "operator": ">=", "threshold": 5, "observed": len(destinations)},
                        ],
                    },
                ))
        return detections


class CredentialBruteforceDetector(Detector):
    detector_id = "pondsec.credential_bruteforce"
    auth_ports = {22, 25, 88, 110, 135, 139, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986}
    failure_reasons = {"timeout", "reject", "reset", "denied", "failed"}

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            src = event.get("source", {}).get("ip")
            port = event.get("destination", {}).get("port")
            metadata = event.get("metadata", {})
            reason = str(metadata.get("flow_reason") or metadata.get("auth_result") or "").lower()
            if src and port in self.auth_ports and (event.get("event_type") != "flow" or reason in self.failure_reasons):
                by_source[src].append(event)

        detections = []
        for src, source_events in by_source.items():
            destinations = {str(event.get("destination", {}).get("ip")) for event in source_events if event.get("destination", {}).get("ip")}
            ports = {int(event.get("destination", {}).get("port")) for event in source_events if event.get("destination", {}).get("port") is not None}
            failed = sum(1 for event in source_events if str(event.get("metadata", {}).get("flow_reason") or "").lower() in self.failure_reasons)
            if len(source_events) < 12 and not (failed >= 8 and len(destinations) >= 3):
                continue
            spray_score = min(1.0, (len(destinations) / 12) + (failed / 40))
            detections.append(make_detection(
                self.detector_id,
                "credential_abuse",
                "Possible brute-force or credential spraying",
                "Repeated failed or denied connections to authentication services resemble credential pressure.",
                src,
                next(iter(destinations)) if len(destinations) == 1 else "auth_services",
                8 if failed >= 8 else 7,
                min(0.96, 0.62 + len(source_events) / 80 + len(destinations) / 60),
                spray_score,
                {
                    "event_count": len(source_events),
                    "failed_connections": failed,
                    "destination_count": len(destinations),
                    "auth_ports": sorted(ports),
                    "signature_required": False,
                    "thresholds": [
                        {"feature": "auth_service_events", "operator": ">=", "threshold": 12, "observed": len(source_events)},
                        {"feature": "failed_auth_service_connections", "operator": ">=", "threshold": 8, "observed": failed},
                    ],
                },
                recommended_action="block",
            ))
        return detections


class DataExfiltrationDetector(Detector):
    detector_id = "pondsec.data_exfiltration"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            ratio = float(item.get("upload_download_ratio") or 0)
            bytes_out = int(item.get("bytes_out") or 0)
            if bytes_out >= 50_000_000 and ratio >= 8:
                detections.append(make_detection(
                    self.detector_id,
                    "exfiltration",
                    "Possible data exfiltration",
                    "Host uploaded substantially more data than it downloaded.",
                    item["source_ip"],
                    None,
                    8,
                    min(0.96, 0.55 + min(ratio, 50) / 100),
                    min(1.0, ratio / 50),
                    {
                        "bytes_out": bytes_out,
                        "upload_download_ratio": ratio,
                        "thresholds": [
                            {"feature": "bytes_out", "operator": ">=", "threshold": 50_000_000, "observed": bytes_out},
                            {"feature": "upload_download_ratio", "operator": ">=", "threshold": 8, "observed": ratio},
                        ],
                    },
                ))
        return detections


class SupplyChainCallbackDetector(Detector):
    detector_id = "pondsec.supply_chain_callback"
    marker_terms = (
        "supply chain",
        "dependency confusion",
        "typosquat",
        "package manager",
        "npm",
        "pypi",
        "rubygems",
        "installer",
        "software update",
        "update callback",
        "ci/cd",
        "build agent",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        marked_sources: set[str] = set()
        for event in events:
            if event.get("event_type") not in {"alert", "drop"}:
                continue
            metadata = event.get("metadata", {})
            haystack = " ".join(str(value or "").lower() for value in (
                metadata.get("signature"),
                metadata.get("category"),
            ))
            if any(term in haystack for term in self.marker_terms):
                src = event.get("source", {}).get("ip")
                if src:
                    marked_sources.add(str(src))
                    detections.append(make_detection(
                        self.detector_id,
                        "supply_chain",
                        "Possible supply-chain callback",
                        "A security marker or reporting export indicates package, installer or update callback behavior.",
                        str(src),
                        event.get("destination", {}).get("ip"),
                        8,
                        0.88,
                        0.7,
                        {
                            "signature_id": metadata.get("signature_id"),
                            "signature": metadata.get("signature"),
                            "suricata_category": metadata.get("category"),
                            "event_source": metadata.get("event_source"),
                            "thresholds": [
                                {"feature": "supply_chain_marker", "operator": "present", "threshold": "present", "observed": metadata.get("signature")},
                            ],
                        },
                        recommended_action="block",
                    ))

        for item in features:
            source_ip = item["source_ip"]
            destinations = int(item.get("destination_count") or 0)
            external = int(item.get("external_connections") or 0)
            burst = float(item.get("burst_score") or 0)
            dns_entropy = float(item.get("dns_entropy") or 0)
            if source_ip in marked_sources:
                continue
            if destinations >= 35 and external >= 35 and (burst >= 0.2 or dns_entropy >= 3.8):
                detections.append(make_detection(
                    self.detector_id,
                    "supply_chain",
                    "Possible supply-chain callback fan-out",
                    "One host contacted many external destinations in an installer-like burst with DNS or burst indicators.",
                    source_ip,
                    None,
                    6,
                    min(0.88, 0.52 + destinations / 180 + min(dns_entropy, 5) / 24),
                    min(1.0, destinations / 80),
                    {
                        "destination_count": destinations,
                        "external_connections": external,
                        "burst_score": burst,
                        "dns_entropy": dns_entropy,
                        "signature_required": False,
                        "thresholds": [
                            {"feature": "destination_count", "operator": ">=", "threshold": 35, "observed": destinations},
                            {"feature": "external_connections", "operator": ">=", "threshold": 35, "observed": external},
                            {"feature": "burst_or_dns_entropy", "operator": "burst>=0.2 OR dns_entropy>=3.8", "threshold": "0.2/3.8", "observed": {"burst_score": burst, "dns_entropy": dns_entropy}},
                        ],
                    },
                    recommended_action="investigate",
                ))
        return detections


class ExploitAttemptDetector(Detector):
    detector_id = "pondsec.exploit_attempt"
    exploit_terms = (
        "exploit",
        "remote code execution",
        "rce",
        "command injection",
        "code injection",
        "sql injection",
        "xss",
        "path traversal",
        "directory traversal",
        "deserialization",
        "shellshock",
        "log4j",
        "cve-",
        "attempted-admin",
        "attempted-user",
        "web attack",
        "privilege gain",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            if event.get("event_type") not in {"alert", "drop"}:
                continue
            metadata = event.get("metadata", {})
            haystack = " ".join(str(value or "").lower() for value in (
                metadata.get("signature"),
                metadata.get("category"),
            ))
            if not any(term in haystack for term in self.exploit_terms):
                continue
            severity = int(metadata.get("severity") or 2)
            detections.append(make_detection(
                "pondsec.exploit_blocked" if event.get("event_type") == "drop" else self.detector_id,
                "exploit_attempt",
                "Possible exploit attempt",
                "A signature or reporting marker indicates exploit-like traffic against a service.",
                event.get("source", {}).get("ip"),
                event.get("destination", {}).get("ip"),
                max(7, min(10, 11 - severity)),
                0.9 if event.get("event_type") == "drop" else 0.86,
                0.75,
                {
                    "signature_id": metadata.get("signature_id"),
                    "signature": metadata.get("signature"),
                    "suricata_category": metadata.get("category"),
                    "suricata_action": metadata.get("action"),
                    "event_source": metadata.get("event_source"),
                    "thresholds": [
                        {"feature": "exploit_marker", "operator": "present", "threshold": "present", "observed": metadata.get("signature")},
                    ],
                },
                recommended_action="block",
            ))
        return detections


class MalwareCallbackDetector(Detector):
    detector_id = "pondsec.malware_callback"
    malware_terms = (
        "malware",
        "trojan",
        "ransomware",
        "botnet",
        "loader",
        "dropper",
        "c2",
        "command and control",
        "payload download",
        "malicious download",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            if event.get("event_type") not in {"alert", "drop"}:
                continue
            metadata = event.get("metadata", {})
            haystack = " ".join(str(value or "").lower() for value in (
                metadata.get("signature"),
                metadata.get("category"),
            ))
            if not any(term in haystack for term in self.malware_terms):
                continue
            detections.append(make_detection(
                self.detector_id,
                "malware",
                "Possible malware callback or payload retrieval",
                "A signature or reporting marker indicates malware, loader, botnet or payload retrieval behavior.",
                event.get("source", {}).get("ip"),
                event.get("destination", {}).get("ip"),
                8,
                0.88,
                0.72,
                {
                    "signature_id": metadata.get("signature_id"),
                    "signature": metadata.get("signature"),
                    "suricata_category": metadata.get("category"),
                    "suricata_action": metadata.get("action"),
                    "event_source": metadata.get("event_source"),
                    "thresholds": [
                        {"feature": "malware_marker", "operator": "present", "threshold": "present", "observed": metadata.get("signature")},
                    ],
                },
                recommended_action="block",
            ))
        return detections


class HostBaselineAnomalyDetector(Detector):
    detector_id = "pondsec.host_baseline_anomaly"
    ready_statuses = {"complete", "updated", "uncertain", "established"}

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            deviation = float(item.get("baseline_deviation") or 0)
            peer_deviation = float(item.get("peer_group_deviation") or 0)
            observations = int(item.get("baseline_observations") or 0)
            baseline_status = str(item.get("baseline_status") or "")
            host_ready = baseline_status in self.ready_statuses and deviation >= 0.65
            peer_ready = item.get("peer_group_status") == "ready" and peer_deviation >= 0.65
            if not host_ready and not peer_ready:
                continue
            anomaly_score = max(deviation if host_ready else 0.0, peer_deviation if peer_ready else 0.0)
            detections.append(make_detection(
                self.detector_id,
                "anomaly",
                "Host baseline anomaly" if host_ready else "Peer group behavior anomaly",
                "Host behavior deviates from its own baseline or a mature peer group without requiring a signature match.",
                item["source_ip"],
                None,
                8 if anomaly_score >= 0.8 else 7,
                min(0.97, 0.68 + anomaly_score / 4),
                anomaly_score,
                {
                    "baseline_deviation": deviation,
                    "baseline_observations": observations,
                    "baseline_status": baseline_status,
                    "baseline_status_label": item.get("baseline_status_label"),
                    "baseline_version": item.get("baseline_version"),
                    "baseline_drift_score": item.get("baseline_drift_score"),
                    "peer_group": item.get("peer_group"),
                    "peer_group_status": item.get("peer_group_status"),
                    "peer_group_size": item.get("peer_group_size"),
                    "peer_group_deviation": peer_deviation,
                    "peer_group_confidence": item.get("peer_group_confidence"),
                    "reasons": item.get("baseline_anomaly_reasons", []),
                    "peer_group_reasons": item.get("peer_group_anomaly_reasons", []),
                    "signature_required": False,
                    "thresholds": [
                        {"feature": "baseline_status", "operator": "in", "threshold": sorted(self.ready_statuses), "observed": baseline_status},
                        {"feature": "baseline_deviation", "operator": ">=", "threshold": 0.65, "observed": deviation},
                        {"feature": "peer_group_status", "operator": "=", "threshold": "ready", "observed": item.get("peer_group_status")},
                        {"feature": "peer_group_deviation", "operator": ">=", "threshold": 0.65, "observed": peer_deviation},
                    ],
                },
                recommended_action="block",
                model_version="pondsec-host-baseline-v1",
            ))
        return detections


class PretrainedIdsModelDetector(Detector):
    detector_id = "pondsec.pretrained_ids_model"
    _runtime: SaidimnIdsCnnRuntime | None = None
    _unavailable: str | None = None

    @classmethod
    def _get_runtime(cls) -> SaidimnIdsCnnRuntime | None:
        if cls._runtime is not None:
            return cls._runtime
        if cls._unavailable is not None:
            return None
        try:
            cls._runtime = SaidimnIdsCnnRuntime()
        except ModelRuntimeUnavailable as exc:
            cls._unavailable = str(exc)
            return None
        return cls._runtime

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        runtime = self._get_runtime()
        if runtime is None:
            return []
        detections = []
        for score in runtime.score_features(features):
            attack_probability = float(score["attack_probability"])
            class_probability = float(score["attack_class_probability"])
            if attack_probability < 0.55:
                continue
            confidence = max(attack_probability, min(0.95, class_probability))
            detections.append(make_detection(
                self.detector_id,
                "machine_learning",
                "Pretrained AI model classified traffic as attack",
                "The verified CICIDS2017 CNN-1D pretrained model classified the flow feature vector as malicious.",
                score["source_ip"],
                None,
                9 if attack_probability >= 0.85 else 7,
                confidence,
                attack_probability,
                {
                    "model_id": score["model_id"],
                    "model_version": score["model_version"],
                    "model_checksum": score["model_checksum"],
                    "runtime_version": score["runtime_version"],
                    "artifact_path": score["artifact_path"],
                    "feature_schema_version": "1",
                    "attack_probability": round(attack_probability, 6),
                    "benign_probability": round(float(score["benign_probability"]), 6),
                    "attack_class": score["attack_class"],
                    "attack_class_probability": round(class_probability, 6),
                    "feature_values": score["feature_values"],
                    "pretrained_model": True,
                    "thresholds": [
                        {"feature": "attack_probability", "operator": ">=", "threshold": 0.55, "observed": round(attack_probability, 6)},
                    ],
                },
                recommended_action="block",
                model_version=score["model_version"],
            ))
        return detections


class UnusualTlsFingerprintDetector(Detector):
    detector_id = "pondsec.unusual_tls_fingerprint"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        by_source: dict[str, set[str]] = defaultdict(set)
        for event in events:
            if event.get("event_type") != "tls":
                continue
            fingerprint = event.get("metadata", {}).get("fingerprint")
            src = event.get("source", {}).get("ip")
            if src and fingerprint:
                by_source[src].add(str(fingerprint))
        for src, fingerprints in by_source.items():
            if len(fingerprints) >= 8:
                detections.append(make_detection(
                    self.detector_id,
                    "evasion",
                    "Unusual TLS fingerprint diversity",
                    "Host used many TLS fingerprints in a short analysis window.",
                    src,
                    None,
                    6,
                    min(0.9, 0.5 + len(fingerprints) / 30),
                    min(1.0, len(fingerprints) / 20),
                    {
                        "fingerprint_count": len(fingerprints),
                        "thresholds": [
                            {"feature": "fingerprint_count", "operator": ">=", "threshold": 8, "observed": len(fingerprints)},
                        ],
                    },
                ))
        return detections


class UnusualDestinationDetector(Detector):
    detector_id = "pondsec.unusual_destination"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            destinations = int(item.get("destination_count") or 0)
            burst = float(item.get("burst_score") or 0)
            connections_60s = int(item.get("connections_60s") or 0)
            if destinations >= 50 and (burst >= 0.2 or connections_60s >= 50):
                detections.append(make_detection(
                    self.detector_id,
                    "anomaly",
                    "Unusual destination fan-out",
                    "Host contacted many destinations in a short window.",
                    item["source_ip"],
                    None,
                    6,
                    min(0.9, 0.5 + destinations / 200),
                    min(1.0, destinations / 100),
                    {
                        "destination_count": destinations,
                        "connections_60s": connections_60s,
                        "burst_score": burst,
                        "thresholds": [
                            {"feature": "destination_count", "operator": ">=", "threshold": 50, "observed": destinations},
                            {"feature": "burst_or_connections_60s", "operator": "burst>=0.2 OR connections_60s>=50", "threshold": "0.2/50", "observed": {"burst_score": burst, "connections_60s": connections_60s}},
                        ],
                    },
                ))
        return detections


class SuricataAlertAdapter(Detector):
    detector_id = "pondsec.suricata_alert"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            event_type = event.get("event_type")
            if event_type not in {"alert", "drop"}:
                continue
            metadata = event.get("metadata", {})
            if not metadata.get("signature_id"):
                continue
            severity = int(metadata.get("severity") or 3)
            is_drop = event_type == "drop"
            detections.append(make_detection(
                "pondsec.suricata_drop" if is_drop else self.detector_id,
                "signature",
                metadata.get("signature") or "Suricata alert",
                "Known dropped traffic imported from Suricata EVE." if is_drop else "Known signature alert imported from Suricata EVE.",
                event.get("source", {}).get("ip"),
                event.get("destination", {}).get("ip"),
                max(4, min(10, 11 - severity)),
                0.9,
                0.0,
                {
                    "signature_id": metadata.get("signature_id"),
                    "category": metadata.get("category"),
                    "suricata_severity": severity,
                    "suricata_action": metadata.get("action"),
                    "drop_reason": metadata.get("drop_reason"),
                    "thresholds": [
                        {"feature": "signature_id", "operator": "present", "threshold": "present", "observed": metadata.get("signature_id")},
                    ],
                },
            ))
        return detections


def default_detectors() -> list[Detector]:
    return [
        PortScanDetector(),
        HorizontalScanDetector(),
        VerticalScanDetector(),
        DNSTunnelingDetector(),
        BeaconingDetector(),
        PretrainedIdsModelDetector(),
        HostBaselineAnomalyDetector(),
        UnusualDestinationDetector(),
        CredentialBruteforceDetector(),
        LateralMovementDetector(),
        DataExfiltrationDetector(),
        UnusualTlsFingerprintDetector(),
        SupplyChainCallbackDetector(),
        ExploitAttemptDetector(),
        MalwareCallbackDetector(),
        SuricataAlertAdapter(),
    ]
