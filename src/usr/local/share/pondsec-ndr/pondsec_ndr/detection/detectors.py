"""Initial deterministic detectors for PondSec NDR."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Any

from pondsec_ndr.detection.base import Detector, make_detection
from pondsec_ndr.features.aggregator import shannon_entropy
from pondsec_ndr.models.runtime import MODEL_ID, ModelRuntimeUnavailable, SaidimnIdsCnnRuntime
from pondsec_ndr.schema import is_private_ip
from pondsec_ndr.traffic import is_infrastructure_response_event


def _normalised_indicator_text(*values: Any) -> str:
    text = " ".join(str(value or "").lower() for value in values)
    return text.translate(str.maketrans({"-": " ", "_": " ", "/": " ", ".": " "}))


def _event_indicator_text(event: dict[str, Any]) -> str:
    metadata = event.get("metadata", {})
    headers = metadata.get("headers") if isinstance(metadata.get("headers"), dict) else {}
    return _normalised_indicator_text(
        metadata.get("signature"),
        metadata.get("category"),
        metadata.get("threat_name"),
        metadata.get("security_category"),
        metadata.get("web_category"),
        metadata.get("application"),
        metadata.get("application_category"),
        metadata.get("rrname"),
        metadata.get("query"),
        metadata.get("domain"),
        metadata.get("sni"),
        metadata.get("tls_sni"),
        metadata.get("server_name"),
        metadata.get("hostname"),
        metadata.get("url_path"),
        metadata.get("filename"),
        metadata.get("mime_type"),
        metadata.get("file_verdict"),
        metadata.get("sandbox_verdict"),
        metadata.get("av_verdict"),
        metadata.get("email_protocol"),
        metadata.get("email_attachment"),
        metadata.get("http_method"),
        metadata.get("status"),
        metadata.get("auth_result"),
        *(headers or {}).values(),
    )


def _has_validation_marker(text: str) -> bool:
    return "pondsec validation" in text or "validation marker" in text or ("pondsec" in text and "validation" in text)


HIGH_RISK_URL_TERMS = (
    "malware",
    "phishing",
    "credential",
    "fraud",
    "scam",
    "botnet",
    "c2",
    "command and control",
    "ransomware",
    "exploit",
    "drive by",
    "payload",
)
MALWARE_TERMS = (
    "malware",
    "trojan",
    "ransomware",
    "botnet",
    "loader",
    "dropper",
    "payload",
    "infected",
    "eicar",
)
PHISHING_TERMS = ("phishing", "credential", "fraud", "scam", "password")
C2_TERMS = ("c2", "command and control", "botnet", "beacon", "callback")
EXPLOIT_TERMS = ("exploit", "rce", "remote code execution", "injection", "cve", "traversal")
BENIGN_WEB_TERMS = (
    "cdn",
    "cloudflare",
    "akamai",
    "apple",
    "microsoft",
    "google",
    "update",
    "telemetry",
    "push",
)
BLOCK_DECISIONS = {"block", "blocked", "deny", "denied", "drop", "dropped", "sinkhole", "quarantine"}
MALICIOUS_VERDICTS = {"malicious", "infected", "malware", "blocked", "quarantine", "quarantined", "denied", "high"}
SUSPICIOUS_FILE_EXTENSIONS = (
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".bat",
    ".cmd",
    ".scr",
    ".lnk",
    ".iso",
    ".img",
    ".zip",
    ".rar",
    ".7z",
)
EICAR_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",
    "3395856ce81f2b7382dee72602f798b642f14140",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}
EMAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}


def _metadata(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("metadata")
    return value if isinstance(value, dict) else {}


def _first_metadata(metadata: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _text_contains_any(text: str, terms: tuple[str, ...] | set[str]) -> bool:
    normalized = _normalised_indicator_text(text)
    tokens = set(normalized.split())
    padded = f" {normalized} "
    for term in terms:
        normalized_term = _normalised_indicator_text(term).strip()
        if not normalized_term:
            continue
        if " " in normalized_term:
            if f" {normalized_term} " in padded:
                return True
            continue
        if normalized_term.isalnum():
            if normalized_term in tokens:
                return True
            continue
        if normalized_term in normalized:
            return True
    return False


def _threat_category_from_text(text: str) -> tuple[str, str]:
    if _text_contains_any(text, PHISHING_TERMS):
        return "credential_abuse", "phishing_or_credential"
    if _text_contains_any(text, C2_TERMS):
        return "command_and_control", "command_and_control"
    if _text_contains_any(text, EXPLOIT_TERMS):
        return "exploit_attempt", "exploit"
    if _text_contains_any(text, MALWARE_TERMS):
        return "malware", "malware"
    return "signature", "security_policy"


def _domain_or_host(event: dict[str, Any]) -> str | None:
    metadata = _metadata(event)
    value = _first_metadata(metadata, "domain", "hostname", "sni", "tls_sni", "server_name", "rrname", "query")
    return str(value).strip().lower().rstrip(".") if value else None


def _provider_id(event: dict[str, Any]) -> str:
    metadata = _metadata(event)
    return str(metadata.get("event_source") or event.get("raw_source") or "unknown")


def _is_zenarmor_event(event: dict[str, Any]) -> bool:
    return _provider_id(event) == "zenarmor" or str(event.get("raw_source") or "") == "zenarmor"


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled", "blocked", "sinkhole"}


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
            if is_infrastructure_response_event(event):
                continue
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
            if is_infrastructure_response_event(event):
                continue
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
        detections = self._detect_from_query_events(events)
        event_sources = {str(item.get("source_ip")) for item in detections if item.get("source_ip")}
        for item in features:
            if str(item.get("source_ip")) in event_sources:
                continue
            entropy = float(item.get("dns_entropy") or 0)
            name_length = int(item.get("dns_name_length") or 0)
            query_rate = float(item.get("dns_query_rate") or 0)
            nxdomain = float(item.get("dns_nxdomain_rate") or 0)
            event_count = int(item.get("connections_5m") or 0)
            dns_event_count = int(item.get("dns_event_count") or 0)
            dns_events_10s = int(item.get("dns_events_10s") or 0)
            dns_events_60s = int(item.get("dns_events_60s") or 0)
            dns_destination_count = int(item.get("dns_destination_count") or item.get("destination_count") or 0)
            dns_destination_port = int(item.get("dominant_dns_destination_port") or item.get("dominant_destination_port") or 0)
            metadata_limited_burst = dns_events_10s >= 12 or dns_events_60s >= 18
            enough_volume = event_count >= 8 or (event_count >= 4 and nxdomain >= 0.3)
            if entropy >= 3.8 and name_length >= 45 and enough_volume and (query_rate >= 0.2 or nxdomain >= 0.3):
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
                        "event_count": event_count,
                        "thresholds": [
                            {"feature": "dns_entropy", "operator": ">=", "threshold": 3.8, "observed": entropy},
                            {"feature": "dns_name_length", "operator": ">=", "threshold": 45, "observed": name_length},
                            {"feature": "dns_event_volume", "operator": "connections_5m>=8 OR connections_5m>=4 AND nxdomain_rate>=0.3", "threshold": "8/4", "observed": {"connections_5m": event_count, "dns_nxdomain_rate": nxdomain}},
                            {"feature": "dns_query_rate_or_nxdomain_rate", "operator": "query_rate>=0.2 OR nxdomain_rate>=0.3", "threshold": "0.2/0.3", "observed": {"dns_query_rate": query_rate, "dns_nxdomain_rate": nxdomain}},
                        ],
                    },
                ))
            elif (
                dns_event_count >= 12
                and metadata_limited_burst
                and dns_destination_port == 53
                and dns_destination_count <= 2
            ):
                detections.append(make_detection(
                    self.detector_id,
                    "command_and_control",
                    "Possible DNS tunneling with limited metadata",
                    "DNS telemetry shows a burst of resolver queries, but the provider did not export query names.",
                    item["source_ip"],
                    "dns_resolver",
                    6,
                    min(0.82, 0.54 + min(query_rate, 20) / 100 + dns_event_count / 200),
                    min(0.75, dns_event_count / 40),
                    {
                        "dns_event_count": dns_event_count,
                        "dns_events_10s": dns_events_10s,
                        "dns_events_60s": dns_events_60s,
                        "dns_destination_count": dns_destination_count,
                        "dominant_dns_destination_port": dns_destination_port,
                        "dns_query_rate": query_rate,
                        "dns_name_length": name_length,
                        "dns_entropy": entropy,
                        "metadata_limited": True,
                        "provider_query_names_missing": True,
                        "signature_required": False,
                        "thresholds": [
                            {"feature": "dns_event_count", "operator": ">=", "threshold": 12, "observed": dns_event_count},
                            {"feature": "dns_burst_volume", "operator": "dns_events_10s>=12 OR dns_events_60s>=18", "threshold": "12/18", "observed": {"dns_events_10s": dns_events_10s, "dns_events_60s": dns_events_60s}},
                            {"feature": "dominant_dns_destination_port", "operator": "=", "threshold": 53, "observed": dns_destination_port},
                            {"feature": "dns_destination_count", "operator": "<=", "threshold": 2, "observed": dns_destination_count},
                        ],
                    },
                    recommended_action="investigate",
                ))
        return detections

    def _detect_from_query_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if is_infrastructure_response_event(event):
                continue
            if event.get("event_type") != "dns":
                continue
            src = event.get("source", {}).get("ip")
            name = self._rrname(event)
            if not src or not name:
                continue
            first_label = name.split(".")[0]
            entropy = shannon_entropy(first_label)
            if len(name) >= 45 and len(first_label) >= 30 and entropy >= 3.6:
                by_source[str(src)].append({
                    "name": name,
                    "first_label": first_label,
                    "entropy": entropy,
                    "length": len(name),
                    "rcode": str((event.get("metadata") or {}).get("rcode") or "").upper(),
                    "destination_ip": event.get("destination", {}).get("ip"),
                })

        detections = []
        for src, items in by_source.items():
            names = {str(item["name"]) for item in items}
            if len(items) < 8 or len(names) < 6:
                continue
            nxdomain = sum(1 for item in items if item.get("rcode") == "NXDOMAIN")
            nxdomain_rate = round(nxdomain / max(len(items), 1), 4)
            max_entropy = max(float(item["entropy"]) for item in items)
            max_length = max(int(item["length"]) for item in items)
            destination = self._common_destination(items)
            detections.append(make_detection(
                self.detector_id,
                "command_and_control",
                "Possible DNS tunneling",
                "Repeated DNS queries contain long high-entropy labels consistent with tunneling-like traffic.",
                src,
                destination,
                8,
                min(0.97, 0.62 + min(len(items), 30) / 100 + max_entropy / 20),
                min(1.0, max_entropy / 5),
                {
                    "suspicious_dns_events": len(items),
                    "unique_dns_names": len(names),
                    "dns_entropy": round(max_entropy, 4),
                    "dns_name_length": max_length,
                    "dns_nxdomain_rate": nxdomain_rate,
                    "sample_domains": sorted(names)[:5],
                    "thresholds": [
                        {"feature": "suspicious_dns_events", "operator": ">=", "threshold": 8, "observed": len(items)},
                        {"feature": "unique_dns_names", "operator": ">=", "threshold": 6, "observed": len(names)},
                        {"feature": "dns_entropy", "operator": ">=", "threshold": 3.6, "observed": round(max_entropy, 4)},
                        {"feature": "dns_name_length", "operator": ">=", "threshold": 45, "observed": max_length},
                    ],
                },
            ))
        return detections

    @staticmethod
    def _rrname(event: dict[str, Any]) -> str | None:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        name = metadata.get("rrname") or metadata.get("query") or metadata.get("dns_query")
        if not name:
            return None
        value = str(name).strip().rstrip(".").lower()
        if not value or "." not in value:
            return None
        return value

    @staticmethod
    def _common_destination(items: list[dict[str, Any]]) -> str | None:
        values = {str(item.get("destination_ip")) for item in items if item.get("destination_ip")}
        if len(values) == 1:
            return next(iter(values))
        return None


class BeaconingDetector(Detector):
    detector_id = "pondsec.beaconing"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_tuple: dict[tuple[str, str, int | None], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if is_infrastructure_response_event(event):
                continue
            src = event.get("source", {}).get("ip")
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            if not src or not dst:
                continue
            by_tuple[(src, dst, port)].append(event)
        detections = []
        for (src, dst, port), tuple_events in by_tuple.items():
            timestamps = []
            for event in tuple_events:
                timestamp = event.get("timestamp", "").replace("Z", "+00:00")
                try:
                    from datetime import datetime
                    timestamps.append(datetime.fromisoformat(timestamp).timestamp())
                except ValueError:
                    continue
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
                nat_mapping_required = any(_event_needs_pre_nat_mapping(event) for event in tuple_events)
                response_target_confidence = "low_without_pre_nat_session_context" if nat_mapping_required else "direct_source"
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
                        "nat_mapping_required": nat_mapping_required,
                        "response_target_confidence": response_target_confidence,
                        "thresholds": [
                            {"feature": "connections", "operator": ">=", "threshold": 5, "observed": len(timestamps)},
                            {"feature": "average_interval_seconds", "operator": ">=", "threshold": 15, "observed": round(avg, 2)},
                            {"feature": "periodicity", "operator": ">=", "threshold": 0.85, "observed": round(periodicity, 4)},
                        ],
                    },
                ))
        return detections


def _event_needs_pre_nat_mapping(event: dict[str, Any]) -> bool:
    metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
    src = event.get("source", {}).get("ip")
    dst = event.get("destination", {}).get("ip")
    return bool(metadata.get("filter_suspicious_pass") and src and dst and not is_private_ip(str(src)) and is_private_ip(str(dst)))


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


class WormLikePropagationDetector(Detector):
    detector_id = "pondsec.worm_like_propagation"
    watched_ports = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            metadata = event.get("metadata", {}) if isinstance(event.get("metadata"), dict) else {}
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            src = event.get("source", {}).get("ip")
            if not src or not dst or port not in self.watched_ports:
                continue
            if metadata.get("filter_suspicious_pass") or (is_private_ip(str(dst)) and str(metadata.get("event_source")) == "opnsense_filterlog"):
                by_source[str(src)].append(event)

        detections = []
        for src, source_events in by_source.items():
            destinations = {str(event.get("destination", {}).get("ip")) for event in source_events if event.get("destination", {}).get("ip")}
            ports = {int(event.get("destination", {}).get("port")) for event in source_events if event.get("destination", {}).get("port") is not None}
            reasons = sorted({
                str((event.get("metadata") or {}).get("filter_suspicious_reason"))
                for event in source_events
                if (event.get("metadata") or {}).get("filter_suspicious_reason")
            })
            if len(source_events) < 12 or len(destinations) < 4 or len(ports) < 3:
                continue
            detections.append(make_detection(
                self.detector_id,
                "lateral_movement",
                "Worm-like propagation pattern",
                "A host attempted repeated connections to multiple private destinations on administration and file-sharing ports.",
                src,
                "private_egress",
                8,
                min(0.96, 0.62 + len(destinations) / 25 + len(ports) / 50),
                min(1.0, len(source_events) / 60),
                {
                    "event_count": len(source_events),
                    "destination_count": len(destinations),
                    "port_count": len(ports),
                    "sample_destinations": sorted(destinations)[:10],
                    "ports": sorted(ports),
                    "filter_suspicious_reasons": reasons,
                    "nat_mapping_required": not is_private_ip(str(src)),
                    "response_target_confidence": "low_without_pre_nat_session_context" if not is_private_ip(str(src)) else "direct_internal_source",
                    "thresholds": [
                        {"feature": "worm_like_connection_attempts", "operator": ">=", "threshold": 12, "observed": len(source_events)},
                        {"feature": "private_destinations", "operator": ">=", "threshold": 4, "observed": len(destinations)},
                        {"feature": "admin_or_file_sharing_ports", "operator": ">=", "threshold": 3, "observed": len(ports)},
                    ],
                },
                recommended_action="investigate",
            ))
        return detections


class CredentialBruteforceDetector(Detector):
    detector_id = "pondsec.credential_bruteforce"
    auth_ports = {22, 25, 88, 110, 135, 139, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986}
    auth_failure_results = {"denied", "failed", "failure", "invalid", "login_failed", "rejected", "unauthorized"}
    http_failure_statuses = {401, 403}
    auth_path_terms = ("/basic", "/login", "/signin", "/sign-in", "/wp-login", "/admin/login", "/auth/")
    marker_terms = (
        "credential",
        "brute force",
        "bruteforce",
        "password spraying",
        "password spray",
        "login failure",
        "authentication failure",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            src = event.get("source", {}).get("ip")
            if src and self._has_auth_failure_evidence(event):
                by_source[src].append(event)

        detections = []
        for src, source_events in by_source.items():
            destinations = {str(event.get("destination", {}).get("ip")) for event in source_events if event.get("destination", {}).get("ip")}
            ports = {int(event.get("destination", {}).get("port")) for event in source_events if event.get("destination", {}).get("port") is not None}
            http_statuses = sorted({
                int(event.get("metadata", {}).get("status"))
                for event in source_events
                if str(event.get("metadata", {}).get("status") or "").isdigit()
            })
            marker_count = sum(1 for event in source_events if self._is_credential_marker(event))
            auth_result_failures = sum(1 for event in source_events if self._has_failed_auth_result(event))
            http_failures = sum(1 for event in source_events if self._has_http_auth_failure(event))
            auth_endpoint_events = sum(1 for event in source_events if self._has_http_auth_endpoint_pressure(event))
            failed = marker_count + auth_result_failures + http_failures + auth_endpoint_events
            has_spray_shape = failed >= 6 and len(destinations) >= 3
            has_bruteforce_shape = failed >= 8 and len(destinations) >= 1
            if not marker_count and not has_spray_shape and not has_bruteforce_shape:
                continue
            spray_score = min(1.0, (len(destinations) / 12) + (failed / 40))
            detections.append(make_detection(
                self.detector_id,
                "credential_abuse",
                "Possible brute-force or credential spraying",
                "Explicit authentication failures or security markers resemble brute-force or credential-spraying behavior.",
                src,
                next(iter(destinations)) if len(destinations) == 1 else "auth_services",
                8 if failed >= 8 or marker_count else 7,
                min(0.96, 0.66 + failed / 80 + len(destinations) / 60 + marker_count / 10),
                spray_score,
                {
                    "event_count": len(source_events),
                    "auth_failure_events": failed,
                    "http_auth_failures": http_failures,
                    "auth_result_failures": auth_result_failures,
                    "auth_endpoint_events": auth_endpoint_events,
                    "marker_events": marker_count,
                    "destination_count": len(destinations),
                    "auth_ports": sorted(ports),
                    "http_statuses": http_statuses,
                    "explicit_auth_evidence": bool(marker_count or auth_result_failures or http_failures),
                    "auth_endpoint_pressure": bool(auth_endpoint_events),
                    "thresholds": [
                        {"feature": "auth_failure_events", "operator": ">=", "threshold": 8, "observed": failed},
                        {"feature": "auth_failure_destinations", "operator": ">=", "threshold": 3, "observed": len(destinations)},
                        {"feature": "auth_endpoint_events", "operator": ">=", "threshold": 8, "observed": auth_endpoint_events},
                        {"feature": "credential_marker", "operator": "present", "threshold": "present", "observed": marker_count},
                    ],
                },
                recommended_action="block",
            ))
        return detections

    def _has_auth_failure_evidence(self, event: dict[str, Any]) -> bool:
        return (
            self._has_http_auth_failure(event)
            or self._has_failed_auth_result(event)
            or self._has_http_auth_endpoint(event)
            or self._is_credential_marker(event)
        )

    def _has_http_auth_failure(self, event: dict[str, Any]) -> bool:
        if event.get("event_type") != "http":
            return False
        status = event.get("metadata", {}).get("status")
        try:
            return int(status) in self.http_failure_statuses
        except (TypeError, ValueError):
            return False

    def _has_failed_auth_result(self, event: dict[str, Any]) -> bool:
        result = str(event.get("metadata", {}).get("auth_result") or "").lower()
        return result in self.auth_failure_results

    def _has_http_auth_endpoint(self, event: dict[str, Any]) -> bool:
        if event.get("event_type") != "http":
            return False
        path = str(event.get("metadata", {}).get("url_path") or "").lower()
        return bool(path) and any(term in path for term in self.auth_path_terms)

    def _has_http_auth_endpoint_pressure(self, event: dict[str, Any]) -> bool:
        return self._has_http_auth_endpoint(event) and not self._has_http_auth_failure(event)

    def _is_credential_marker(self, event: dict[str, Any]) -> bool:
        if event.get("event_type") not in {"alert", "drop"}:
            return False
        text = _event_indicator_text(event)
        return any(term in text for term in self.marker_terms)


class AuthServicePressureDetector(Detector):
    detector_id = "pondsec.auth_service_pressure"
    auth_ports = CredentialBruteforceDetector.auth_ports
    failure_reasons = {"timeout", "reject", "reset", "denied", "failed"}

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("event_type") != "flow":
                continue
            src = event.get("source", {}).get("ip")
            port = event.get("destination", {}).get("port")
            reason = str(event.get("metadata", {}).get("flow_reason") or "").lower()
            if src and port in self.auth_ports and reason in self.failure_reasons:
                by_source[src].append(event)

        detections = []
        for src, source_events in by_source.items():
            destinations = {str(event.get("destination", {}).get("ip")) for event in source_events if event.get("destination", {}).get("ip")}
            ports = {int(event.get("destination", {}).get("port")) for event in source_events if event.get("destination", {}).get("port") is not None}
            failed = len(source_events)
            if len(source_events) < 16 and not (failed >= 10 and len(destinations) >= 3):
                continue
            detections.append(make_detection(
                self.detector_id,
                "reconnaissance",
                "Authentication service pressure",
                "Repeated connection failures hit authentication services, but no explicit failed-login evidence was observed.",
                src,
                next(iter(destinations)) if len(destinations) == 1 else "auth_services",
                5 if len(destinations) < 3 else 6,
                min(0.82, 0.48 + len(source_events) / 100 + len(destinations) / 90),
                min(1.0, len(source_events) / 40),
                {
                    "event_count": len(source_events),
                    "failed_connections": failed,
                    "destination_count": len(destinations),
                    "auth_ports": sorted(ports),
                    "explicit_auth_evidence": False,
                    "thresholds": [
                        {"feature": "auth_service_connection_failures", "operator": ">=", "threshold": 16, "observed": len(source_events)},
                        {"feature": "auth_service_destinations", "operator": ">=", "threshold": 3, "observed": len(destinations)},
                    ],
                },
                recommended_action="investigate",
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
        "ci cd",
        "build agent",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        marked_sources: set[str] = set()
        for event in events:
            if not self._is_marker_event(event):
                continue
            metadata = event.get("metadata", {})
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
                        "event_type": event.get("event_type"),
                        "hostname": metadata.get("hostname") or metadata.get("sni"),
                        "url_path": metadata.get("url_path"),
                        "rrname": metadata.get("rrname"),
                        "validation_marker": _has_validation_marker(_event_indicator_text(event)),
                        "thresholds": [
                            {"feature": "supply_chain_marker", "operator": "present", "threshold": "present", "observed": metadata.get("signature") or metadata.get("url_path") or metadata.get("rrname") or metadata.get("sni")},
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

    def _is_marker_event(self, event: dict[str, Any]) -> bool:
        text = _event_indicator_text(event)
        has_supply_context = any(term in text for term in self.marker_terms)
        if not has_supply_context:
            return False
        if event.get("event_type") in {"alert", "drop"}:
            return True
        return event.get("event_type") in {"dns", "http", "tls"} and _has_validation_marker(text)


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
        "cve",
        "attempted-admin",
        "attempted admin",
        "attempted-user",
        "attempted user",
        "web attack",
        "privilege gain",
    )

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            metadata = event.get("metadata", {})
            text = _event_indicator_text(event)
            if not self._is_exploit_marker(event, text):
                continue
            severity = int(metadata.get("severity") or 2)
            validation_marker = _has_validation_marker(text)
            detections.append(make_detection(
                "pondsec.exploit_blocked" if event.get("event_type") == "drop" else self.detector_id,
                "exploit_attempt",
                "Possible exploit attempt",
                "A signature or reporting marker indicates exploit-like traffic against a service.",
                event.get("source", {}).get("ip"),
                event.get("destination", {}).get("ip"),
                max(7, min(10, 11 - severity)),
                0.9 if event.get("event_type") == "drop" else 0.86 if event.get("event_type") in {"alert", "drop"} else 0.82,
                0.75,
                {
                    "signature_id": metadata.get("signature_id"),
                    "signature": metadata.get("signature"),
                    "suricata_category": metadata.get("category"),
                    "suricata_action": metadata.get("action"),
                    "event_source": metadata.get("event_source"),
                    "event_type": event.get("event_type"),
                    "hostname": metadata.get("hostname") or metadata.get("sni"),
                    "url_path": metadata.get("url_path"),
                    "rrname": metadata.get("rrname"),
                    "validation_marker": validation_marker,
                    "thresholds": [
                        {"feature": "exploit_marker", "operator": "present", "threshold": "present", "observed": metadata.get("signature") or metadata.get("url_path") or metadata.get("rrname") or metadata.get("sni")},
                    ],
                },
                recommended_action="block",
            ))
        return detections

    def _is_exploit_marker(self, event: dict[str, Any], text: str) -> bool:
        has_exploit_context = any(term in text for term in self.exploit_terms)
        if not has_exploit_context:
            return False
        if event.get("event_type") in {"alert", "drop"}:
            return True
        return event.get("event_type") in {"http", "tls", "dns"} and _has_validation_marker(text)


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


class ZenarmorSecurityEventDetector(Detector):
    detector_id = "pondsec.zenarmor_security_event"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            if not _is_zenarmor_event(event):
                continue
            metadata = _metadata(event)
            decision = str(metadata.get("decision") or "").lower()
            text = _event_indicator_text(event)
            has_security_context = bool(
                metadata.get("threat_name")
                or metadata.get("security_category")
                or _text_contains_any(text, HIGH_RISK_URL_TERMS)
            )
            if not has_security_context:
                continue
            category, threat_kind = _threat_category_from_text(text)
            blocked = decision in BLOCK_DECISIONS or event.get("event_type") == "drop"
            source = event.get("source", {}).get("ip")
            destination = event.get("destination", {}).get("ip") or _domain_or_host(event)
            severity = 9 if threat_kind in {"malware", "command_and_control", "exploit"} else 8
            confidence = 0.94 if blocked and metadata.get("threat_name") else 0.9 if blocked else 0.86
            detections.append(make_detection(
                self.detector_id,
                category,
                "Zenarmor security event",
                "Zenarmor exported security, URL, TLS or policy context for a high-risk event.",
                source,
                destination,
                severity,
                confidence,
                0.78 if blocked else 0.62,
                {
                    "provider_id": "zenarmor",
                    "event_source": "zenarmor",
                    "decision": decision or None,
                    "threat_name": metadata.get("threat_name"),
                    "security_category": metadata.get("security_category"),
                    "web_category": metadata.get("web_category"),
                    "application": metadata.get("application"),
                    "policy_name": metadata.get("policy_name"),
                    "rule_name": metadata.get("rule_name"),
                    "domain": _domain_or_host(event),
                    "url_path": metadata.get("url_path"),
                    "tls_sni": metadata.get("tls_sni"),
                    "tls_inspected": metadata.get("tls_inspected"),
                    "session_id": metadata.get("session_id"),
                    "device_name": metadata.get("device_name"),
                    "byte_count": metadata.get("byte_count"),
                    "threat_kind": threat_kind,
                    "provider_prevented": blocked,
                    "thresholds": [
                        {"feature": "zenarmor_security_context", "operator": "present", "threshold": "present", "observed": metadata.get("threat_name") or metadata.get("security_category")},
                        {"feature": "zenarmor_decision", "operator": "in", "threshold": sorted(BLOCK_DECISIONS), "observed": decision or event.get("event_type")},
                    ],
                },
                recommended_action="investigate" if blocked else "block",
            ))
        return detections


class UrlThreatDetector(Detector):
    detector_id = "pondsec.url_threat"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            if event.get("event_type") not in {"dns", "http", "tls", "alert", "drop"}:
                continue
            metadata = _metadata(event)
            domain = _domain_or_host(event)
            url_path = metadata.get("url_path")
            if not domain and not url_path:
                continue
            text = _event_indicator_text(event)
            has_high_risk_context = bool(
                metadata.get("threat_name")
                or metadata.get("security_category")
                or _text_contains_any(text, HIGH_RISK_URL_TERMS)
                or _has_validation_marker(text)
            )
            if not has_high_risk_context:
                continue
            if _text_contains_any(text, BENIGN_WEB_TERMS) and not (metadata.get("threat_name") or metadata.get("security_category") or _has_validation_marker(text)):
                continue
            category, threat_kind = _threat_category_from_text(text)
            source = event.get("source", {}).get("ip")
            destination = event.get("destination", {}).get("ip") or domain
            provider = _provider_id(event)
            detections.append(make_detection(
                self.detector_id,
                category,
                "High-risk URL or domain",
                "URL, DNS or TLS metadata contains high-risk category, threat or validation-marker context.",
                source,
                destination,
                8 if metadata.get("threat_name") or metadata.get("security_category") else 7,
                0.9 if metadata.get("threat_name") or metadata.get("security_category") else 0.82,
                0.7,
                {
                    "provider_id": provider,
                    "event_source": provider,
                    "domain": domain,
                    "url_path": url_path,
                    "threat_name": metadata.get("threat_name"),
                    "security_category": metadata.get("security_category"),
                    "web_category": metadata.get("web_category"),
                    "application": metadata.get("application"),
                    "tls_sni": metadata.get("tls_sni") or metadata.get("sni") or metadata.get("server_name"),
                    "tls_inspected": metadata.get("tls_inspected"),
                    "validation_marker": _has_validation_marker(text),
                    "threat_kind": threat_kind,
                    "thresholds": [
                        {"feature": "url_or_domain_security_context", "operator": "present", "threshold": "present", "observed": metadata.get("threat_name") or metadata.get("security_category") or domain},
                    ],
                },
                recommended_action="block",
            ))
        return detections


class FileSandboxVerdictDetector(Detector):
    detector_id = "pondsec.file_sandbox_verdict"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            metadata = _metadata(event)
            filename = str(_first_metadata(metadata, "filename", "file_name") or "")
            hashes = {
                str(metadata.get("md5") or "").lower(),
                str(metadata.get("sha1") or "").lower(),
                str(metadata.get("sha256") or "").lower(),
            }
            verdict_text = _normalised_indicator_text(
                metadata.get("file_verdict"),
                metadata.get("sandbox_verdict"),
                metadata.get("av_verdict"),
                metadata.get("threat_name"),
                metadata.get("security_category"),
                metadata.get("mime_type"),
                filename,
            )
            has_file_context = event.get("event_type") == "fileinfo" or bool(filename or (hashes - {""}) or verdict_text.strip())
            if not has_file_context:
                continue
            eicar = bool((hashes - {""}) & EICAR_HASHES) or "eicar" in verdict_text
            malicious_verdict = eicar or any(term in verdict_text for term in MALICIOUS_VERDICTS) or _text_contains_any(verdict_text, MALWARE_TERMS)
            suspicious_extension = any(filename.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS)
            if not malicious_verdict and not suspicious_extension:
                continue
            source = event.get("source", {}).get("ip")
            destination = event.get("destination", {}).get("ip") or _domain_or_host(event)
            email_context = self._email_context(event, metadata)
            detector_id = self.detector_id if malicious_verdict else "pondsec.suspicious_file_transfer"
            title = "Email-borne file threat" if email_context and malicious_verdict else "File sandbox or malware verdict" if malicious_verdict else "Suspicious file transfer"
            detections.append(make_detection(
                detector_id,
                "malware" if malicious_verdict else "supply_chain",
                title,
                "File metadata, hash, AV or sandbox verdict indicates a malicious or risky transferred artifact.",
                source,
                destination,
                9 if malicious_verdict else 5,
                0.96 if eicar or metadata.get("sandbox_verdict") or metadata.get("av_verdict") else 0.84 if malicious_verdict else 0.68,
                0.86 if malicious_verdict else 0.45,
                {
                    "provider_id": _provider_id(event),
                    "event_source": _provider_id(event),
                    "filename": filename or None,
                    "mime_type": metadata.get("mime_type"),
                    "file_size": metadata.get("file_size") or metadata.get("size") or metadata.get("seen_bytes") or metadata.get("total_bytes"),
                    "md5": metadata.get("md5"),
                    "sha1": metadata.get("sha1"),
                    "sha256": metadata.get("sha256"),
                    "file_verdict": metadata.get("file_verdict"),
                    "sandbox_verdict": metadata.get("sandbox_verdict"),
                    "av_verdict": metadata.get("av_verdict"),
                    "threat_name": metadata.get("threat_name"),
                    "suspicious_extension": suspicious_extension,
                    "email_context": email_context,
                    "safe_test_file": eicar,
                    "signature_required": bool(malicious_verdict),
                    "thresholds": [
                        {"feature": "file_or_sandbox_verdict", "operator": "malicious_or_suspicious", "threshold": sorted(MALICIOUS_VERDICTS), "observed": metadata.get("sandbox_verdict") or metadata.get("av_verdict") or metadata.get("file_verdict") or filename},
                    ],
                },
                recommended_action="block" if malicious_verdict else "investigate",
            ))
        return detections

    @staticmethod
    def _email_context(event: dict[str, Any], metadata: dict[str, Any]) -> bool:
        port = event.get("destination", {}).get("port")
        app_text = _normalised_indicator_text(
            metadata.get("application"),
            metadata.get("application_category"),
            metadata.get("email_protocol"),
            metadata.get("email_attachment"),
            metadata.get("protocol"),
        )
        return bool(port in EMAIL_PORTS or "mail" in app_text or "smtp" in app_text or "imap" in app_text or "pop3" in app_text or "webmail" in app_text)


class EmailThreatDetector(Detector):
    detector_id = "pondsec.email_threat"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            metadata = _metadata(event)
            if not FileSandboxVerdictDetector._email_context(event, metadata):
                continue
            filename = str(_first_metadata(metadata, "filename", "file_name") or "")
            decision = str(_first_metadata(metadata, "decision", "action", "policy_action") or "").lower()
            verdict_text = _normalised_indicator_text(
                metadata.get("file_verdict"),
                metadata.get("sandbox_verdict"),
                metadata.get("av_verdict"),
                metadata.get("threat_name"),
                metadata.get("security_category"),
                filename,
            )
            indicator_text = _event_indicator_text(event) + " " + verdict_text
            provider_threat = bool(metadata.get("threat_name")) or _text_contains_any(indicator_text, HIGH_RISK_URL_TERMS)
            malicious_file = any(term in verdict_text for term in MALICIOUS_VERDICTS) or _text_contains_any(verdict_text, MALWARE_TERMS)
            suspicious_attachment = bool(filename and any(filename.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS))
            provider_prevented = decision in BLOCK_DECISIONS or event.get("event_type") == "drop"
            if not (provider_threat or malicious_file or (provider_prevented and suspicious_attachment)):
                continue
            if _text_contains_any(indicator_text, BENIGN_WEB_TERMS) and not (provider_threat or malicious_file or provider_prevented):
                continue
            category, threat_kind = _threat_category_from_text(indicator_text)
            if malicious_file and category == "signature":
                category, threat_kind = "malware", "malware"
            if category == "signature":
                category, threat_kind = "credential_abuse", "email_security"
            source = event.get("source", {}).get("ip")
            destination = event.get("destination", {}).get("ip") or _domain_or_host(event)
            detections.append(make_detection(
                self.detector_id,
                category,
                "Email-borne threat",
                "Email, webmail or mail-protocol telemetry contains URL, attachment, sandbox or provider security evidence.",
                source,
                destination,
                9 if malicious_file or provider_prevented else 8,
                0.95 if malicious_file else 0.9 if provider_prevented or metadata.get("threat_name") else 0.84,
                0.82 if malicious_file or provider_prevented else 0.68,
                {
                    "provider_id": _provider_id(event),
                    "event_source": _provider_id(event),
                    "email_protocol": metadata.get("email_protocol") or metadata.get("protocol"),
                    "email_attachment": metadata.get("email_attachment"),
                    "filename": filename or None,
                    "mime_type": metadata.get("mime_type"),
                    "file_size": metadata.get("file_size") or metadata.get("size") or metadata.get("seen_bytes") or metadata.get("total_bytes"),
                    "file_verdict": metadata.get("file_verdict"),
                    "sandbox_verdict": metadata.get("sandbox_verdict"),
                    "av_verdict": metadata.get("av_verdict"),
                    "domain": _domain_or_host(event),
                    "url_path": metadata.get("url_path"),
                    "tls_sni": metadata.get("tls_sni") or metadata.get("sni") or metadata.get("server_name"),
                    "tls_inspected": metadata.get("tls_inspected"),
                    "threat_name": metadata.get("threat_name"),
                    "security_category": metadata.get("security_category"),
                    "decision": decision or None,
                    "provider_prevented": provider_prevented,
                    "threat_kind": threat_kind,
                    "suspicious_attachment": suspicious_attachment,
                    "thresholds": [
                        {"feature": "email_context", "operator": "present", "threshold": "mail/webmail/attachment", "observed": metadata.get("email_protocol") or metadata.get("application") or event.get("destination", {}).get("port")},
                        {"feature": "email_threat_context", "operator": "present", "threshold": "provider threat, malicious verdict, or blocked suspicious attachment", "observed": metadata.get("threat_name") or metadata.get("security_category") or metadata.get("sandbox_verdict") or metadata.get("file_verdict") or decision},
                    ],
                },
                recommended_action="investigate" if provider_prevented else "block",
            ))
        return detections


class DnsSinkholeDetector(Detector):
    detector_id = "pondsec.dns_sinkhole_hit"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            if event.get("event_type") != "dns":
                continue
            metadata = _metadata(event)
            decision = str(_first_metadata(metadata, "decision", "policy_action", "dns_action") or "").lower()
            answers = metadata.get("answers") or []
            if not isinstance(answers, list):
                answers = [answers]
            sinkhole = (
                _boolish(_first_metadata(metadata, "sinkhole", "sinkhole_hit", "dns_sinkhole", "blocked_domain"))
                or decision in {"sinkhole", "blocked", "block", "deny", "denied"}
                or any(str(answer) in {"0.0.0.0", "::", "127.0.0.1"} for answer in answers)
            )
            if not sinkhole:
                continue
            domain = _domain_or_host(event)
            source = event.get("source", {}).get("ip")
            detections.append(make_detection(
                self.detector_id,
                "command_and_control",
                "DNS sinkhole hit",
                "DNS telemetry indicates a blocked or sinkholed domain lookup from an internal entity.",
                source,
                domain or event.get("destination", {}).get("ip"),
                8,
                0.9,
                0.74,
                {
                    "provider_id": _provider_id(event),
                    "event_source": _provider_id(event),
                    "domain": domain,
                    "decision": decision or None,
                    "answers": answers[:8],
                    "security_category": metadata.get("security_category"),
                    "threat_name": metadata.get("threat_name"),
                    "provider_prevented": True,
                    "thresholds": [
                        {"feature": "dns_sinkhole_decision", "operator": "present", "threshold": "sinkhole_or_blocked", "observed": decision or answers[:3]},
                    ],
                },
                recommended_action="investigate",
            ))
        return detections


class ThreatIntelIndicatorDetector(Detector):
    detector_id = "pondsec.threat_intel_indicator"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for event in events:
            metadata = _metadata(event)
            reputation = str(_first_metadata(metadata, "reputation", "domain_reputation", "ip_reputation", "threat_reputation") or "").lower()
            confidence = self._confidence(metadata)
            ioc_match = _first_metadata(metadata, "ioc_match", "indicator_match", "threat_intel_match")
            if not ioc_match and confidence < 0.85 and reputation not in {"malicious", "known_bad", "bad", "high", "block", "blocked"}:
                continue
            text = _event_indicator_text(event) + " " + reputation
            category, threat_kind = _threat_category_from_text(text)
            source = event.get("source", {}).get("ip")
            destination = event.get("destination", {}).get("ip") or _domain_or_host(event)
            detections.append(make_detection(
                self.detector_id,
                category if category != "signature" else "command_and_control",
                "Threat-intel indicator match",
                "Local or provider-supplied threat intelligence matched the IP, domain, URL or file indicator.",
                source,
                destination,
                9 if confidence >= 0.95 or reputation in {"malicious", "known_bad"} else 8,
                min(0.98, max(0.86, confidence)),
                min(1.0, confidence),
                {
                    "provider_id": _provider_id(event),
                    "event_source": _provider_id(event),
                    "indicator": ioc_match or _domain_or_host(event) or destination,
                    "ioc_type": metadata.get("ioc_type") or metadata.get("indicator_type"),
                    "reputation": reputation or None,
                    "threat_intel_confidence": confidence,
                    "threat_intel_source": metadata.get("threat_intel_source") or metadata.get("intel_source"),
                    "threat_name": metadata.get("threat_name"),
                    "threat_kind": threat_kind,
                    "thresholds": [
                        {"feature": "threat_intel_confidence", "operator": ">=", "threshold": 0.85, "observed": confidence},
                        {"feature": "reputation", "operator": "in", "threshold": "malicious/known_bad/high", "observed": reputation},
                    ],
                },
                recommended_action="block",
            ))
        return detections

    @staticmethod
    def _confidence(metadata: dict[str, Any]) -> float:
        for key in ("threat_intel_confidence", "ioc_confidence", "reputation_confidence", "confidence"):
            value = metadata.get(key)
            try:
                number = float(value)
            except (TypeError, ValueError):
                continue
            return number / 100 if number > 1 else number
        return 0.0


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
        AuthServicePressureDetector(),
        LateralMovementDetector(),
        WormLikePropagationDetector(),
        DataExfiltrationDetector(),
        UnusualTlsFingerprintDetector(),
        SupplyChainCallbackDetector(),
        ExploitAttemptDetector(),
        MalwareCallbackDetector(),
        ZenarmorSecurityEventDetector(),
        UrlThreatDetector(),
        EmailThreatDetector(),
        FileSandboxVerdictDetector(),
        DnsSinkholeDetector(),
        ThreatIntelIndicatorDetector(),
        SuricataAlertAdapter(),
    ]
