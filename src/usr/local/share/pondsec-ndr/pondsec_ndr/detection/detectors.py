"""Initial deterministic detectors for PondSec NDR."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Any

from pondsec_ndr.detection.base import Detector, make_detection
from pondsec_ndr.features.aggregator import shannon_entropy
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
                    {"unique_ports": port_count, "unique_destinations": dest_count, "failed_connections": failed},
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
                    {"unique_ports": len(ports), "sample_ports": sorted(ports)[:20]},
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
                    {"destination_count": len(destinations), "port": port},
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
                    {"dns_entropy": entropy, "dns_name_length": name_length, "dns_query_rate": query_rate, "dns_nxdomain_rate": nxdomain},
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
                    {"connections": len(timestamps), "average_interval_seconds": round(avg, 2), "interval_stddev": round(spread, 2), "port": port},
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
                    {"destination_count": len(destinations), "ports": sorted(self.watched_ports)},
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
                    {"bytes_out": bytes_out, "upload_download_ratio": ratio},
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
                    {"fingerprint_count": len(fingerprints)},
                ))
        return detections


class UnusualDestinationDetector(Detector):
    detector_id = "pondsec.unusual_destination"

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        detections = []
        for item in features:
            destinations = int(item.get("destination_count") or 0)
            if destinations >= 50 and float(item.get("burst_score") or 0) >= 0.2:
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
                    {"destination_count": destinations, "burst_score": item.get("burst_score")},
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
        UnusualDestinationDetector(),
        LateralMovementDetector(),
        DataExfiltrationDetector(),
        UnusualTlsFingerprintDetector(),
        SuricataAlertAdapter(),
    ]
