"""Bounded feature aggregation for deterministic detectors."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import math
from statistics import mean, pstdev
from typing import Any

from pondsec_ndr.schema import FEATURE_SCHEMA_VERSION, is_private_ip


def _parse_time(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def shannon_entropy(value: str | None) -> float:
    if not value:
        return 0.0
    counts = defaultdict(int)
    for char in value:
        counts[char] += 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _base_feature(source_ip: str) -> dict[str, Any]:
    return {
        "feature_version": FEATURE_SCHEMA_VERSION,
        "source_ip": source_ip,
        "flow_duration": 0,
        "packet_count": 0,
        "byte_count": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "upload_download_ratio": 0.0,
        "connections_10s": 0,
        "connections_60s": 0,
        "connections_5m": 0,
        "unique_destinations_60s": 0,
        "unique_destinations_5m": 0,
        "unique_ports_60s": 0,
        "unique_ports_5m": 0,
        "failed_connections": 0,
        "internal_connections": 0,
        "external_connections": 0,
        "new_destination_score": 0.0,
        "new_service_score": 0.0,
        "dns_query_rate": 0.0,
        "dns_nxdomain_rate": 0.0,
        "dns_name_length": 0,
        "dns_entropy": 0.0,
        "tls_sni_seen_before": None,
        "tls_fingerprint_seen_before": None,
        "certificate_age": None,
        "certificate_issuer_seen_before": None,
        "http_method_frequency": {},
        "http_status_distribution": {},
        "suricata_alert_count": 0,
        "periodicity_score": 0.0,
        "beaconing_score": 0.0,
        "burst_score": 0.0,
        "data_transfer_deviation": 0.0,
        "baseline_deviation": 0.0,
        "destination_count": 0,
        "port_count": 0,
    }


def aggregate_features(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        src = event.get("source", {}).get("ip")
        if src:
            grouped[src].append(event)

    features: list[dict[str, Any]] = []
    for source_ip, source_events in grouped.items():
        item = _base_feature(source_ip)
        timestamps = sorted(_parse_time(event["timestamp"]) for event in source_events)
        first = timestamps[0] if timestamps else 0
        last = timestamps[-1] if timestamps else 0
        destinations = set()
        ports = set()
        dns_names: list[str] = []
        nxdomain = 0
        http_methods: dict[str, int] = defaultdict(int)
        http_status: dict[str, int] = defaultdict(int)

        for event in source_events:
            metadata = event.get("metadata", {})
            dst = event.get("destination", {}).get("ip")
            dst_port = event.get("destination", {}).get("port")
            if dst:
                destinations.add(dst)
            if dst_port is not None:
                ports.add(dst_port)
            item["bytes_in"] += int(metadata.get("bytes_in") or 0)
            item["bytes_out"] += int(metadata.get("bytes_out") or 0)
            item["byte_count"] += int(metadata.get("byte_count") or 0)
            item["packet_count"] += int(metadata.get("packet_count") or 0)
            item["flow_duration"] += float(metadata.get("duration") or 0)
            if metadata.get("flow_state") in {"closed", "new"} and metadata.get("flow_reason") in {"timeout", "reject", "reset"}:
                item["failed_connections"] += 1
            if is_private_ip(dst):
                item["internal_connections"] += 1
            elif dst:
                item["external_connections"] += 1
            if event.get("event_type") == "dns":
                name = metadata.get("rrname")
                if name:
                    dns_names.append(str(name))
                if str(metadata.get("rcode", "")).upper() == "NXDOMAIN":
                    nxdomain += 1
            if event.get("event_type") == "http":
                method = str(metadata.get("http_method") or "unknown")
                status = str(metadata.get("status") or "unknown")
                http_methods[method] += 1
                http_status[status] += 1
            if event.get("event_type") == "alert":
                item["suricata_alert_count"] += 1

        duration = max(last - first, 1.0)
        item["connections_10s"] = sum(1 for ts in timestamps if last - ts <= 10)
        item["connections_60s"] = sum(1 for ts in timestamps if last - ts <= 60)
        item["connections_5m"] = sum(1 for ts in timestamps if last - ts <= 300)
        item["unique_destinations_60s"] = len(destinations)
        item["unique_destinations_5m"] = len(destinations)
        item["unique_ports_60s"] = len(ports)
        item["unique_ports_5m"] = len(ports)
        item["destination_count"] = len(destinations)
        item["port_count"] = len(ports)
        item["upload_download_ratio"] = round(item["bytes_out"] / max(item["bytes_in"], 1), 4)
        item["dns_query_rate"] = round(len(dns_names) / duration, 4)
        item["dns_nxdomain_rate"] = round(nxdomain / max(len(dns_names), 1), 4)
        if dns_names:
            item["dns_name_length"] = int(mean(len(name) for name in dns_names))
            item["dns_entropy"] = round(mean(shannon_entropy(name.split(".")[0]) for name in dns_names), 4)
        if len(timestamps) >= 4:
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            avg = mean(intervals)
            spread = pstdev(intervals) if len(intervals) > 1 else 0
            if avg > 0:
                item["periodicity_score"] = round(max(0.0, 1.0 - (spread / avg)), 4)
                item["beaconing_score"] = item["periodicity_score"] if len(destinations) <= 3 else item["periodicity_score"] * 0.5
        if item["connections_10s"] > 20:
            item["burst_score"] = min(1.0, item["connections_10s"] / 100)
        if item["upload_download_ratio"] > 10:
            item["data_transfer_deviation"] = min(1.0, item["upload_download_ratio"] / 100)
        item["baseline_deviation"] = max(item["burst_score"], item["data_transfer_deviation"], item["dns_entropy"] / 5 if item["dns_entropy"] else 0)
        item["http_method_frequency"] = dict(http_methods)
        item["http_status_distribution"] = dict(http_status)
        features.append(item)
    return features
