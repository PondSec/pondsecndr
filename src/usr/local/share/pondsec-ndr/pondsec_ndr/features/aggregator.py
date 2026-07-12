"""Bounded feature aggregation for deterministic detectors."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import ipaddress
import math
from statistics import mean, pstdev
from typing import Any

from pondsec_ndr.schema import FEATURE_SCHEMA_VERSION, is_private_ip
from pondsec_ndr.traffic import is_infrastructure_response_event, source_is_excluded


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
        "packets_in": 0,
        "packets_out": 0,
        "byte_count": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "dns_bytes_out": 0,
        "non_dns_bytes_out": 0,
        "external_bytes_out": 0,
        "external_non_dns_bytes_out": 0,
        "dominant_destination_port": 0,
        "upload_download_ratio": 0.0,
        "connections_10s": 0,
        "connections_60s": 0,
        "connections_5m": 0,
        "unique_destinations_60s": 0,
        "unique_destinations_5m": 0,
        "unique_ports_60s": 0,
        "unique_ports_5m": 0,
        "failed_connections": 0,
        "firewall_blocked_connections": 0,
        "firewall_suspicious_pass_connections": 0,
        "firewall_blocked_only": False,
        "internal_connections": 0,
        "external_connections": 0,
        "new_destination_score": 0.0,
        "new_service_score": 0.0,
        "dns_query_rate": 0.0,
        "dns_event_count": 0,
        "dns_events_10s": 0,
        "dns_events_60s": 0,
        "dns_destination_count": 0,
        "non_dns_destination_count": 0,
        "external_destination_count": 0,
        "dominant_dns_destination_port": 0,
        "dns_nxdomain_rate": 0.0,
        "dns_name_length": 0,
        "dns_entropy": 0.0,
        "tls_sni_seen_before": None,
        "tls_fingerprint_seen_before": None,
        "certificate_age": None,
        "certificate_issuer_seen_before": None,
        "http_method_frequency": {},
        "http_status_distribution": {},
        "applications": [],
        "domains": [],
        "provider_decisions": {},
        "suricata_alert_count": 0,
        "periodicity_score": 0.0,
        "beaconing_score": 0.0,
        "burst_score": 0.0,
        "data_transfer_deviation": 0.0,
        "baseline_deviation": 0.0,
        "destination_count": 0,
        "port_count": 0,
    }


def _metadata_values(metadata: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (list, tuple, set)):
            values.extend(str(item).strip() for item in value if str(item).strip())
            continue
        if isinstance(value, dict):
            values.extend(str(item).strip() for item in value.values() if str(item).strip())
            continue
        text = str(value).strip()
        if text:
            values.append(text)
    return values


def aggregate_features(
    events: list[dict[str, Any]],
    excluded_source_hosts: set[str] | list[str] | tuple[str, ...] | None = None,
    excluded_source_networks: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    excluded_hosts = {str(item).strip() for item in (excluded_source_hosts or []) if str(item).strip()}
    excluded_networks = []
    for value in excluded_source_networks or []:
        try:
            excluded_networks.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError:
            continue
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if is_infrastructure_response_event(event):
            continue
        src = event.get("source", {}).get("ip")
        if src and source_is_excluded(str(src), excluded_hosts, excluded_networks):
            continue
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
        port_counter: Counter[int] = Counter()
        dns_port_counter: Counter[int] = Counter()
        dns_names: list[str] = []
        dns_destinations = set()
        non_dns_destinations = set()
        external_destinations = set()
        dns_timestamps: list[float] = []
        nxdomain = 0
        http_methods: dict[str, int] = defaultdict(int)
        http_status: dict[str, int] = defaultdict(int)
        application_counter: Counter[str] = Counter()
        domain_counter: Counter[str] = Counter()
        decision_counter: Counter[str] = Counter()

        for event in source_events:
            metadata = event.get("metadata", {})
            dst = event.get("destination", {}).get("ip")
            dst_port = event.get("destination", {}).get("port")
            firewall_blocked = (
                str(metadata.get("event_source") or "") == "opnsense_filterlog"
                and str(metadata.get("filter_action") or "").lower() == "block"
            )
            if firewall_blocked:
                item["firewall_blocked_connections"] += 1
            if not firewall_blocked and metadata.get("filter_suspicious_pass"):
                item["firewall_suspicious_pass_connections"] += 1
            if dst:
                destinations.add(dst)
            if dst_port is not None:
                ports.add(dst_port)
                port_counter[int(dst_port)] += 1
            item["packets_in"] += int(metadata.get("packets_in") or 0)
            item["packets_out"] += int(metadata.get("packets_out") or 0)
            item["bytes_in"] += int(metadata.get("bytes_in") or 0)
            bytes_out = int(metadata.get("bytes_out") or 0)
            item["bytes_out"] += bytes_out
            item["byte_count"] += int(metadata.get("byte_count") or 0)
            item["packet_count"] += int(metadata.get("packet_count") or 0)
            item["flow_duration"] += float(metadata.get("duration") or 0)
            if metadata.get("flow_state") in {"closed", "new"} and metadata.get("flow_reason") in {"timeout", "reject", "reset"}:
                item["failed_connections"] += 1
            if is_private_ip(dst):
                item["internal_connections"] += 1
            elif dst:
                item["external_connections"] += 1
                external_destinations.add(dst)
                item["external_bytes_out"] += bytes_out
            if event.get("event_type") == "dns":
                item["dns_bytes_out"] += bytes_out
                item["dns_event_count"] += 1
                dns_timestamps.append(_parse_time(event["timestamp"]))
                if dst:
                    dns_destinations.add(dst)
                if dst_port is not None:
                    dns_port_counter[int(dst_port)] += 1
                name = metadata.get("rrname")
                if name:
                    dns_names.append(str(name))
                if str(metadata.get("rcode", "")).upper() == "NXDOMAIN":
                    nxdomain += 1
            else:
                item["non_dns_bytes_out"] += bytes_out
                if dst:
                    non_dns_destinations.add(dst)
                if dst and not is_private_ip(dst):
                    item["external_non_dns_bytes_out"] += bytes_out
            if event.get("event_type") == "http":
                method = str(metadata.get("http_method") or "unknown")
                status = str(metadata.get("status") or "unknown")
                http_methods[method] += 1
                http_status[status] += 1
            if event.get("event_type") == "alert":
                item["suricata_alert_count"] += 1
            for value in _metadata_values(metadata, "application", "app", "service", "application_category"):
                application_counter[value] += 1
            for value in _metadata_values(metadata, "domain", "sni", "tls_sni", "server_name", "rrname", "query", "http_host"):
                domain_counter[value.lower().rstrip(".")] += 1
            for value in _metadata_values(metadata, "decision", "action", "policy_action", "suricata_action"):
                decision_counter[value.lower()] += 1

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
        item["firewall_blocked_only"] = bool(source_events) and item["firewall_blocked_connections"] == len(source_events)
        if port_counter:
            item["dominant_destination_port"] = port_counter.most_common(1)[0][0]
        if dns_port_counter:
            item["dominant_dns_destination_port"] = dns_port_counter.most_common(1)[0][0]
        item["dns_destination_count"] = len(dns_destinations)
        item["non_dns_destination_count"] = len(non_dns_destinations)
        item["external_destination_count"] = len(external_destinations)
        item["upload_download_ratio"] = round(item["bytes_out"] / max(item["bytes_in"], 1), 4)
        item["dns_query_rate"] = round(item["dns_event_count"] / duration, 4)
        if dns_timestamps:
            last_dns = max(dns_timestamps)
            item["dns_events_10s"] = sum(1 for ts in dns_timestamps if last_dns - ts <= 10)
            item["dns_events_60s"] = sum(1 for ts in dns_timestamps if last_dns - ts <= 60)
        item["dns_nxdomain_rate"] = round(nxdomain / max(item["dns_event_count"], 1), 4)
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
        item["applications"] = [value for value, _count in application_counter.most_common(10)]
        item["domains"] = [value for value, _count in domain_counter.most_common(20)]
        item["provider_decisions"] = dict(decision_counter)
        features.append(item)
    return features
