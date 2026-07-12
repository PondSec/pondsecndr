"""Traffic classification helpers shared by aggregation and detectors."""

from __future__ import annotations

import ipaddress
from typing import Any


EPHEMERAL_PORT_FLOOR = 32768
THREAT_INTEL_LOOKUP_SUFFIXES = (
    "malware.hash.cymru.com",
    "hash.cymru.com",
)


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def is_infrastructure_response_event(event: dict[str, Any]) -> bool:
    """Return true for server responses that should not look like scans.

    Sensors report DNS responses as traffic from the resolver to the client's
    ephemeral UDP port. Generic scan and beacon detectors must not interpret
    that as a resolver scanning many random high ports on the client.
    """

    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    destination = event.get("destination") if isinstance(event.get("destination"), dict) else {}
    src_port = _port(source.get("port"))
    dst_port = _port(destination.get("port"))
    if src_port is None or dst_port is None or dst_port < EPHEMERAL_PORT_FLOOR:
        return False

    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    event_type = str(event.get("event_type") or "").lower()
    app_proto = str(metadata.get("app_proto") or metadata.get("application") or "").lower()
    dns_type = str(metadata.get("dns_type") or "").lower()
    if src_port == 53 and (
        event_type == "dns"
        or app_proto == "dns"
        or "domain name resolution" in app_proto
        or dns_type == "response"
        or metadata.get("rrname")
    ):
        return True

    return False


def filter_analysis_events(
    events: list[dict[str, Any]],
    excluded_source_hosts: set[str] | list[str] | tuple[str, ...] | None = None,
    excluded_source_networks: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Remove firewall-owned or explicitly excluded sources from attack analysis.

    Raw telemetry is still stored elsewhere. This filter only prevents local
    firewall/WAN/management addresses from becoming threat sources when sensors
    observe NATed or firewall-originated traffic.
    """

    hosts = {str(item).strip() for item in (excluded_source_hosts or []) if str(item).strip()}
    networks = _parse_networks(excluded_source_networks or [])
    filtered = []
    for event in events:
        source_ip = event_source_ip(event)
        if source_ip and source_is_excluded(source_ip, hosts, networks):
            continue
        filtered.append(event)
    return filtered


def event_source_ip(event: dict[str, Any]) -> str | None:
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    value = source.get("ip")
    if value:
        return str(value)
    value = event.get("source_ip")
    return str(value) if value else None


def source_is_excluded(source_ip: str, hosts: set[str], networks: list[ipaddress._BaseNetwork]) -> bool:
    if source_ip in hosts:
        return True
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(address in network for network in networks)


def is_threat_intel_lookup_event(event: dict[str, Any]) -> bool:
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    candidates = [
        metadata.get("rrname"),
        metadata.get("query"),
        metadata.get("domain"),
        metadata.get("hostname"),
        metadata.get("sni"),
        metadata.get("tls_sni"),
        metadata.get("server_name"),
    ]
    for candidate in candidates:
        domain = _normalise_domain(candidate)
        if domain and any(domain == suffix or domain.endswith(f".{suffix}") for suffix in THREAT_INTEL_LOOKUP_SUFFIXES):
            return True
    return False


def _parse_networks(values: list[str] | tuple[str, ...]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
    return networks


def _normalise_domain(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split(":", 1)[0]
    return text
