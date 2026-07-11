"""Traffic classification helpers shared by aggregation and detectors."""

from __future__ import annotations

from typing import Any


EPHEMERAL_PORT_FLOOR = 32768


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
