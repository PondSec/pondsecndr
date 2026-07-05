"""Internal event schema helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from typing import Any
from uuid import NAMESPACE_URL, uuid5


SUPPORTED_EVE_TYPES = {"flow", "alert", "drop", "dns", "tls", "http", "fileinfo", "anomaly", "stats"}
FEATURE_SCHEMA_VERSION = "1"
EVENT_SCHEMA_VERSION = 1


def parse_timestamp(value: Any) -> str | None:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    text = str(value).strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def valid_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def valid_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def event_id_from(data: dict[str, Any]) -> str:
    basis = {
        "timestamp": data.get("timestamp"),
        "event_type": data.get("event_type"),
        "src": data.get("source", {}).get("ip"),
        "sp": data.get("source", {}).get("port"),
        "dst": data.get("destination", {}).get("ip"),
        "dp": data.get("destination", {}).get("port"),
        "proto": data.get("protocol"),
        "meta": data.get("metadata", {}),
    }
    return str(uuid5(NAMESPACE_URL, json.dumps(basis, sort_keys=True, default=str)))


def empty_event(event_type: str, timestamp: str) -> dict[str, Any]:
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "event_type": event_type,
        "timestamp": timestamp,
        "source": {"ip": None, "port": None, "interface": None},
        "destination": {"ip": None, "port": None},
        "protocol": None,
        "direction": "unknown",
        "metadata": {},
        "raw_source": "suricata",
    }
