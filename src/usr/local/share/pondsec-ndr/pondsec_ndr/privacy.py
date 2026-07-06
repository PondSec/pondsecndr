"""Privacy-preserving exports and data deletion helpers."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.storage.database import EventStore


EXPORT_TABLES = [
    "incidents",
    "detections",
    "hosts",
    "block_entries",
    "allowlist_entries",
    "models",
    "policies",
]
IP_FIELD_NAMES = {
    "ip",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dest_ip",
    "host_ip",
    "value",
    "destination",
}
SENSITIVE_FIELD_PARTS = {
    "password",
    "passwd",
    "secret",
    "private_key",
    "authorization",
    "cookie",
    "token",
}


def privacy_status(config: PondSecConfig) -> dict[str, Any]:
    return {
        "status": "ok",
        "retention_days": config.retention_days,
        "privacy_mode": config.privacy_mode,
        "anonymize_storage": config.anonymize_storage,
        "payload_storage": "disabled",
        "cloud_telemetry": "disabled_without_explicit_opt_in",
        "exports": {
            "anonymized_json": True,
            "raw_export_requires_explicit_flag": True,
        },
        "data_deletion": {
            "telemetry_purge": True,
            "open_incidents_retained_by_default": True,
        },
    }


def export_privacy_bundle(
    config: PondSecConfig,
    store: EventStore,
    output_path: Path,
    anonymize: bool = True,
    include_events: bool = False,
) -> dict[str, Any]:
    tables = ["events"] + EXPORT_TABLES if include_events else list(EXPORT_TABLES)
    bundle: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "export_type": "pondsec-ndr-privacy-export",
        "anonymized": anonymize,
        "payload_storage": "disabled",
        "cloud_telemetry": "disabled_without_explicit_opt_in",
        "retention_days": config.retention_days,
        "tables": {},
    }
    for table in tables:
        rows = store.list_rows(table, limit=10000)
        decoded = [_decode_json_columns(row) for row in rows]
        bundle["tables"][table] = [sanitize_for_export(row, anonymize=anonymize) for row in decoded]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return {
        "status": "ok",
        "output": str(output_path),
        "anonymized": anonymize,
        "include_events": include_events,
        "tables": {table: len(bundle["tables"][table]) for table in tables},
    }


def purge_telemetry_before(store: EventStore, older_than_days: int) -> dict[str, Any]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, older_than_days))).isoformat()
    deleted = store.purge_before(cutoff)
    return {
        "status": "ok",
        "cutoff": cutoff,
        "deleted_records": deleted,
        "open_incidents_retained": True,
    }


def sanitized_config(config: PondSecConfig) -> dict[str, Any]:
    payload = asdict(config)
    for key in ("data_dir", "log_dir", "run_dir"):
        if key in payload:
            payload[key] = str(payload[key])
    return sanitize_for_export(payload, anonymize=False)


def sanitize_for_export(value: Any, anonymize: bool = True, key_name: str | None = None) -> Any:
    if key_name and _is_sensitive_key(key_name):
        return "[redacted]"
    if isinstance(value, dict):
        return {key: sanitize_for_export(item, anonymize=anonymize, key_name=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_for_export(item, anonymize=anonymize, key_name=key_name) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_export(item, anonymize=anonymize, key_name=key_name) for item in value]
    if anonymize and isinstance(value, str) and _should_anonymize_value(value, key_name):
        return anonymize_address(value)
    return value


def anonymize_address(value: str) -> str:
    text = str(value)
    try:
        if "/" in text:
            parsed = ipaddress.ip_network(text, strict=False)
            kind = f"ip{parsed.version}-net"
        else:
            parsed = ipaddress.ip_address(text)
            kind = f"ip{parsed.version}"
    except ValueError:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"anon-{kind}-{digest}"


def _decode_json_columns(row: dict[str, Any]) -> dict[str, Any]:
    decoded = dict(row)
    for key in list(decoded):
        if key.endswith("_json") and isinstance(decoded[key], str):
            try:
                decoded[key[:-5]] = json.loads(decoded[key])
                del decoded[key]
            except json.JSONDecodeError:
                pass
    return decoded


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_FIELD_PARTS)


def _should_anonymize_value(value: str, key_name: str | None) -> bool:
    if key_name and key_name.lower() in IP_FIELD_NAMES:
        return _looks_like_address(value)
    return _looks_like_address(value)


def _looks_like_address(value: str) -> bool:
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
