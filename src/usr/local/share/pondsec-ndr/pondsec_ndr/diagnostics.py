"""Diagnostics helpers."""

from __future__ import annotations

import os
import subprocess
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.storage.database import EventStore


def service_status(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    db = store.check()
    return {
        "status": health["status"],
        "pid": health["pid"],
        "updated_at": health["updated_at"],
        "mode": config.mode,
        "enabled": config.enabled,
        "fail_open": config.fail_open,
        "database": db,
        "suricata_eve_path": config.suricata_eve_path,
    }


def diagnostics(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    db = store.check()
    detail = health.get("detail") or {}
    return {
        "status": health["status"],
        "pid": health["pid"],
        "uptime_seconds": detail.get("uptime_seconds"),
        "cpu_percent": None,
        "ram_bytes": None,
        "eventrate": detail.get("event_rate_per_second", 0),
        "queue_size": detail.get("queue_size", 0),
        "queue_drops": detail.get("queue_drops", 0),
        "parser_errors": detail.get("parser_errors", 0),
        "database_size": db.get("size_bytes"),
        "active_model_version": _active_model(config),
        "feature_version": "1",
        "collector_offset": detail.get("collector_offset"),
        "suricata_eve_path": config.suricata_eve_path,
        "last_collector_errors": detail.get("last_collector_errors", []),
        "last_ml_errors": detail.get("last_ml_errors", []),
        "last_response_errors": detail.get("last_response_errors", []),
        "pf_tables": _pf_tables_status(),
    }


def self_test(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    errors = config.validate()
    db = store.check()
    if db["status"] != "ok":
        errors.append("database integrity check failed")
    return {
        "status": "ok" if not errors else "failed",
        "checks": {
            "config": "ok" if not config.validate() else "failed",
            "database": db["status"],
            "fail_open": config.fail_open,
            "response_side_effects": "none",
        },
        "errors": errors,
    }


def _active_model(config: PondSecConfig) -> str | None:
    for model in model_inventory(config.data_dir):
        if model.get("active"):
            return model["model_id"]
    return None


def _pf_tables_status() -> dict[str, Any]:
    try:
        result = subprocess.run(
            ["/sbin/pfctl", "-s", "Tables"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "tables": []}
    tables = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("PONDSEC_NDR_")]
    return {"available": result.returncode == 0, "tables": tables}
