"""Diagnostics helpers."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
from pathlib import Path
import pwd
import grp
import shlex
import stat
import subprocess
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.storage.database import EventStore

DEFAULT_SERVICE_USER = os.environ.get("PONDSEC_NDR_SERVICE_USER", "pondsecndr")


def service_status(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    db = store.check()
    eve_access = eve_access_status(config)
    return {
        "status": health["status"],
        "pid": health["pid"],
        "updated_at": health["updated_at"],
        "mode": config.mode,
        "enabled": config.enabled,
        "fail_open": config.fail_open,
        "database": db,
        "suricata_eve_path": config.suricata_eve_path,
        "eve_access": eve_access,
    }


def diagnostics(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    db = store.check()
    detail = health.get("detail") or {}
    eve_access = eve_access_status(config)
    telemetry_counts = store.telemetry_type_counts()
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
        "eve_access": eve_access,
        "last_collector_errors": detail.get("last_collector_errors", []),
        "last_ml_errors": detail.get("last_ml_errors", []),
        "last_response_errors": detail.get("last_response_errors", []),
        "pf_tables": _pf_tables_status(),
        "pf_blocking": _pf_blocking_status(),
        "ml_runtime": _ml_runtime_status(config),
        "host_baselines": store.baseline_summary(),
        "tls_inspection": _tls_inspection_status(telemetry_counts),
    }


def self_test(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    errors = config.validate()
    db = store.check()
    eve_access = eve_access_status(config)
    ml_runtime = _ml_runtime_status(config)
    host_baselines = store.baseline_summary()
    if db["status"] != "ok":
        errors.append("database integrity check failed")
    if eve_access["status"] != "ok":
        errors.append(eve_access["message"])
    return {
        "status": "ok" if not errors else "failed",
        "checks": {
            "config": "ok" if not config.validate() else "failed",
            "database": db["status"],
            "eve_access": eve_access["status"],
            "fail_open": config.fail_open,
            "response_side_effects": "time_limited_pf_table_on_activation",
            "machine_learning": "ok" if config.detection.machine_learning else "disabled",
            "host_baselines": "ok" if host_baselines["total_hosts"] >= 0 else "failed",
            "pytorch_runtime": ml_runtime["pytorch_status"],
        },
        "eve_access": eve_access,
        "ml_runtime": ml_runtime,
        "host_baselines": host_baselines,
        "errors": errors,
    }


def eve_access_status(config: PondSecConfig, service_user: str = DEFAULT_SERVICE_USER) -> dict[str, Any]:
    eve_path = Path(config.suricata_eve_path)
    result: dict[str, Any] = {
        "status": "failed",
        "path": str(eve_path),
        "service_user": service_user,
        "exists": False,
        "parent": str(eve_path.parent),
        "parent_traversable": False,
        "readable": False,
        "checked_by": "posix-mode",
        "message": "",
        "recommendation": "",
    }
    if not eve_path.is_absolute():
        result.update({
            "message": "Suricata EVE path must be absolute",
            "recommendation": "Use an absolute path such as /var/log/suricata/eve.json.",
        })
        return result

    try:
        user = pwd.getpwnam(service_user)
    except KeyError:
        result.update({
            "message": f"service user does not exist: {service_user}",
            "recommendation": "Run the plugin post-install step so the dedicated service account is created.",
        })
        return result

    probe = _actual_read_probe(eve_path, service_user)
    if probe["attempted"]:
        result["checked_by"] = "service-user-probe"
        result["probe"] = probe
        result["readable"] = bool(probe["readable"])
        try:
            result["exists"] = eve_path.exists()
        except OSError:
            result["exists"] = False
        if probe["readable"]:
            result.update({
                "status": "ok",
                "parent_traversable": True,
                "message": f"EVE file is readable by {service_user}: {eve_path}",
                "recommendation": "",
            })
            return result

    groups = _groups_for_user(service_user, user.pw_gid)
    parent_check = _ancestor_access(eve_path.parent, user.pw_uid, groups)
    result["parent_traversable"] = parent_check["ok"]
    if not parent_check["ok"] and not probe["attempted"]:
        result.update({
            "message": f"EVE parent path is not traversable by {service_user}: {parent_check['path']}",
            "recommendation": (
                "Grant the service user execute permission on the Suricata log directory path, "
                "for example with a group/ACL that lets pondsecndr traverse /var/log/suricata."
            ),
        })
        return result

    try:
        file_stat = eve_path.stat()
    except FileNotFoundError:
        result.update({
            "status": "missing",
            "message": f"EVE file does not exist: {eve_path}",
            "recommendation": "Enable Suricata EVE JSON logging or update the configured Suricata EVE path.",
        })
        return result
    except PermissionError:
        result.update({
            "message": f"EVE file is not statable by the current diagnostic process: {eve_path}",
            "recommendation": "Check directory permissions and OPNsense log path hardening.",
        })
        return result
    except OSError as exc:
        result.update({
            "message": f"EVE file cannot be inspected: {exc}",
            "recommendation": "Check the configured path and underlying filesystem state.",
        })
        return result

    result["exists"] = True
    result["readable"] = _mode_allows(file_stat, user.pw_uid, groups, os.R_OK)

    if result["readable"]:
        result.update({
            "status": "ok",
            "message": f"EVE file is readable by {service_user}: {eve_path}",
            "recommendation": "",
        })
        return result

    result.update({
        "message": f"EVE file is not readable by {service_user}: {eve_path}",
        "recommendation": (
            "Grant read permission on eve.json to pondsecndr, or add pondsecndr to the log-reading "
            "group/ACL used by Suricata while keeping the service unprivileged."
        ),
    })
    return result


def _groups_for_user(username: str, primary_gid: int) -> set[int]:
    groups = {primary_gid}
    for group in grp.getgrall():
        if username in group.gr_mem:
            groups.add(group.gr_gid)
    return groups


def _ancestor_access(path: Path, uid: int, groups: set[int]) -> dict[str, Any]:
    current = Path(path.anchor or "/")
    if not path.is_absolute():
        return {"ok": False, "path": str(path)}
    for part in path.parts[1:]:
        current = current / part
        try:
            path_stat = current.stat()
        except OSError:
            return {"ok": False, "path": str(current)}
        if not stat.S_ISDIR(path_stat.st_mode) or not _mode_allows(path_stat, uid, groups, os.X_OK):
            return {"ok": False, "path": str(current)}
    return {"ok": True, "path": str(path)}


def _mode_allows(path_stat: os.stat_result, uid: int, groups: set[int], access: int) -> bool:
    checks = []
    if access & os.R_OK:
        checks.append((stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH))
    if access & os.W_OK:
        checks.append((stat.S_IWUSR, stat.S_IWGRP, stat.S_IWOTH))
    if access & os.X_OK:
        checks.append((stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH))
    if not checks:
        return True
    for owner_bit, group_bit, other_bit in checks:
        if path_stat.st_uid == uid:
            allowed = bool(path_stat.st_mode & owner_bit)
        elif path_stat.st_gid in groups:
            allowed = bool(path_stat.st_mode & group_bit)
        else:
            allowed = bool(path_stat.st_mode & other_bit)
        if not allowed:
            return False
    return True


def _actual_read_probe(eve_path: Path, service_user: str) -> dict[str, Any]:
    su_path = Path("/usr/bin/su")
    if os.geteuid() != 0 or not su_path.exists():
        return {"attempted": False, "readable": None}
    command = f"/bin/test -r {shlex.quote(str(eve_path))}"
    try:
        probe = subprocess.run(
            [str(su_path), "-m", service_user, "-c", command],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"attempted": True, "readable": False, "error": str(exc)}
    payload: dict[str, Any] = {"attempted": True, "readable": probe.returncode == 0, "returncode": probe.returncode}
    if probe.stderr.strip():
        payload["stderr"] = probe.stderr.strip()[-300:]
    return payload


def _active_model(config: PondSecConfig) -> str | None:
    for model in model_inventory(config.data_dir):
        if model.get("active"):
            return model["model_id"]
    return None


def _ml_runtime_status(config: PondSecConfig) -> dict[str, Any]:
    inventory = model_inventory(config.data_dir)
    preferred = next((item for item in inventory if item.get("preferred")), None)
    torch_spec = importlib.util.find_spec("torch")
    torch_version = None
    if torch_spec is not None:
        try:
            torch_version = importlib.metadata.version("torch")
        except importlib.metadata.PackageNotFoundError:
            torch_version = "unknown"
    return {
        "status": "active" if config.detection.machine_learning else "disabled",
        "host_baseline_anomaly": "active" if config.detection.machine_learning else "disabled",
        "external_model_id": preferred["model_id"] if preferred else None,
        "external_model_status": preferred["status"] if preferred else "missing",
        "external_model_runtime": preferred["runtime"] if preferred else None,
        "pytorch_available": torch_spec is not None,
        "pytorch_status": "available" if torch_spec is not None else "unavailable",
        "pytorch_version": torch_version,
        "python_executable": os.sys.executable,
        "runtime_boundary": "external pretrained models run only in an unprivileged audited worker",
    }


def _tls_inspection_status(telemetry_counts: dict[str, int]) -> dict[str, Any]:
    http_events = int(telemetry_counts.get("http", 0))
    tls_events = int(telemetry_counts.get("tls", 0))
    if http_events:
        status = "http_metadata_observed"
    elif tls_events:
        status = "tls_metadata_observed"
    else:
        status = "no_recent_tls_http_metadata"
    return {
        "status": status,
        "http_events_24h": http_events,
        "tls_events_24h": tls_events,
        "note": "PondSec consumes decrypted HTTP metadata when Suricata or a proxy publishes it into telemetry.",
    }


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


def _pf_blocking_status() -> dict[str, Any]:
    enforcer = PFTableEnforcer()
    return {
        "table": enforcer.table,
        "rule_present": enforcer.rule_present(),
        "mode": "active-table-enforcement",
    }
