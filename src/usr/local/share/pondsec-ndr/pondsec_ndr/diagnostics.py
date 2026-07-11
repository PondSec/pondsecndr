"""Diagnostics helpers."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import grp
import shlex
import stat
import subprocess
import tarfile
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.privacy import privacy_status, sanitize_for_export, sanitized_config
from pondsec_ndr.providers import provider_inventory
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.storage.database import EventStore

DEFAULT_SERVICE_USER = os.environ.get("PONDSEC_NDR_SERVICE_USER", "pondsecndr")


def service_status(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    detail = health.get("detail", {}) if isinstance(health.get("detail"), dict) else {}
    db = store.check()
    eve_access = eve_access_status(config)
    return {
        "status": health["status"],
        "pid": health["pid"],
        "updated_at": health["updated_at"],
        "mode": detail.get("effective_mode", config.mode),
        "configured_mode": config.mode,
        "response_mode": detail.get("effective_response_mode", config.response.mode),
        "configured_response_mode": config.response.mode,
        "response_auto_armed": bool(detail.get("response_auto_armed")),
        "effective_response": detail.get("effective_response", {}),
        "enabled": config.enabled,
        "fail_open": config.fail_open,
        "database": db,
        "suricata_eve_path": config.suricata_eve_path,
        "eve_access": eve_access,
        "learning_status": config.detection.learning_status(),
    }


def diagnostics(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    health = store.get_health()
    db = store.check()
    detail = health.get("detail") or {}
    eve_access = eve_access_status(config)
    telemetry_counts = store.telemetry_type_counts()
    ml_runtime = _ml_runtime_status(config)
    pf_blocking = _pf_blocking_status()
    tls_inspection = _tls_inspection_status(telemetry_counts)
    resource_usage = detail.get("resource_usage", {})
    learning_status = config.detection.learning_status()
    providers = provider_inventory(config, health)
    return {
        "status": health["status"],
        "pid": health["pid"],
        "mode": detail.get("effective_mode", config.mode),
        "configured_mode": config.mode,
        "response_mode": detail.get("effective_response_mode", config.response.mode),
        "configured_response_mode": config.response.mode,
        "response_auto_armed": bool(detail.get("response_auto_armed")),
        "effective_response": detail.get("effective_response", {}),
        "uptime_seconds": detail.get("uptime_seconds"),
        "cpu_percent": resource_usage.get("cpu_percent"),
        "ram_mb": resource_usage.get("rss_mb"),
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
        "resource_usage": resource_usage,
        "resource_warnings": detail.get("resource_warnings", []),
        "learning_status": detail.get("learning_status", learning_status),
        "learning_suppressed_detectors": detail.get("learning_suppressed_detectors", []),
        "limits": detail.get("limits", {
            "max_event_rate": config.max_event_rate,
            "max_queue_length": config.max_queue_length,
            "max_database_mb": config.max_database_mb,
            "incident_rate_limit_per_minute": config.incident_rate_limit_per_minute,
            "pf_action_rate_limit_per_minute": config.pf_action_rate_limit_per_minute,
        }),
        "readiness": _readiness_status(config, health, db, eve_access, ml_runtime, pf_blocking, tls_inspection, learning_status),
        "pf_tables": _pf_tables_status(),
        "pf_blocking": pf_blocking,
        "ml_runtime": ml_runtime,
        "host_baselines": store.baseline_summary(),
        "tls_inspection": tls_inspection,
        "providers": providers,
    }


def self_test(config: PondSecConfig, store: EventStore) -> dict[str, Any]:
    errors = config.validate()
    db = store.check()
    eve_access = eve_access_status(config)
    ml_runtime = _ml_runtime_status(config)
    host_baselines = store.baseline_summary()
    learning_status = config.detection.learning_status()
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
            "learning_mode": learning_status["status"],
            "host_baselines": "ok" if host_baselines["total_hosts"] >= 0 else "failed",
            "numpy_runtime": ml_runtime["numpy_status"],
            "pytorch_runtime": "optional_" + ml_runtime["pytorch_status"],
        },
        "eve_access": eve_access,
        "ml_runtime": ml_runtime,
        "learning_status": learning_status,
        "host_baselines": host_baselines,
        "errors": errors,
    }


def diagnostic_archive(config: PondSecConfig, store: EventStore, output_path: Path) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payloads = {
        "diagnostics.json": diagnostics(config, store),
        "service_status.json": service_status(config, store),
        "database.json": store.check(),
        "models.json": {"items": model_inventory(config.data_dir)},
        "providers.json": {"items": provider_inventory(config, store.get_health())},
        "privacy.json": privacy_status(config),
        "sanitized_config.json": sanitized_config(config),
        "permissions.json": {
            "eve_access": eve_access_status(config),
            "pf_blocking": _pf_blocking_status(),
            "pf_tables": _pf_tables_status(),
        },
        "README.json": {
            "archive_type": "pondsec-ndr-diagnostics",
            "contains_sensitive_payloads": False,
            "contains_private_keys": False,
            "contains_passwords": False,
            "note": "Generated for support. Traffic metadata is summarized and configuration is sanitized.",
        },
    }
    with tarfile.open(output_path, "w:gz") as archive:
        for name, payload in payloads.items():
            safe_payload = sanitize_for_export(payload, anonymize=False)
            data = json.dumps(safe_payload, indent=2, sort_keys=True, default=str).encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return {
        "status": "ok",
        "output": str(output_path),
        "files": sorted(payloads),
        "sensitive_payloads_included": False,
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
    learning_status = config.detection.learning_status()
    numpy_spec = importlib.util.find_spec("numpy")
    numpy_version = None
    if numpy_spec is not None:
        try:
            numpy_version = importlib.metadata.version("numpy")
        except importlib.metadata.PackageNotFoundError:
            numpy_version = "unknown"
    torch_spec = importlib.util.find_spec("torch")
    torch_version = None
    if torch_spec is not None:
        try:
            torch_version = importlib.metadata.version("torch")
        except importlib.metadata.PackageNotFoundError:
            torch_version = "unknown"
    return {
        "status": "learning" if learning_status.get("active") else ("active" if config.detection.machine_learning else "disabled"),
        "host_baseline_anomaly": "suppressed_by_learning_mode" if learning_status.get("active") else ("active" if config.detection.machine_learning else "disabled"),
        "external_model_id": preferred["model_id"] if preferred else None,
        "external_model_status": preferred["status"] if preferred else "missing",
        "external_model_runtime": preferred["runtime"] if preferred else None,
        "learning_status": learning_status,
        "numpy_available": numpy_spec is not None,
        "numpy_status": "available" if numpy_spec is not None else "unavailable",
        "numpy_version": numpy_version,
        "pytorch_available": torch_spec is not None,
        "pytorch_status": "available" if torch_spec is not None else "unavailable",
        "pytorch_version": torch_version,
        "python_executable": os.sys.executable,
        "runtime_boundary": "product inference uses a verified pickle-free NumPy export; upstream PyTorch artifacts are handled only by an audited export worker",
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
        "requirement": "optional",
        "note": "PondSec consumes decrypted HTTP metadata when Suricata or a proxy publishes it into telemetry.",
        "recommendation": (
            "For deeper web visibility, enable TLS inspection in Zenarmor or Squid where legally and operationally appropriate. "
            "PondSec still works without TLS decryption, but encrypted payload content remains opaque."
        ),
    }


def _readiness_status(
    config: PondSecConfig,
    health: dict[str, Any],
    db: dict[str, Any],
    eve_access: dict[str, Any],
    ml_runtime: dict[str, Any],
    pf_blocking: dict[str, Any],
    tls_inspection: dict[str, Any],
    learning_status: dict[str, Any],
) -> dict[str, Any]:
    detail = health.get("detail", {}) if isinstance(health.get("detail"), dict) else {}
    checks = [
        {
            "id": "service_enabled",
            "label": "PondSec service enabled",
            "requirement": "required",
            "status": "ok" if config.enabled else "warning",
            "detail": "PondSec is enabled in plugin settings." if config.enabled else "PondSec is installed but disabled in plugin settings.",
            "recommendation": "" if config.enabled else "Enable PondSec NDR in Settings after confirming interfaces and data sources.",
        },
        {
            "id": "suricata_eve",
            "label": "Suricata EVE telemetry",
            "requirement": "required",
            "status": "ok" if eve_access.get("status") == "ok" else "failed",
            "detail": eve_access.get("message") or "Suricata EVE telemetry is not confirmed.",
            "recommendation": eve_access.get("recommendation") or "",
        },
        {
            "id": "interfaces",
            "label": "Protected interfaces selected",
            "requirement": "required",
            "status": "ok" if (config.interfaces.monitored or config.interfaces.internal or config.interfaces.wan) else "warning",
            "detail": ", ".join(config.interfaces.monitored or config.interfaces.internal or config.interfaces.wan) or "No monitored interface selected.",
            "recommendation": "" if (config.interfaces.monitored or config.interfaces.internal or config.interfaces.wan) else "Select WAN, internal, DMZ and VLAN interfaces in PondSec NDR settings.",
        },
        {
            "id": "database",
            "label": "Local event database",
            "requirement": "required",
            "status": "ok" if db.get("status") == "ok" else "failed",
            "detail": f"Schema {db.get('schema_version')} integrity {db.get('integrity')}.",
            "recommendation": "" if db.get("status") == "ok" else "Run database check/migration before starting the service.",
        },
        {
            "id": "ml_runtime",
            "label": "AI model runtime",
            "requirement": "required for AI detections",
            "status": "ok" if ml_runtime.get("external_model_status") == "active" else "warning",
            "detail": f"{ml_runtime.get('external_model_id') or 'No model'} status: {ml_runtime.get('external_model_status')}.",
            "recommendation": "" if ml_runtime.get("external_model_status") == "active" else "Install and verify the pretrained model artifact, then run the model self-test.",
        },
        {
            "id": "learning_mode",
            "label": "AI learning phase",
            "requirement": "required for AI production alarms",
            "status": "warning" if learning_status.get("active") else "ok",
            "detail": (
                f"Status {learning_status.get('status')}; remaining days: {learning_status.get('remaining_days')}; "
                f"override: {bool(learning_status.get('early_ai_activation_override'))}."
            ),
            "recommendation": learning_status.get("warning") or "AI alarms are armed for production use.",
        },
        _response_policy_readiness(config, learning_status, detail),
        {
            "id": "pf_response",
            "label": "PF response rule",
            "requirement": "required for blocking",
            "status": "ok" if pf_blocking.get("rule_present") else "warning",
            "detail": f"PF table {pf_blocking.get('table')} rule present: {bool(pf_blocking.get('rule_present'))}.",
            "recommendation": "" if pf_blocking.get("rule_present") else "Install/reconfigure the plugin so PondSec PF table enforcement can be applied.",
        },
        {
            "id": "tls_visibility",
            "label": "TLS / web visibility",
            "requirement": "optional",
            "status": "ok" if tls_inspection.get("status") in {"http_metadata_observed", "tls_metadata_observed"} else "info",
            "detail": f"HTTP events: {tls_inspection.get('http_events_24h')}; TLS events: {tls_inspection.get('tls_events_24h')}.",
            "recommendation": tls_inspection.get("recommendation", ""),
        },
        {
            "id": "privacy_defaults",
            "label": "Privacy defaults",
            "requirement": "required for publication",
            "status": "ok" if config.privacy_mode else "warning",
            "detail": "Privacy mode is enabled; cloud telemetry is not used by PondSec.",
            "recommendation": "" if config.privacy_mode else "Enable privacy mode before production rollout.",
        },
    ]
    required = [item for item in checks if item["requirement"].startswith("required")]
    failed = [item for item in required if item["status"] == "failed"]
    warnings = [item for item in required if item["status"] == "warning"]
    if failed:
        status = "not_ready"
    elif warnings:
        status = "needs_attention"
    else:
        status = "ready"
    return {
        "status": status,
        "mode": detail.get("effective_mode", config.mode),
        "configured_mode": config.mode,
        "response_mode": detail.get("effective_response_mode", config.response.mode),
        "configured_response_mode": config.response.mode,
        "response_auto_armed": bool(detail.get("response_auto_armed")),
        "automatic_blocking": bool((detail.get("effective_response") or {}).get("automatic_blocking", config.response.automatic_blocking)),
        "service_status": health.get("status"),
        "required_ok": len(required) - len(failed) - len(warnings),
        "required_total": len(required),
        "checks": checks,
    }


def _response_policy_readiness(config: PondSecConfig, learning_status: dict[str, Any], health_detail: dict[str, Any] | None = None) -> dict[str, Any]:
    response = config.response
    health_detail = health_detail or {}
    effective_response = health_detail.get("effective_response") if isinstance(health_detail.get("effective_response"), dict) else {}
    effective_mode = str(health_detail.get("effective_response_mode") or response.mode)
    auto_armed = bool(health_detail.get("response_auto_armed"))
    if auto_armed:
        status = "ok"
        detail = "Auto-arm is active after learning; effective Enforce response is armed with safety gates."
        recommendation = ""
        return {
            "id": "response_policy",
            "label": "Automatic response posture",
            "requirement": "required for safe enforcement",
            "status": status,
            "detail": detail,
            "recommendation": recommendation,
            "mode": effective_mode,
            "configured_mode": response.mode,
            "response_auto_armed": True,
            "automatic_blocking": bool(effective_response.get("automatic_blocking")),
            "ai_full_decision_mode": bool(effective_response.get("ai_full_decision_mode")),
            "isolate_internal": bool(effective_response.get("isolate_internal")),
            "internal_isolation_cooldown_seconds": response.internal_isolation_cooldown_seconds,
            "max_internal_isolations_per_hour": response.max_internal_isolations_per_hour,
            "kill_switch": response.kill_switch,
            "maintenance_mode": response.maintenance_mode,
        }
    if response.mode == "observe":
        status = "ok"
        detail = "Observe mode is active; PondSec will not change PF tables automatically."
        recommendation = "Stay in Observe during learning. Move to Recommend or Enforce only after baselines and protected assets are verified."
    elif response.mode == "recommend":
        status = "ok"
        detail = "Recommend mode is active; PondSec can create response proposals without changing PF tables."
        recommendation = "Review proposals and protected assets before enabling Enforce."
    elif response.mode == "shadow_enforce":
        status = "warning"
        detail = "Shadow Enforce is active; PondSec evaluates would-execute response decisions without changing PF tables."
        recommendation = "Use Shadow Enforce only for validation. After learning completes, Auto-arm should move effective response to Enforce for real prevention."
    elif response.mode == "enforce":
        blockers = []
        if not response.automatic_blocking:
            blockers.append("automatic blocking is disabled")
        if learning_status.get("active"):
            blockers.append("learning phase is active")
        elif response.isolate_internal and not _learning_complete_for_internal_response(learning_status):
            blockers.append("learning phase is not complete for internal auto-isolation")
        if not response.ai_full_decision_mode:
            blockers.append("AI full decision mode is disabled")
        if response.kill_switch:
            blockers.append("response kill switch is active")
        if response.maintenance_mode:
            blockers.append("maintenance mode is active")
        status = "ok" if not blockers else "warning"
        detail = "Enforce mode is armed." if not blockers else "Enforce mode is not armed: " + "; ".join(blockers) + "."
        recommendation = "" if not blockers else "Keep Observe or Recommend until every response-policy precondition is satisfied."
    else:
        status = "failed"
        detail = f"Unknown response mode: {response.mode}."
        recommendation = "Select Observe, Recommend, Shadow Enforce, or Enforce."
    return {
        "id": "response_policy",
        "label": "Automatic response posture",
        "requirement": "required for safe enforcement",
        "status": status,
        "detail": detail,
        "recommendation": recommendation,
        "mode": response.mode,
        "automatic_blocking": response.automatic_blocking,
        "ai_full_decision_mode": response.ai_full_decision_mode,
        "isolate_internal": response.isolate_internal,
        "internal_isolation_cooldown_seconds": response.internal_isolation_cooldown_seconds,
        "max_internal_isolations_per_hour": response.max_internal_isolations_per_hour,
        "kill_switch": response.kill_switch,
        "maintenance_mode": response.maintenance_mode,
    }


def _learning_complete_for_internal_response(learning_status: dict[str, Any]) -> bool:
    return (
        learning_status.get("status") == "armed"
        and bool(learning_status.get("started_at"))
        and int(learning_status.get("remaining_days") or 0) == 0
    )


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
