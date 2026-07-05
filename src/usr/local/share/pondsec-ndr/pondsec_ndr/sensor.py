"""OPNsense Suricata sensor checks and hardening helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


CONFIG_XML = Path("/conf/config.xml")
SURICATA_YAML = Path("/usr/local/etc/suricata/suricata.yaml")
BACKUP_DIR = Path("/var/backups/pondsec-ndr")

BASE_EVE_TYPES = ("alert", "drop", "flow", "dns")


def required_eve_types(config: Any) -> list[str]:
    required = list(BASE_EVE_TYPES)
    if getattr(config.detection, "http_metadata", True):
        required.append("http")
    if getattr(config.detection, "tls_analysis", True):
        required.append("tls")
    return required


def eve_types_from_suricata_yaml(text: str) -> list[str]:
    types: list[str] = []
    in_first_eve_log = False
    in_types = False
    types_indent = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "- eve-log:" and not in_first_eve_log:
            in_first_eve_log = True
            continue
        if not in_first_eve_log:
            continue
        if stripped == "types:":
            in_types = True
            types_indent = len(line) - len(line.lstrip())
            continue
        if in_types:
            indent = len(line) - len(line.lstrip())
            if stripped and indent <= types_indent:
                break
            if stripped.startswith("- "):
                name = stripped[2:].split(":", 1)[0].strip()
                if name:
                    types.append(name)
    return types


def patch_suricata_yaml_text(text: str, required: list[str] | tuple[str, ...]) -> tuple[str, bool, list[str]]:
    present = set(eve_types_from_suricata_yaml(text))
    missing = [item for item in required if item not in present]
    patchable = [item for item in missing if item in {"flow", "dns"}]
    if not patchable:
        return text, False, []

    lines = text.splitlines()
    output: list[str] = []
    inserted = False
    for line in lines:
        output.append(line)
        if not inserted and line.strip() == "types:":
            indent = line[: len(line) - len(line.lstrip())] + "  "
            if "flow" in patchable:
                output.append(f"{indent}- flow")
            if "dns" in patchable:
                output.append(f"{indent}- dns:")
                output.append(f"{indent}    requests: yes")
                output.append(f"{indent}    responses: yes")
            inserted = True
    if not inserted:
        return text, False, []
    return "\n".join(output) + ("\n" if text.endswith("\n") else ""), True, patchable


def sensor_status(config: Any) -> dict[str, Any]:
    desired_interfaces = config.interfaces.monitored
    ids = _ids_config_status(desired_interfaces)
    yaml_status = _suricata_yaml_status(required_eve_types(config))
    running = _command_ok(["/bin/pgrep", "-qx", "suricata"])
    status = "ok"
    issues: list[str] = []
    if ids.get("config_present") and ids.get("missing_interfaces"):
        issues.append("ids_interfaces_missing")
    if yaml_status.get("missing_required_eve_types"):
        issues.append("suricata_eve_types_missing")
    if not running:
        issues.append("suricata_not_running")
    if issues:
        status = "failed"
    return {
        "status": status,
        "issues": issues,
        "opnsense_ids": ids,
        "suricata_eve": yaml_status,
        "suricata_running": running,
        "required_eve_types": required_eve_types(config),
        "note": "PondSec NDR needs Suricata EVE flow and dns telemetry for live behavior and AI detections.",
    }


def harden_sensor(config: Any, restart_suricata: bool = False) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    changes: list[str] = []
    errors: list[str] = []
    backups: list[str] = []

    config_result = _harden_ids_config(config.interfaces.monitored, config)
    changes.extend(config_result["changes"])
    errors.extend(config_result["errors"])
    backups.extend(config_result["backups"])

    template_result = _run(["/usr/local/sbin/configctl", "template", "reload", "OPNsense/IDS"])
    if template_result["returncode"] == 0:
        changes.append("opnsense_ids_template_reloaded")
    else:
        errors.append("template_reload_failed")

    yaml_result = _patch_suricata_yaml(required_eve_types(config))
    changes.extend(yaml_result["changes"])
    errors.extend(yaml_result["errors"])
    backups.extend(yaml_result["backups"])

    newsyslog_result = _harden_newsyslog()
    changes.extend(newsyslog_result["changes"])
    errors.extend(newsyslog_result["errors"])
    backups.extend(newsyslog_result["backups"])

    restart_result = None
    if restart_suricata:
        restart_result = _run(["/usr/local/sbin/configctl", "ids", "restart"])
        if restart_result["returncode"] == 0:
            changes.append("suricata_restarted")
        else:
            errors.append("suricata_restart_failed")

    acl_result = _harden_eve_acl()
    changes.extend(acl_result["changes"])
    errors.extend(acl_result["errors"])

    status = sensor_status(config)
    return {
        "status": "ok" if not errors and status["status"] == "ok" else "failed",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "changes": changes,
        "errors": errors,
        "backups": backups,
        "template_reload": template_result,
        "suricata_restart": restart_result,
        "sensor_status": status,
    }


def _ids_config_status(desired_interfaces: list[str]) -> dict[str, Any]:
    if not CONFIG_XML.exists():
        return {"config_present": False, "path": str(CONFIG_XML), "missing_interfaces": desired_interfaces}
    try:
        root = ET.parse(CONFIG_XML).getroot()
    except ET.ParseError as exc:
        return {"config_present": True, "path": str(CONFIG_XML), "parse_error": str(exc), "missing_interfaces": desired_interfaces}
    general = root.find("OPNsense/IDS/general")
    if general is None:
        return {"config_present": True, "path": str(CONFIG_XML), "ids_present": False, "missing_interfaces": desired_interfaces}
    interfaces = _csv((general.findtext("interfaces") or ""))
    return {
        "config_present": True,
        "ids_present": True,
        "enabled": general.findtext("enabled"),
        "mode": general.findtext("mode"),
        "interfaces": interfaces,
        "desired_interfaces": desired_interfaces,
        "missing_interfaces": [item for item in desired_interfaces if item not in interfaces],
        "http_eve_enabled": general.findtext("eveLog/http/enable"),
        "tls_eve_enabled": general.findtext("eveLog/tls/enable"),
    }


def _suricata_yaml_status(required: list[str]) -> dict[str, Any]:
    if not SURICATA_YAML.exists():
        return {"path": str(SURICATA_YAML), "exists": False, "eve_types": [], "missing_required_eve_types": required}
    text = SURICATA_YAML.read_text(encoding="utf-8", errors="replace")
    eve_types = eve_types_from_suricata_yaml(text)
    return {
        "path": str(SURICATA_YAML),
        "exists": True,
        "eve_types": eve_types,
        "missing_required_eve_types": [item for item in required if item not in eve_types],
    }


def _harden_ids_config(desired_interfaces: list[str], config: Any) -> dict[str, Any]:
    result = {"changes": [], "errors": [], "backups": []}
    if not CONFIG_XML.exists():
        result["errors"].append("opnsense_config_xml_missing")
        return result
    try:
        tree = ET.parse(CONFIG_XML)
    except ET.ParseError as exc:
        result["errors"].append(f"opnsense_config_xml_parse_failed: {exc}")
        return result
    root = tree.getroot()
    general = root.find("OPNsense/IDS/general")
    if general is None:
        result["errors"].append("opnsense_ids_general_missing")
        return result
    changed = False
    current = _csv(general.findtext("interfaces") or "")
    merged = current + [item for item in desired_interfaces if item and item not in current]
    if merged != current:
        _child(general, "interfaces").text = ",".join(merged)
        result["changes"].append("opnsense_ids_interfaces_updated")
        changed = True
    if getattr(config.detection, "http_metadata", True):
        changed |= _set_nested_text(general, ["eveLog", "http", "enable"], "1", result, "opnsense_http_eve_enabled")
    if getattr(config.detection, "tls_analysis", True):
        changed |= _set_nested_text(general, ["eveLog", "tls", "enable"], "1", result, "opnsense_tls_eve_enabled")
        changed |= _set_nested_text(general, ["eveLog", "tls", "extended"], "1", result, "opnsense_tls_eve_extended")
    if not changed:
        return result
    backup = _backup(CONFIG_XML)
    result["backups"].append(str(backup))
    tree.write(CONFIG_XML, encoding="utf-8", xml_declaration=True)
    return result


def _patch_suricata_yaml(required: list[str]) -> dict[str, Any]:
    result = {"changes": [], "errors": [], "backups": []}
    if not SURICATA_YAML.exists():
        result["errors"].append("suricata_yaml_missing")
        return result
    text = SURICATA_YAML.read_text(encoding="utf-8", errors="replace")
    patched, changed, added = patch_suricata_yaml_text(text, required)
    if not changed:
        return result
    backup = _backup(SURICATA_YAML)
    result["backups"].append(str(backup))
    SURICATA_YAML.write_text(patched, encoding="utf-8")
    result["changes"].append("suricata_yaml_eve_types_added:" + ",".join(added))
    return result


def _harden_eve_acl() -> dict[str, Any]:
    result = {"changes": [], "errors": []}
    log_dir = Path("/var/log/suricata")
    eve = log_dir / "eve.json"
    if not log_dir.exists():
        return result
    for command, change in (
        (["/bin/chmod", "750", str(log_dir)], "suricata_log_dir_mode_checked"),
        (["/bin/setfacl", "-m", "u:pondsecndr:xaRcs::allow", str(log_dir)], "suricata_log_dir_acl_checked"),
    ):
        payload = _run(command)
        if payload["returncode"] == 0:
            result["changes"].append(change)
    if eve.exists():
        for command, change in (
            (["/usr/sbin/chown", "root:pondsecndr", str(eve)], "eve_group_checked"),
            (["/bin/chmod", "640", str(eve)], "eve_mode_checked"),
            (["/bin/setfacl", "-m", "u:pondsecndr:raRcs::allow", str(eve)], "eve_acl_checked"),
        ):
            payload = _run(command)
            if payload["returncode"] == 0:
                result["changes"].append(change)
    return result


def _harden_newsyslog() -> dict[str, Any]:
    result = {"changes": [], "errors": [], "backups": []}
    path = Path("/etc/newsyslog.conf.d/suricata")
    if not path.exists():
        return result
    text = path.read_text(encoding="utf-8", errors="replace")
    replacement = text.replace("/var/log/suricata/eve.json\troot:wheel\t640", "/var/log/suricata/eve.json\troot:pondsecndr\t640")
    replacement = replacement.replace("/var/log/suricata/eve.json root:wheel 640", "/var/log/suricata/eve.json root:pondsecndr 640")
    if replacement == text:
        return result
    backup = _backup(path)
    result["backups"].append(str(backup))
    path.write_text(replacement, encoding="utf-8")
    result["changes"].append("suricata_newsyslog_group_updated")
    return result


def _set_nested_text(root: ET.Element, path: list[str], value: str, result: dict[str, Any], change_name: str) -> bool:
    node = root
    for part in path:
        node = _child(node, part)
    if node.text == value:
        return False
    node.text = value
    result["changes"].append(change_name)
    return True


def _child(root: ET.Element, name: str) -> ET.Element:
    node = root.find(name)
    if node is None:
        node = ET.SubElement(root, name)
    return node


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _backup(path: Path) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    target = BACKUP_DIR / f"{path.name}.{stamp}.bak"
    shutil.copy2(path, target)
    return target


def _command_ok(command: list[str]) -> bool:
    return _run(command)["returncode"] == 0


def _run(command: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except OSError as exc:
        return {"command": command, "returncode": 127, "stdout": "", "stderr": str(exc)}
