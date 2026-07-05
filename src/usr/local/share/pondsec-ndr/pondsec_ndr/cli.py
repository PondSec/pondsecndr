"""Command line interface for PondSec NDR."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
from typing import Any

from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.config import ensure_directories, load_config
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import default_detectors
from pondsec_ndr.diagnostics import diagnostics as diagnostics_payload
from pondsec_ndr.diagnostics import self_test, service_status
from pondsec_ndr.features.aggregator import aggregate_features
from pondsec_ndr.models.manager import ModelError, download_model_artifacts, model_inventory
from pondsec_ndr.response.engine import ResponseDenied, propose_block_for_incident, validate_ip_or_network
from pondsec_ndr.service import PondSecService
from pondsec_ndr.storage.database import EventStore


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [item for item in argv if item != "--json"]
    parser = argparse.ArgumentParser(prog="pondsec-ndrctl")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("health")

    diagnostics = sub.add_parser("diagnostics")
    diagnostics_sub = diagnostics.add_subparsers(dest="diagnostics_command")
    diagnostics_sub.add_parser("self-test")

    dashboard = sub.add_parser("dashboard")
    dashboard_sub = dashboard.add_subparsers(dest="dashboard_command", required=True)
    dashboard_sub.add_parser("summary")
    dashboard_sub.add_parser("timeline")

    for name in ("detections", "hosts", "policies", "logs"):
        section = sub.add_parser(name)
        section_sub = section.add_subparsers(dest="section_command", required=True)
        section_sub.add_parser("list")

    incidents = sub.add_parser("incidents")
    incidents_sub = incidents.add_subparsers(dest="section_command", required=True)
    incidents_sub.add_parser("list")
    close_incident = incidents_sub.add_parser("close")
    close_incident.add_argument("incident_id")
    reopen_incident = incidents_sub.add_parser("reopen")
    reopen_incident.add_argument("incident_id")
    false_positive = incidents_sub.add_parser("false-positive")
    false_positive.add_argument("incident_id")

    allowlist = sub.add_parser("allowlist")
    allowlist_sub = allowlist.add_subparsers(dest="section_command", required=True)
    allowlist_sub.add_parser("list")
    allowlist_add = allowlist_sub.add_parser("add")
    allowlist_add.add_argument("value")
    allowlist_add.add_argument("--reason", default=None)
    allowlist_add.add_argument("--expires-at", default=None)
    allowlist_delete = allowlist_sub.add_parser("delete")
    allowlist_delete.add_argument("allowlist_id")

    blocklist = sub.add_parser("blocklist")
    blocklist_sub = blocklist.add_subparsers(dest="section_command", required=True)
    blocklist_sub.add_parser("list")
    block_propose = blocklist_sub.add_parser("propose")
    block_propose.add_argument("incident_id")
    block_propose.add_argument("--duration-seconds", type=int, default=None)
    block_activate = blocklist_sub.add_parser("activate")
    block_activate.add_argument("block_id")
    block_remove = blocklist_sub.add_parser("remove")
    block_remove.add_argument("block_id")
    block_remove.add_argument("--reason", default="manual removal")
    blocklist_sub.add_parser("expire")

    interfaces = sub.add_parser("interfaces")
    interfaces_sub = interfaces.add_subparsers(dest="interfaces_command", required=True)
    interfaces_sub.add_parser("list")

    model = sub.add_parser("model")
    model_sub = model.add_subparsers(dest="model_command", required=True)
    model_sub.add_parser("list")
    verify = model_sub.add_parser("verify")
    verify.add_argument("model_id", nargs="?")
    fetch = model_sub.add_parser("fetch")
    fetch.add_argument("model_id")

    database = sub.add_parser("database")
    database_sub = database.add_subparsers(dest="database_command", required=True)
    database_sub.add_parser("check")
    database_sub.add_parser("migrate")

    config_cmd = sub.add_parser("config")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("validate")

    replay = sub.add_parser("replay")
    replay.add_argument("eve_file")
    replay.add_argument("--max-lines", type=int, default=100000)

    run = sub.add_parser("run")
    run.add_argument("--once", action="store_true")
    run.add_argument("--max-lines", type=int, default=1000)

    sub.add_parser("traffic")

    args = parser.parse_args(argv)
    args.json = as_json or args.json
    config = load_config()
    if args.command == "replay":
        result, exit_code = replay_file(Path(args.eve_file), args.max_lines), 0
        emit(result, args.json)
        return exit_code
    if args.command == "config" and args.config_command == "validate":
        errors = config.validate()
        result = {"status": "ok" if not errors else "failed", "errors": errors}
        emit(result, args.json)
        return 0 if not errors else 1
    if args.command == "model" and args.model_command in {"list", "verify"}:
        inventory = model_inventory(config.data_dir)
        if args.model_command == "verify" and args.model_id:
            inventory = [item for item in inventory if item["model_id"] == args.model_id]
        ok = all(item["status"] in {"installed", "catalog"} for item in inventory)
        result = {"items": inventory} if args.model_command == "list" else {"status": "ok" if ok else "failed", "items": inventory}
        emit(result, args.json)
        return 0 if ok else 1
    ensure_directories(config)
    store = EventStore(config.data_dir / "pondsec-ndr.db")
    store.migrate()

    try:
        result, exit_code = dispatch(args, config, store)
    except ModelError as exc:
        result, exit_code = {"status": "error", "message": str(exc)}, 2
    except ResponseDenied as exc:
        result, exit_code = {"status": "denied", "message": str(exc)}, 3
    emit(result, args.json)
    return exit_code


def dispatch(args: argparse.Namespace, config: Any, store: EventStore) -> tuple[dict[str, Any], int]:
    command = args.command
    if command in {"status", "health"}:
        return service_status(config, store), 0
    if command == "diagnostics":
        if args.diagnostics_command == "self-test":
            payload = self_test(config, store)
            return payload, 0 if payload["status"] == "ok" else 1
        return diagnostics_payload(config, store), 0
    if command == "dashboard":
        payload = store.dashboard_summary() if args.dashboard_command == "summary" else store.dashboard_timeline()
        payload["metrics"] = payload.get("metrics", {})
        payload["metrics"].update({
            "service_status": store.get_health()["status"],
            "operating_mode": config.mode,
            "interfaces": config.interfaces.monitored,
            "active_model_version": _active_model(config),
            "queue_utilization": 0,
            "last_collector_errors": store.get_health().get("detail", {}).get("last_collector_errors", []),
            "last_response_errors": store.get_health().get("detail", {}).get("last_response_errors", []),
        })
        return payload, 0
    if command == "detections":
        return {"items": _decode_rows(store.list_rows("detections"))}, 0
    if command == "incidents":
        if args.section_command == "list":
            return {"items": _decode_rows(store.list_rows("incidents"))}, 0
        status_map = {"close": "closed", "reopen": "open", "false-positive": "false_positive"}
        changed = store.update_incident_status(args.incident_id, status_map[args.section_command], actor="cli")
        return {"status": "ok" if changed else "not_found", "incident_id": args.incident_id}, 0 if changed else 1
    if command == "hosts":
        return {"items": _decode_rows(store.list_rows("hosts"))}, 0
    if command == "allowlist":
        if args.section_command == "list":
            return {"items": _decode_rows(store.list_rows("allowlist_entries"))}, 0
        if args.section_command == "add":
            value = validate_ip_or_network(args.value)
            return {"status": "ok", "item": store.add_allowlist_entry(value, args.reason, args.expires_at, actor="cli")}, 0
        if args.section_command == "delete":
            changed = store.remove_allowlist_entry(args.allowlist_id, actor="cli")
            return {"status": "ok" if changed else "not_found", "allowlist_id": args.allowlist_id}, 0 if changed else 1
    if command == "blocklist":
        if args.section_command == "list":
            return {"items": _decode_rows(store.list_rows("block_entries"))}, 0
        if args.section_command == "propose":
            proposal = propose_block_for_incident(store, config, args.incident_id, actor="cli", duration_seconds=args.duration_seconds)
            return {"status": "ok", "item": proposal, "pf_side_effects": "none"}, 0
        if args.section_command == "activate":
            changed = store.update_block_status(args.block_id, "active", actor="cli")
            return {"status": "ok" if changed else "not_found", "block_id": args.block_id, "pf_side_effects": "none"}, 0 if changed else 1
        if args.section_command == "remove":
            changed = store.update_block_status(args.block_id, "removed", args.reason, actor="cli")
            return {"status": "ok" if changed else "not_found", "block_id": args.block_id, "pf_side_effects": "none"}, 0 if changed else 1
        if args.section_command == "expire":
            expired = store.expire_block_entries(actor="cli")
            return {"status": "ok", "expired": expired, "pf_side_effects": "none"}, 0
    if command == "policies":
        return {"items": _decode_rows(store.list_rows("policies"))}, 0
    if command == "logs":
        return logs_list(config), 0
    if command == "interfaces":
        return interfaces_list(config), 0
    if command == "model":
        if args.model_command == "fetch":
            return {"status": "ok", "manifest": download_model_artifacts(config.data_dir, args.model_id)}, 0
    if command == "database":
        if args.database_command == "migrate":
            store.migrate()
            return {"status": "ok", "schema_version": 1}, 0
        payload = store.check()
        return payload, 0 if payload["status"] == "ok" else 1
    if command == "run":
        service = PondSecService(config)
        if args.once:
            return service.run_once(max_lines=args.max_lines), 0
        service.run_forever()
        return {"status": "stopped"}, 0
    if command == "traffic":
        return {"items": [], "message": "Traffic analytics requires ingested events; no synthetic data is generated."}, 0
    raise ValueError(f"unsupported command: {command}")


def replay_file(eve_file: Path, max_lines: int) -> dict[str, Any]:
    offset = eve_file.parent / f".{eve_file.name}.pondsec-replay-offset"
    offset.unlink(missing_ok=True)
    collector = EveCollector(eve_file, offset, queue_limit=max_lines)
    events, stats = collector.read_once(max_lines=max_lines)
    features = aggregate_features(events)
    detections = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections)
    offset.unlink(missing_ok=True)
    return {
        "status": "ok",
        "events": len(events),
        "collector": asdict(stats),
        "detections": detections,
        "incidents": incidents,
        "response_mode": "simulation_only",
    }


def interfaces_list(config: Any) -> dict[str, Any]:
    interfaces = []
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        interfaces = sorted(path.name for path in net_dir.iterdir())
    elif Path("/sbin/ifconfig").exists():
        import subprocess
        result = subprocess.run(["/sbin/ifconfig", "-l"], capture_output=True, text=True, check=False, timeout=5)
        interfaces = result.stdout.split()
    return {
        "items": [{"name": name, "configured": name in config.interfaces.monitored} for name in interfaces],
        "configured": config.interfaces.monitored,
    }


def logs_list(config: Any) -> dict[str, Any]:
    path = config.log_dir / "pondsec-ndr.log"
    if not path.exists():
        return {"items": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-100:]
    records = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"message": line})
    return {"items": records}


def _active_model(config: Any) -> str | None:
    for model in model_inventory(config.data_dir):
        if model.get("active"):
            return model["model_id"]
    return None


def _decode_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decoded = []
    for row in rows:
        item = dict(row)
        for key in list(item):
            if key.endswith("_json") and isinstance(item[key], str):
                try:
                    item[key[:-5]] = json.loads(item[key])
                except json.JSONDecodeError:
                    item[key[:-5]] = item[key]
                del item[key]
        decoded.append(item)
    return decoded


def emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return
    status = result.get("status")
    if status:
        print(status)
    else:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    sys.exit(main())
