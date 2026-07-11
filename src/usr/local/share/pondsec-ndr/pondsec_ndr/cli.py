"""Command line interface for PondSec NDR."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import grp
import pwd
import shutil
import subprocess
import sys
import time
from typing import Any

from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.config import ensure_directories, load_config
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import default_detectors
from pondsec_ndr.diagnostics import diagnostic_archive
from pondsec_ndr.diagnostics import diagnostics as diagnostics_payload
from pondsec_ndr.diagnostics import self_test, service_status
from pondsec_ndr.features.aggregator import aggregate_features
from pondsec_ndr.models.manager import ModelError, download_model_artifacts, model_inventory, write_runtime_selftest
from pondsec_ndr.models.runtime import MODEL_ID, SYNTHETIC_AI_VALIDATION_VECTOR, ModelRuntimeUnavailable, SaidimnIdsCnnRuntime
from pondsec_ndr.privacy import export_privacy_bundle, privacy_status, purge_telemetry_before
from pondsec_ndr.intel.cve import CveEnrichmentOptions, enrich_case_cves
from pondsec_ndr.response.engine import ResponseDenied, activate_block, propose_block_for_incident, propose_manual_block, release_incident_response, remove_block, validate_ip_or_network
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.sensor import harden_sensor, sensor_status
from pondsec_ndr.service import PondSecService
from pondsec_ndr.storage.database import EventStore, SCHEMA_VERSION


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
    diagnostics_archive = diagnostics_sub.add_parser("archive")
    diagnostics_archive.add_argument("--output", required=True)

    privacy = sub.add_parser("privacy")
    privacy_sub = privacy.add_subparsers(dest="privacy_command", required=True)
    privacy_sub.add_parser("status")
    privacy_export = privacy_sub.add_parser("export")
    privacy_export.add_argument("--output", required=True)
    privacy_export.add_argument("--no-anonymize", action="store_true")
    privacy_export.add_argument("--include-events", action="store_true")
    privacy_purge = privacy_sub.add_parser("purge")
    privacy_purge.add_argument("--older-than-days", type=int, required=True)

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
    get_incident = incidents_sub.add_parser("get")
    get_incident.add_argument("incident_id")
    close_incident = incidents_sub.add_parser("close")
    close_incident.add_argument("incident_id")
    reopen_incident = incidents_sub.add_parser("reopen")
    reopen_incident.add_argument("incident_id")
    archive_incident = incidents_sub.add_parser("archive")
    archive_incident.add_argument("incident_id")
    delete_incident = incidents_sub.add_parser("delete")
    delete_incident.add_argument("incident_id")
    false_positive = incidents_sub.add_parser("false-positive")
    false_positive.add_argument("incident_id")
    release_incident = incidents_sub.add_parser("release")
    release_incident.add_argument("incident_id")
    merge_incident = incidents_sub.add_parser("merge")
    merge_incident.add_argument("primary_id")
    merge_incident.add_argument("secondary_id")
    link_incident = incidents_sub.add_parser("link")
    link_incident.add_argument("primary_id")
    link_incident.add_argument("related_id")
    keep_separate = incidents_sub.add_parser("keep-separate")
    keep_separate.add_argument("primary_id")
    keep_separate.add_argument("related_id")

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
    block_add = blocklist_sub.add_parser("add")
    block_add.add_argument("value")
    block_add.add_argument("--reason", default=None)
    block_add.add_argument("--duration-seconds", type=int, default=None)
    block_propose = blocklist_sub.add_parser("propose")
    block_propose.add_argument("incident_id")
    block_propose.add_argument("--duration-seconds", type=int, default=None)
    block_activate = blocklist_sub.add_parser("activate")
    block_activate.add_argument("block_id")
    block_remove = blocklist_sub.add_parser("remove")
    block_remove.add_argument("block_id")
    block_remove.add_argument("--reason", default="manual removal")
    blocklist_sub.add_parser("expire")

    pf = sub.add_parser("pf")
    pf_sub = pf.add_subparsers(dest="pf_command", required=True)
    pf_table = pf_sub.add_parser("table-op")
    pf_table.add_argument("operation", choices=("add", "delete", "test"))
    pf_table.add_argument("target")
    pf_sub.add_parser("rule-present")

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
    model_sub.add_parser("self-test")
    validate_model_flow = model_sub.add_parser("validate-flow")
    validate_model_flow.add_argument("--kind", choices=("attack", "benign"), default="attack")
    validate_model_flow.add_argument("--source-ip", default=None)
    validate_model_flow.add_argument("--device", default="igb0_vlan10")

    database = sub.add_parser("database")
    database_sub = database.add_subparsers(dest="database_command", required=True)
    database_sub.add_parser("check")
    database_sub.add_parser("migrate")

    maintenance = sub.add_parser("maintenance")
    maintenance_sub = maintenance.add_subparsers(dest="maintenance_command", required=True)
    reset_runtime = maintenance_sub.add_parser("reset-runtime")
    reset_runtime.add_argument("--restart-service", action="store_true")
    reset_runtime.add_argument("--flush-pf", action="store_true")

    config_cmd = sub.add_parser("config")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("validate")

    sensor = sub.add_parser("sensor")
    sensor_sub = sensor.add_subparsers(dest="sensor_command", required=True)
    sensor_sub.add_parser("status")
    sensor_harden = sensor_sub.add_parser("harden")
    sensor_harden.add_argument("--restart-suricata", action="store_true")

    protection = sub.add_parser("protection")
    protection_sub = protection.add_subparsers(dest="protection_command", required=True)
    validate_protection = protection_sub.add_parser("validate")
    validate_protection.add_argument("--source-ip", default="203.0.113.250")
    validate_protection.add_argument("--destination-ip", default="192.168.30.3")
    validate_protection.add_argument("--duration-seconds", type=int, default=600)
    validate_protection.add_argument("--remove-after", action="store_true")
    validate_suite = protection_sub.add_parser("validate-suite")
    validate_suite.add_argument("--duration-seconds", type=int, default=900)
    validate_suite.add_argument("--remove-after", action="store_true")

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
        result, exit_code = replay_file(Path(args.eve_file), args.max_lines, config), 0
        emit(result, args.json)
        return exit_code
    if args.command == "config" and args.config_command == "validate":
        errors = config.validate()
        result = {"status": "ok" if not errors else "failed", "errors": errors}
        emit(result, args.json)
        return 0 if not errors else 1
    if args.command == "model" and args.model_command in {"list", "verify"}:
        inventory = model_inventory(config.data_dir)
        if args.model_command == "list":
            emit({"items": inventory}, args.json)
            return 0
        if args.model_command == "verify" and args.model_id:
            inventory = [item for item in inventory if item["model_id"] == args.model_id]
        ok = all(item["status"] in {"active", "installed", "catalog"} for item in inventory)
        result = {"status": "ok" if ok else "failed", "items": inventory}
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
        if args.diagnostics_command == "archive":
            payload = diagnostic_archive(config, store, Path(args.output))
            return payload, 0 if payload["status"] == "ok" else 1
        return diagnostics_payload(config, store), 0
    if command == "privacy":
        if args.privacy_command == "status":
            return privacy_status(config), 0
        if args.privacy_command == "export":
            payload = export_privacy_bundle(
                config,
                store,
                Path(args.output),
                anonymize=not args.no_anonymize,
                include_events=args.include_events,
            )
            return payload, 0
        if args.privacy_command == "purge":
            payload = purge_telemetry_before(store, args.older_than_days)
            return payload, 0
    if command == "dashboard":
        payload = store.dashboard_summary() if args.dashboard_command == "summary" else store.dashboard_timeline()
        payload["metrics"] = payload.get("metrics", {})
        payload["metrics"].update({
            "service_status": store.get_health()["status"],
            "operating_mode": config.mode,
            "response_mode": config.response.mode,
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
            return {"items": _decode_rows(store.list_rows("incidents")), "summary": store.incident_status_summary()}, 0
        if args.section_command == "get":
            incident = store.get_incident(args.incident_id)
            if incident is None:
                return {"status": "not_found", "incident_id": args.incident_id}, 1
            response_block = store.existing_response_block(incident.get("incident_id"), incident.get("source_ip"))
            if response_block:
                incident["response_state"] = response_block
            incident["response_blocks"] = store.active_response_blocks_for_incident(incident.get("incident_id"))
            return {"status": "ok", "item": incident, "analysis": _incident_analysis(incident, response_block, store=store, config=config)}, 0
        if args.section_command == "release":
            payload = release_incident_response(store, args.incident_id, actor="cli")
            return payload, 0 if payload["status"] in {"ok", "not_found"} else 1
        if args.section_command == "merge":
            payload = store.merge_incidents(args.primary_id, args.secondary_id, actor="cli")
            return payload, 0 if payload["status"] == "ok" else 1
        if args.section_command == "link":
            store.audit_case_action("link", args.primary_id, {"related_incident_id": args.related_id}, actor="cli")
            return {"status": "ok", "primary_id": args.primary_id, "related_incident_id": args.related_id}, 0
        if args.section_command == "keep-separate":
            store.audit_case_action("keep_separate", args.primary_id, {"related_incident_id": args.related_id}, actor="cli")
            return {"status": "ok", "primary_id": args.primary_id, "related_incident_id": args.related_id}, 0
        if args.section_command == "delete":
            payload = store.delete_incident(args.incident_id, actor="cli")
            return payload, 0 if payload["status"] == "ok" else 1
        status_map = {"close": "closed", "reopen": "open", "archive": "archived", "false-positive": "false_positive"}
        changed = store.update_incident_status(args.incident_id, status_map[args.section_command], actor="cli")
        return {"status": "ok" if changed else "not_found", "incident_id": args.incident_id}, 0 if changed else 1
    if command == "hosts":
        return {"items": _decode_rows(store.list_rows("hosts"))}, 0
    if command == "allowlist":
        if args.section_command == "list":
            return {"items": _decode_rows(store.list_rows("allowlist_entries"))}, 0
        if args.section_command == "add":
            value = validate_ip_or_network(args.value)
            return {"status": "ok", "item": store.add_allowlist_entry(value, args.reason or None, args.expires_at or None, actor="cli")}, 0
        if args.section_command == "delete":
            changed = store.remove_allowlist_entry(args.allowlist_id, actor="cli")
            return {"status": "ok" if changed else "not_found", "allowlist_id": args.allowlist_id}, 0 if changed else 1
    if command == "blocklist":
        if args.section_command == "list":
            return _decode_blocklist_view(store.blocklist_view()), 0
        if args.section_command == "add":
            proposal = propose_manual_block(store, config, args.value, args.reason or None, actor="cli", duration_seconds=args.duration_seconds)
            return {"status": "ok", "item": proposal, "pf_side_effects": "none_until_activated"}, 0
        if args.section_command == "propose":
            proposal = propose_block_for_incident(store, config, args.incident_id, actor="cli", duration_seconds=args.duration_seconds)
            return {"status": "ok", "item": proposal, "pf_side_effects": "none_until_activated"}, 0
        if args.section_command == "activate":
            payload = activate_block(store, config, args.block_id, actor="cli")
            return payload, 0 if payload["status"] == "ok" else 1
        if args.section_command == "remove":
            payload = remove_block(store, args.block_id, args.reason, actor="cli")
            return payload, 0 if payload["status"] == "ok" else 1
        if args.section_command == "expire":
            expired_sources = store.expired_active_block_sources()
            expired = store.expire_block_entries(actor="cli")
            enforcer = PFTableEnforcer()
            removed = []
            for source_ip in expired_sources:
                if source_ip not in store.active_block_sources():
                    removed.append(enforcer.delete(source_ip).as_dict())
            return {"status": "ok", "expired": expired, "pf_removed": removed}, 0
    if command == "pf":
        enforcer = PFTableEnforcer(allow_configctl=False)
        if args.pf_command == "rule-present":
            present = enforcer.rule_present()
            return {"status": "ok" if present else "failed", "rule_present": present, "table": enforcer.table}, 0 if present else 1
        target = validate_ip_or_network(args.target)
        if args.operation == "add":
            result = enforcer.add(target)
        elif args.operation == "delete":
            result = enforcer.delete(target)
        else:
            result = enforcer.test(target)
        return {"status": "ok" if result.ok else "failed", "pf_result": result.as_dict()}, 0 if result.ok else 1
    if command == "policies":
        return {"items": _decode_rows(store.list_rows("policies"))}, 0
    if command == "logs":
        return logs_list(config), 0
    if command == "interfaces":
        return interfaces_list(config), 0
    if command == "model":
        if args.model_command == "fetch":
            return {"status": "ok", "manifest": download_model_artifacts(config.data_dir, args.model_id)}, 0
        if args.model_command == "self-test":
            payload = run_model_self_test(config)
            return payload, 0 if payload["status"] == "ok" else 1
        if args.model_command == "validate-flow":
            payload = validate_model_flow(store, config, args.kind, args.source_ip, args.device)
            return payload, 0 if payload["status"] in {"ok", "benign"} else 1
    if command == "database":
        if args.database_command == "migrate":
            store.migrate()
            return {"status": "ok", "schema_version": SCHEMA_VERSION}, 0
        payload = store.check()
        return payload, 0 if payload["status"] == "ok" else 1
    if command == "maintenance" and args.maintenance_command == "reset-runtime":
        payload = reset_runtime_state(store, config, restart_service=args.restart_service, flush_pf=args.flush_pf)
        return payload, 0 if payload["status"] == "ok" else 1
    if command == "sensor":
        if args.sensor_command == "status":
            payload = sensor_status(config)
            return payload, 0 if payload["status"] == "ok" else 1
        if args.sensor_command == "harden":
            payload = harden_sensor(config, restart_suricata=args.restart_suricata)
            return payload, 0 if payload["status"] == "ok" else 1
    if command == "protection" and args.protection_command == "validate":
        payload = validate_protection_path(store, config, args.source_ip, args.destination_ip, args.duration_seconds, args.remove_after)
        return payload, 0 if payload["status"] == "ok" else 1
    if command == "protection" and args.protection_command == "validate-suite":
        payload = validate_protection_suite(store, config, args.duration_seconds, args.remove_after)
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


def reset_runtime_state(store: EventStore, config: Any, restart_service: bool = False, flush_pf: bool = False) -> dict[str, Any]:
    service_stop = _run_service_action("onestop") if restart_service else None
    pf_flush = PFTableEnforcer().flush().as_dict() if flush_pf else None
    reset = store.reset_runtime_state(actor="maintenance-reset")
    removed_paths = []
    for path in [
        config.data_dir / "learning_started_at",
        config.data_dir / "collector_offsets",
        config.data_dir / "eve.offset.json",
        config.data_dir / "filterlog.offset.json",
    ]:
        try:
            if path.is_dir():
                shutil.rmtree(path)
                removed_paths.append(str(path))
            elif path.exists():
                path.unlink()
                removed_paths.append(str(path))
        except OSError as exc:
            return {"status": "failed", "message": f"cannot remove runtime path {path}: {exc}", "reset": reset}
    seeded_offsets = _seed_collector_offsets_at_end(config)
    service_start = _run_service_action("onestart") if restart_service else None
    return {
        "status": "ok",
        "reset": reset,
        "pf_flush": pf_flush,
        "removed_paths": removed_paths,
        "seeded_offsets": seeded_offsets,
        "service_stop": service_stop,
        "service_start": service_start,
        "learning_phase": "restarted_on_next_service_start",
        "kept": ["configuration", "allowlist", "policies", "models"],
    }


def _seed_collector_offsets_at_end(config: Any) -> list[dict[str, Any]]:
    offset_dir = config.data_dir / "collector_offsets"
    seeded = []
    sources = [
        ("suricata_eve", Path(config.suricata_eve_path), offset_dir / "suricata_eve.json"),
        ("opnsense_filterlog", Path("/var/log/filter/filter.log"), offset_dir / "opnsense_filterlog.json"),
    ]
    offset_dir.mkdir(parents=True, exist_ok=True)
    for provider, source_path, offset_path in sources:
        try:
            stat = source_path.stat()
        except OSError as exc:
            seeded.append({"provider": provider, "status": "skipped", "path": str(source_path), "reason": str(exc)})
            continue
        payload = {"inode": int(stat.st_ino), "offset": int(stat.st_size)}
        try:
            offset_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
            _chown_service_path(offset_dir)
            _chown_service_path(offset_path)
        except OSError as exc:
            seeded.append({"provider": provider, "status": "failed", "path": str(offset_path), "reason": str(exc)})
            continue
        seeded.append({"provider": provider, "status": "ok", "path": str(offset_path), "offset": payload["offset"]})
    return seeded


def _chown_service_path(path: Path) -> None:
    if os.geteuid() != 0:
        return
    try:
        user = pwd.getpwnam("pondsecndr")
        group = grp.getgrnam("pondsecndr")
    except KeyError:
        return
    try:
        os.chown(path, user.pw_uid, group.gr_gid)
    except OSError:
        return


def _run_service_action(action: str) -> dict[str, Any]:
    command = ["/usr/local/etc/rc.d/pondsec_ndr", action]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    except OSError as exc:
        return {"status": "failed", "command": command, "message": str(exc)}
    return {
        "status": "ok" if result.returncode == 0 else "failed",
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def replay_file(eve_file: Path, max_lines: int, config: Any) -> dict[str, Any]:
    offset = eve_file.parent / f".{eve_file.name}.pondsec-replay-offset"
    offset.unlink(missing_ok=True)
    collector = EveCollector(eve_file, offset, queue_limit=max_lines)
    events, stats = collector.read_once(max_lines=max_lines)
    features = aggregate_features(events)
    detections = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections, window_seconds=config.detection.correlation_window_minutes * 60)
    offset.unlink(missing_ok=True)
    return {
        "status": "ok",
        "events": len(events),
        "collector": asdict(stats),
        "detections": detections,
        "incidents": incidents,
        "response_mode": "simulation_only",
    }


def validate_protection_path(
    store: EventStore,
    config: Any,
    source_ip: str,
    destination_ip: str,
    duration_seconds: int,
    remove_after: bool,
) -> dict[str, Any]:
    source_ip = validate_ip_or_network(source_ip)
    destination_ip = validate_ip_or_network(destination_ip)
    if "/" in source_ip or "/" in destination_ip:
        raise ResponseDenied("protection validation requires host IP addresses, not networks")
    events = [
        _validation_flow_event(source_ip, destination_ip, 20 + index, index)
        for index in range(18)
    ]
    features = aggregate_features(events)
    detections = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections, window_seconds=config.detection.correlation_window_minutes * 60)
    for incident in incidents:
        incident["title"] = "[PondSec validation] " + incident["title"]
        incident["evidence"]["validation"] = True
    inserted_events = store.insert_events(events)
    store.insert_features(features)
    inserted_detections = store.insert_detections(detections)
    inserted_incidents = store.insert_incidents(incidents)
    if not incidents:
        return {
            "status": "failed",
            "reason": "synthetic suspicious behavior did not produce an incident",
            "inserted_events": inserted_events,
            "inserted_detections": inserted_detections,
            "inserted_incidents": inserted_incidents,
        }
    incident = max(incidents, key=lambda item: item["risk_score"])
    original_minimum_risk = config.response.minimum_risk_score
    original_minimum_confidence = config.response.minimum_confidence
    config.response.minimum_risk_score = min(original_minimum_risk, int(incident["risk_score"]))
    config.response.minimum_confidence = min(original_minimum_confidence, int(float(incident["confidence"]) * 100))
    proposal = propose_block_for_incident(store, config, incident["incident_id"], actor="protection-validation", duration_seconds=duration_seconds)
    activation = activate_block(store, config, proposal["block_id"], actor="protection-validation")
    active_block = store.get_block_entry(proposal["block_id"]) or proposal
    removal = None
    if remove_after:
        removal = remove_block(store, proposal["block_id"], "protection validation cleanup", actor="protection-validation")
    return {
        "status": "ok" if activation["status"] == "ok" else "failed",
        "validated_behavior": "horizontal/vertical port scan",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "inserted_events": inserted_events,
        "inserted_detections": inserted_detections,
        "inserted_incidents": inserted_incidents,
        "detectors": sorted({item["detector_id"] for item in detections}),
        "incident": {
            "incident_id": incident["incident_id"],
            "risk_score": incident["risk_score"],
            "confidence": incident["confidence"],
            "category": incident["category"],
        },
        "block": active_block,
        "activation": activation,
        "removal": removal,
    }


def validate_protection_suite(
    store: EventStore,
    config: Any,
    duration_seconds: int,
    remove_after: bool,
) -> dict[str, Any]:
    scenarios = _validation_scenarios()
    results = []
    for scenario in scenarios:
        result = _run_validation_scenario(store, config, scenario, duration_seconds, remove_after)
        results.append(result)
    model = next((item for item in model_inventory(config.data_dir) if item.get("preferred")), None)
    required = {item["scenario"] for item in scenarios}
    passed = {item["scenario"] for item in results if item["status"] == "ok"}
    return {
        "status": "ok" if required == passed else "failed",
        "mode": config.mode,
        "automatic_blocking": config.response.automatic_blocking,
        "response_thresholds": {
            "minimum_risk_score": config.response.minimum_risk_score,
            "minimum_confidence": config.response.minimum_confidence,
            "isolate_internal": config.response.isolate_internal,
            "block_external": config.response.block_external,
        },
        "interfaces": {
            "monitored": config.interfaces.monitored,
            "monitored_devices": config.interfaces.monitored_devices,
            "wan": config.interfaces.wan,
            "wan_devices": config.interfaces.wan_devices,
            "internal": config.interfaces.internal,
            "internal_devices": config.interfaces.internal_devices,
            "management": config.interfaces.management,
            "management_devices": config.interfaces.management_devices,
            "protected_networks": config.interfaces.excluded_networks,
        },
        "ml_model": {
            "active_model_version": _active_model(config),
            "preferred_model": model["model_id"] if model else None,
            "preferred_model_status": model["status"] if model else None,
            "host_baseline_anomaly": "active" if config.detection.machine_learning else "disabled",
            "runtime_note": "Host-baseline anomaly detection is active in-process; external PyTorch models require a safe unprivileged worker.",
        },
        "coverage": sorted(passed),
        "results": results,
    }


def run_model_self_test(config: Any) -> dict[str, Any]:
    try:
        runtime = SaidimnIdsCnnRuntime()
        payload = runtime.self_test()
    except ModelRuntimeUnavailable as exc:
        payload = {
            "status": "failed",
            "model_id": MODEL_ID,
            "error": str(exc),
            "synthetic_ai_validation_vector": True,
        }
    write_runtime_selftest(config.data_dir, payload, MODEL_ID)
    return payload


def validate_model_flow(
    store: EventStore,
    config: Any,
    kind: str,
    source_ip: str | None,
    device: str,
) -> dict[str, Any]:
    attack = kind == "attack"
    source = source_ip or ("192.168.10.243" if attack else "192.168.10.244")
    destination = "203.0.113.77" if attack else "198.51.100.244"
    events = [_validation_flow_event_at(
        _validation_timestamp(0),
        source,
        destination,
        443,
        device,
        0,
        bytes_out=18000 if attack else 1200,
        bytes_in=1200 if attack else 1600,
        reason="finished",
    )]
    features = store.score_features_against_baselines(
        aggregate_features(events),
        minimum_observations=config.detection.minimum_observations,
    )
    if attack:
        for feature in features:
            feature["cicids_vector"] = _pretrained_ai_validation_vector()

    runtime = SaidimnIdsCnnRuntime()
    started = time.perf_counter()
    model_scores = runtime.score_features(features)
    inference_duration_ms = round((time.perf_counter() - started) * 1000, 3)

    pf = PFTableEnforcer()
    pf_before = pf.test(source).as_dict()
    active_before = source in store.active_block_sources()
    detections = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections, window_seconds=config.detection.correlation_window_minutes * 60)
    for incident in incidents:
        incident["title"] = f"[PondSec AI validation:{kind}] {incident['title']}"
        incident["evidence"]["validation"] = {
            "kind": kind,
            "synthetic_ai_validation_vector": attack,
            "production_path": "suricata_event_normalize_aggregate_model_detect_correlate_store",
        }
    inserted_events = store.insert_events(events)
    store.insert_features(features)
    inserted_detections = store.insert_detections(detections)
    inserted_incidents = store.insert_incidents(incidents)
    pf_after = pf.test(source).as_dict()
    active_after = source in store.active_block_sources()
    ai_detections = [item for item in detections if item["detector_id"] == "pondsec.pretrained_ids_model"]
    return {
        "status": "ok" if (attack and ai_detections and incidents) or (not attack and not ai_detections) else "failed",
        "kind": kind,
        "mode": config.mode,
        "source_ip": source,
        "destination_ip": destination,
        "device": device,
        "synthetic_ai_validation_vector": attack,
        "live_traffic_claim": False,
        "model_scores": model_scores,
        "inference_duration_ms": inference_duration_ms,
        "detections": ai_detections,
        "incidents": incidents,
        "inserted_events": inserted_events,
        "inserted_detections": inserted_detections,
        "inserted_incidents": inserted_incidents,
        "pf_response_attempted": False,
        "pf_source_blocked_before": bool(pf_before["ok"] or active_before),
        "pf_source_blocked_after": bool(pf_after["ok"] or active_after),
        "monitor_mode_no_block": config.mode == "monitor" and not (pf_after["ok"] or active_after),
        "pf_before": pf_before,
        "pf_after": pf_after,
    }


def _run_validation_scenario(
    store: EventStore,
    config: Any,
    scenario: dict[str, Any],
    duration_seconds: int,
    remove_after: bool,
) -> dict[str, Any]:
    if scenario["scenario"] == "unknown_zero_day_baseline_anomaly":
        _seed_validation_baseline(store, scenario, config.detection.minimum_observations)
    events = scenario["events"]()
    features = store.score_features_against_baselines(
        aggregate_features(events),
        minimum_observations=config.detection.minimum_observations,
    )
    for feature in features:
        feature.update(scenario.get("feature_overrides", {}).get(feature["source_ip"], {}))
    detections = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections, window_seconds=config.detection.correlation_window_minutes * 60)
    for incident in incidents:
        incident["title"] = f"[PondSec validation:{scenario['scenario']}] {incident['title']}"
        incident["evidence"]["validation"] = {
            "scenario": scenario["scenario"],
            "behavior": scenario["behavior"],
            "interface": scenario["interface"],
            "device": scenario["device"],
        }
    inserted_events = store.insert_events(events)
    store.insert_features(features)
    inserted_detections = store.insert_detections(detections)
    inserted_incidents = store.insert_incidents(incidents)
    matched_detections = [item for item in detections if item["detector_id"] in scenario["expected_detectors"]]
    if not matched_detections or not incidents:
        return {
            "status": "failed",
            "scenario": scenario["scenario"],
            "behavior": scenario["behavior"],
            "interface": scenario["interface"],
            "device": scenario["device"],
            "reason": "expected detection or incident was not produced",
            "detectors": sorted({item["detector_id"] for item in detections}),
            "inserted_events": inserted_events,
            "inserted_detections": inserted_detections,
            "inserted_incidents": inserted_incidents,
        }
    incident = max(incidents, key=lambda item: item["risk_score"])
    action = _auto_prevent_incident(store, config, incident["incident_id"], duration_seconds)
    removal = None
    if remove_after and action.get("block_id"):
        removal = remove_block(store, action["block_id"], "protection validation suite cleanup", actor="protection-validation")
    return {
        "status": "ok" if action.get("status") == "ok" else "failed",
        "scenario": scenario["scenario"],
        "behavior": scenario["behavior"],
        "interface": scenario["interface"],
        "device": scenario["device"],
        "source_ip": scenario["source_ip"],
        "destination_ip": scenario["destination_ip"],
        "expected_detectors": scenario["expected_detectors"],
        "detectors": sorted({item["detector_id"] for item in detections}),
        "incident": {
            "incident_id": incident["incident_id"],
            "risk_score": incident["risk_score"],
            "confidence": incident["confidence"],
            "category": incident["category"],
        },
        "auto_prevent": action,
        "removal": removal,
        "inserted_events": inserted_events,
        "inserted_detections": inserted_detections,
        "inserted_incidents": inserted_incidents,
    }


def _auto_prevent_incident(store: EventStore, config: Any, incident_id: str, duration_seconds: int) -> dict[str, Any]:
    if not config.response.automatic_blocking or config.mode != "prevent":
        raise ResponseDenied("automatic prevent mode is not enabled")
    proposal = propose_block_for_incident(
        store,
        config,
        incident_id,
        actor="protection-validation",
        duration_seconds=duration_seconds,
        automatic=True,
    )
    activation = activate_block(store, config, proposal["block_id"], actor="protection-validation")
    return {
        "status": activation["status"],
        "block_id": proposal["block_id"],
        "source_ip": proposal["source_ip"],
        "automatic": bool(proposal.get("automatic")),
        "pf_table": activation["pf_table"],
        "pf_rule_present": activation["pf_rule_present"],
        "pf_add": activation["pf_add"],
        "pf_verify": activation["pf_verify"],
    }


def _seed_validation_baseline(store: EventStore, scenario: dict[str, Any], minimum_observations: int) -> None:
    normal_events = [
        _validation_flow_event_at(
            _validation_timestamp(-3600 + index * 60),
            scenario["source_ip"],
            "192.168.20.10",
            443,
            scenario["device"],
            index,
            bytes_out=2400,
            bytes_in=1600,
            reason="finished",
        )
        for index in range(max(1, minimum_observations))
    ]
    normal_features = aggregate_features(normal_events)
    for _ in range(max(1, minimum_observations)):
        store.update_host_baselines(normal_features)


def _validation_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario": "pretrained_ai_model_inference_vlan10",
            "behavior": "Verified pretrained CICIDS2017 CNN-1D AI model classifies a full flow vector as attack",
            "interface": "opt2",
            "device": "igb0_vlan10",
            "source_ip": "192.168.10.243",
            "destination_ip": "203.0.113.77",
            "expected_detectors": ["pondsec.pretrained_ids_model"],
            "feature_overrides": {"192.168.10.243": {"cicids_vector": _pretrained_ai_validation_vector()}},
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(0), "192.168.10.243", "203.0.113.77", 443, "igb0_vlan10", 0, bytes_out=18000, bytes_in=1200, reason="finished")
            ],
        },
        {
            "scenario": "wan_attack_prevention",
            "behavior": "External reconnaissance/port scan against DMZ from WAN",
            "interface": "wan",
            "device": "pppoe0",
            "source_ip": "203.0.113.241",
            "destination_ip": "192.168.30.3",
            "expected_detectors": ["pondsec.portscan", "pondsec.vertical_scan"],
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(index), "203.0.113.241", "192.168.30.3", 20 + index, "pppoe0", index)
                for index in range(18)
            ],
        },
        {
            "scenario": "beaconing_vlan10",
            "behavior": "Periodic command-and-control beaconing from VLAN10",
            "interface": "opt2",
            "device": "igb0_vlan10",
            "source_ip": "192.168.10.241",
            "destination_ip": "203.0.113.44",
            "expected_detectors": ["pondsec.beaconing"],
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(index * 60), "192.168.10.241", "203.0.113.44", 443, "igb0_vlan10", index, reason="finished")
                for index in range(6)
            ],
        },
        {
            "scenario": "lateral_movement_vlan20",
            "behavior": "Internal SMB/RDP fan-out consistent with lateral movement from VLAN20",
            "interface": "opt3",
            "device": "igb0_vlan20",
            "source_ip": "192.168.20.241",
            "destination_ip": "internal",
            "expected_detectors": ["pondsec.lateral_movement"],
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(index), "192.168.20.241", f"192.168.30.{20 + index}", 445 if index % 2 else 3389, "igb0_vlan20", index, reason="finished")
                for index in range(6)
            ],
        },
        {
            "scenario": "dns_tunneling_dmz",
            "behavior": "High-entropy NXDOMAIN DNS tunneling from DMZ",
            "interface": "opt1",
            "device": "re0",
            "source_ip": "192.168.30.241",
            "destination_ip": "9.9.9.9",
            "expected_detectors": ["pondsec.dns_tunneling"],
            "events": lambda: [
                _validation_dns_event(_validation_timestamp(index), "192.168.30.241", "9.9.9.9", "re0", index)
                for index in range(12)
            ],
        },
        {
            "scenario": "data_exfiltration_vlan10",
            "behavior": "Large asymmetric upload consistent with data exfiltration from VLAN10",
            "interface": "opt2",
            "device": "igb0_vlan10",
            "source_ip": "192.168.10.242",
            "destination_ip": "203.0.113.88",
            "expected_detectors": ["pondsec.data_exfiltration"],
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(index), "192.168.10.242", "203.0.113.88", 443, "igb0_vlan10", index, bytes_out=30_000_000, bytes_in=1000, reason="finished")
                for index in range(2)
            ],
        },
        {
            "scenario": "unknown_zero_day_baseline_anomaly",
            "behavior": "Unknown behavior anomaly against an established host baseline without a signature",
            "interface": "opt3",
            "device": "igb0_vlan20",
            "source_ip": "192.168.20.242",
            "destination_ip": "203.0.113.99",
            "expected_detectors": ["pondsec.host_baseline_anomaly"],
            "events": lambda: [
                _validation_flow_event_at(_validation_timestamp(index), "192.168.20.242", f"203.0.113.{20 + index}", 8000 + index, "igb0_vlan20", index, bytes_out=400_000, bytes_in=100, reason="finished")
                for index in range(40)
            ],
        },
    ]


def _pretrained_ai_validation_vector() -> list[float]:
    return list(SYNTHETIC_AI_VALIDATION_VECTOR)


def _validation_timestamp(offset_seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)).isoformat()


def _validation_flow_event_at(
    timestamp: str,
    source_ip: str,
    destination_ip: str,
    port: int,
    interface: str,
    index: int,
    bytes_out: int = 2000,
    bytes_in: int = 200,
    reason: str = "timeout",
) -> dict[str, Any]:
    raw = {
        "timestamp": timestamp,
        "event_type": "flow",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": 52000 + index,
        "dest_ip": destination_ip,
        "dest_port": port,
        "proto": "TCP",
        "flow": {
            "state": "closed",
            "reason": reason,
            "age": 1,
            "pkts_toserver": 3,
            "pkts_toclient": 1,
            "bytes_toserver": bytes_out,
            "bytes_toclient": bytes_in,
        },
    }
    from pondsec_ndr.normalizers.suricata import normalize_eve
    return normalize_eve(raw)


def _validation_dns_event(timestamp: str, source_ip: str, destination_ip: str, interface: str, index: int) -> dict[str, Any]:
    label = f"z9x8c7v6b5n4m3a2s1d0qwertyuiopasdfghjkl{index:02d}"
    raw = {
        "timestamp": timestamp,
        "event_type": "dns",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": 53000 + index,
        "dest_ip": destination_ip,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"rrname": f"{label}.validation.pondsec.test", "rrtype": "TXT", "rcode": "NXDOMAIN"},
    }
    from pondsec_ndr.normalizers.suricata import normalize_eve
    return normalize_eve(raw)


def _validation_flow_event(source_ip: str, destination_ip: str, port: int, index: int) -> dict[str, Any]:
    timestamp = f"2026-07-05T16:50:{index:02d}+00:00"
    raw = {
        "timestamp": timestamp,
        "event_type": "flow",
        "src_ip": source_ip,
        "src_port": 52000 + index,
        "dest_ip": destination_ip,
        "dest_port": port,
        "proto": "TCP",
        "flow": {
            "state": "closed",
            "reason": "timeout",
            "age": 1,
            "pkts_toserver": 3,
            "pkts_toclient": 1,
            "bytes_toserver": 2000,
            "bytes_toclient": 200,
        },
    }
    from pondsec_ndr.normalizers.suricata import normalize_eve
    return normalize_eve(raw)


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


ATTACK_STAGES = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
    "response",
]

STAGE_STATUS_RANK = {
    "not_seen": 0,
    "suspected": 1,
    "observed": 2,
    "confirmed": 3,
    "prevented": 4,
}

GRAPH_STATUS_RANK = {
    "inferred": 1,
    "observed": 2,
    "correlated": 3,
    "confirmed": 4,
}


def _incident_analysis(
    incident: dict[str, Any],
    response_block: dict[str, Any] | None = None,
    store: EventStore | None = None,
    config: Any | None = None,
) -> dict[str, Any]:
    evidence = incident.get("evidence") if isinstance(incident.get("evidence"), dict) else {}
    detections = evidence.get("detections", []) if isinstance(evidence, dict) else []
    if not isinstance(detections, list):
        detections = []
    entity_roles = evidence.get("entity_roles", {}) if isinstance(evidence, dict) and isinstance(evidence.get("entity_roles"), dict) else {}
    if not entity_roles:
        entity_roles = _infer_entity_roles(detections, incident)
    targets = incident.get("affected_targets") or []
    response_block = response_block or incident.get("response_state")
    response_blocks = incident.get("response_blocks") if isinstance(incident.get("response_blocks"), list) else []
    timeline = []
    admin_guidance = []
    notable_features = []
    stages = _empty_attack_stages()
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        explanation = detection.get("explainability") or (detection.get("evidence") or {}).get("explainability") or {}
        stage = _stage_for_detection(detection, incident)
        certainty = _certainty_for_detection(detection)
        timeline.append({
            "timestamp": detection.get("timestamp"),
            "title": detection.get("title"),
            "detector_id": detection.get("detector_id"),
            "category": detection.get("category"),
            "stage": stage,
            "status": certainty,
            "edge_kind": _edge_kind_for_stage(stage, detection.get("category")),
            "severity": detection.get("severity"),
            "confidence": detection.get("confidence"),
            "risk_delta": _risk_contribution(detection),
            "summary": explanation.get("why") or detection.get("description"),
            "evidence": detection.get("evidence", {}),
            "raw_events": (detection.get("evidence") or {}).get("events", []),
        })
        _promote_stage(stages, stage, certainty, detection)
        for item in explanation.get("administrator_guidance", []) if isinstance(explanation, dict) else []:
            if item not in admin_guidance:
                admin_guidance.append(item)
        for item in explanation.get("notable_features", []) if isinstance(explanation, dict) else []:
            notable_features.append(item)
    if response_block:
        _promote_stage(stages, "response", "prevented" if response_block.get("status") == "active" else "observed", {
            "detector_id": "pondsec.response",
            "title": "Response action",
            "confidence": response_block.get("confidence"),
        })
    threat_intel = _case_threat_intelligence(detections, config)
    if threat_intel.get("risk_modifier"):
        incident_risk_factors = list(incident.get("risk_factors", []))
        incident_risk_factors.append({
            "name": "cve_intel_priority",
            "value": threat_intel["risk_modifier"],
            "source": "local CVE/KEV/EPSS enrichment",
            "note": "Prioritization only; not used as sole blocking evidence.",
        })
    else:
        incident_risk_factors = incident.get("risk_factors", [])
    graph = _incident_attack_graph(incident, detections, targets, response_block, entity_roles)
    visual_timeline = _group_timeline(timeline)
    summary = _case_summary(incident, targets, admin_guidance, response_block, entity_roles, response_blocks, threat_intel)
    related_cases = _related_cases(store, incident, entity_roles) if store else []
    response_decisions = store.response_decisions_for_incident(incident.get("incident_id")) if store else []
    return {
        "case_summary": summary,
        "case_narrative": summary.get("narrative", {}),
        "entity_roles": entity_roles,
        "related_cases": related_cases,
        "response_decisions": response_decisions,
        "threat_intelligence": threat_intel,
        "host_story": {
            "source_ip": incident.get("source_ip"),
            "destination_ip": incident.get("destination_ip"),
            "entity_roles": entity_roles,
            "affected_targets": targets,
            "attack_stage": incident.get("attack_stage"),
            "category": incident.get("category"),
            "first_seen": incident.get("first_seen") or incident.get("created_at"),
            "last_seen": incident.get("last_seen") or incident.get("updated_at"),
            "event_count": incident.get("event_count"),
            "detection_count": incident.get("detection_count"),
            "suppressed_count": incident.get("suppressed_count"),
        },
        "attack_graph": graph,
        "attack_stages": [stages[name] for name in ATTACK_STAGES if stages[name]["status"] != "not_seen"],
        "timeline": sorted(timeline, key=lambda item: str(item.get("timestamp") or "")),
        "visual_timeline": visual_timeline,
        "notable_features": notable_features[:20],
        "administrator_guidance": admin_guidance[:12],
        "risk_factors": incident_risk_factors,
        "correlation": evidence.get("correlation", {}),
    }


def _empty_attack_stages() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "stage": name,
            "status": "not_seen",
            "confidence": 0,
            "detection_count": 0,
            "evidence": [],
            "certainty_note": "No evidence observed for this phase.",
        }
        for name in ATTACK_STAGES
    }


def _promote_stage(stages: dict[str, dict[str, Any]], stage: str, status: str, detection: dict[str, Any]) -> None:
    stage = stage if stage in stages else "execution"
    status = status if status in STAGE_STATUS_RANK else "suspected"
    current = stages[stage]
    if STAGE_STATUS_RANK[status] > STAGE_STATUS_RANK[current["status"]]:
        current["status"] = status
    current["confidence"] = max(float(current.get("confidence") or 0), float(detection.get("confidence") or 0))
    current["detection_count"] = int(current.get("detection_count") or 0) + 1
    current["evidence"].append({
        "detector_id": detection.get("detector_id"),
        "title": detection.get("title"),
        "timestamp": detection.get("timestamp"),
        "confidence": detection.get("confidence"),
    })
    if current["status"] == "confirmed":
        current["certainty_note"] = "Confirmed by a strong detector or explicit security action."
    elif current["status"] == "prevented":
        current["certainty_note"] = "Traffic was blocked or a response action is active; this does not prove successful compromise."
    elif current["status"] == "observed":
        current["certainty_note"] = "Observed directly in telemetry, but not marked as exploit-confirmed."
    elif current["status"] == "suspected":
        current["certainty_note"] = "Weak or inferred signal only; investigate before treating as confirmed."


def _stage_for_detection(detection: dict[str, Any], incident: dict[str, Any]) -> str:
    category = str(detection.get("category") or incident.get("category") or "").lower()
    detector_id = str(detection.get("detector_id") or "").lower()
    title = str(detection.get("title") or "").lower()
    if "lateral" in detector_id or category == "lateral_movement":
        return "lateral_movement"
    if "beacon" in detector_id or category == "command_and_control":
        return "command_and_control"
    if "exfil" in detector_id or category == "exfiltration":
        return "exfiltration"
    if "portscan" in detector_id or "scan" in title or category == "reconnaissance":
        return "reconnaissance"
    if category == "signature":
        if _signature_indicates_reconnaissance(detection):
            return "reconnaissance"
        return "initial_access"
    if category == "machine_learning":
        return "execution"
    if category == "anomaly":
        return incident.get("attack_stage") if incident.get("attack_stage") in ATTACK_STAGES else "execution"
    return incident.get("attack_stage") if incident.get("attack_stage") in ATTACK_STAGES else "execution"


def _signature_indicates_reconnaissance(detection: dict[str, Any]) -> bool:
    evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
    haystack = " ".join(
        str(value or "").lower()
        for value in (
            detection.get("detector_id"),
            detection.get("title"),
            detection.get("description"),
            evidence.get("signature"),
            evidence.get("category"),
            evidence.get("suricata_category"),
            evidence.get("metadata"),
        )
    )
    recon_terms = (
        "reputation",
        "poor reputation",
        "cins",
        "scanner",
        "internet scanner",
        "crawler",
        "bot",
        "spider",
        "masscan",
        "nmap",
        "zmap",
        "shodan",
        "censys",
        "shadowserver",
        "binaryedge",
        "stretchoid",
        "scan",
    )
    exploit_terms = (
        "exploit",
        "attempted-admin",
        "attempted-user",
        "web attack",
        "sql injection",
        "xss",
        "path traversal",
        "command injection",
        "remote code execution",
        "rce",
        "shell",
        "cve-",
    )
    if any(term in haystack for term in exploit_terms):
        return False
    return any(term in haystack for term in recon_terms)


def _edge_kind_for_stage(stage: str, category: str | None = None) -> str:
    if stage == "reconnaissance":
        return "scan"
    if stage == "initial_access":
        return "exploit_attempt"
    if stage == "lateral_movement":
        return "lateral_movement"
    if stage == "command_and_control":
        return "command_and_control"
    if stage == "exfiltration":
        return "exfiltration"
    if stage == "response":
        return "response"
    if category == "signature":
        return "exploit_attempt"
    return "correlated_behavior"


def _certainty_for_detection(detection: dict[str, Any]) -> str:
    evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
    detector_id = str(detection.get("detector_id") or "").lower()
    category = str(detection.get("category") or "").lower()
    confidence = float(detection.get("confidence") or 0)
    action = str(evidence.get("suricata_action") or evidence.get("action") or "").lower()
    if evidence.get("exploit_success") or evidence.get("compromise_confirmed"):
        return "confirmed"
    if action in {"blocked", "drop", "dropped"} or "suricata_drop" in detector_id:
        return "prevented"
    if category == "signature":
        return "observed" if confidence >= 0.6 else "suspected"
    if confidence >= 0.75:
        return "observed"
    return "suspected"


def _risk_contribution(detection: dict[str, Any]) -> int:
    severity = float(detection.get("severity") or 0)
    confidence = float(detection.get("confidence") or 0)
    anomaly = float(detection.get("anomaly_score") or 0)
    return int(min(100, round((severity * 6) + (confidence * 25) + (anomaly * 20))))


def _incident_attack_graph(
    incident: dict[str, Any],
    detections: list[dict[str, Any]],
    targets: list[Any],
    response_block: dict[str, Any] | None,
    entity_roles: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    entity_roles = entity_roles or {}
    source_ip = str(incident.get("source_ip") or "unknown-source")
    source_id = _add_graph_node(nodes, source_ip, _role_node_type(source_ip, entity_roles, "source_host"), "observed", incident.get("risk_score"), incident.get("confidence"))
    source_network = _network_label(source_ip)
    if source_network:
        _add_graph_node(nodes, source_network, "internal_network", "inferred", None, None)
    visible_targets = _visible_targets(incident, detections, targets)
    for role, value in entity_roles.items():
        if isinstance(value, str):
            _add_graph_node(nodes, value, _role_node_type(value, entity_roles, role), "correlated", incident.get("risk_score"), incident.get("confidence"))

    for index, detection in enumerate(detections[:40]):
        if not isinstance(detection, dict):
            continue
        stage = _stage_for_detection(detection, incident)
        edge_kind = _edge_kind_for_stage(stage, detection.get("category"))
        certainty = _certainty_for_detection(detection)
        graph_status = _graph_status_for_detection(detection, incident)
        source = str(detection.get("source_ip") or source_ip)
        detection_source_id = _add_graph_node(nodes, source, _role_node_type(source, entity_roles, "source_host"), graph_status, detection.get("severity"), detection.get("confidence"))
        destination = detection.get("destination_ip") or incident.get("destination_ip")
        if not destination:
            destination = "Host baseline"
        destination = _target_group(str(destination), visible_targets)
        node_type = _role_node_type(destination, entity_roles, _node_type(destination))
        target_id = _add_graph_node(nodes, destination, node_type, graph_status if destination != "Host baseline" else "inferred", detection.get("severity"), detection.get("confidence"))
        edge = {
            "id": f"edge-{index}-{edge_kind}",
            "source": detection_source_id,
            "target": target_id,
            "kind": edge_kind,
            "status": graph_status if destination != "Host baseline" else "inferred",
            "stage_status": certainty,
            "stage": stage,
            "timestamp": detection.get("timestamp"),
            "protocol": (detection.get("evidence") or {}).get("protocol"),
            "ports": _ports_for_detection(detection),
            "confidence": detection.get("confidence"),
            "risk_contribution": _risk_contribution(detection),
            "detection_ids": [detection.get("detection_id")] if detection.get("detection_id") else [],
            "title": detection.get("title"),
            "summary": detection.get("description"),
            "evidence": detection.get("evidence", {}),
        }
        edges.append(edge)

    if response_block:
        response_id = _add_graph_node(nodes, f"PF {response_block.get('status', 'response')}", "response", "confirmed", response_block.get("risk_score"), response_block.get("confidence"))
        response_target = str(response_block.get("source_ip") or entity_roles.get("response_target") or source_ip)
        response_source_id = _add_graph_node(nodes, response_target, _role_node_type(response_target, entity_roles, "response_target"), "confirmed", response_block.get("risk_score"), response_block.get("confidence"))
        edges.append({
            "id": "edge-response",
            "source": response_source_id,
            "target": response_id,
            "kind": "response",
            "status": "confirmed" if response_block.get("status") == "active" else "observed",
            "stage_status": "prevented" if response_block.get("status") == "active" else "observed",
            "stage": "response",
            "timestamp": response_block.get("created_at"),
            "protocol": "pf",
            "ports": [],
            "confidence": response_block.get("confidence"),
            "risk_contribution": response_block.get("risk_score"),
            "detection_ids": [],
            "count": 1,
            "title": f"PF block {response_block.get('status')}",
            "summary": response_block.get("reason"),
            "evidence": response_block,
        })

    return {
        "nodes": list(nodes.values())[:24],
        "edges": _dedupe_graph_edges(edges)[:60],
        "legend": {
            "observed": "Seen directly in firewall or Suricata telemetry.",
            "inferred": "Derived from host, subnet, or baseline context.",
            "correlated": "Combined from multiple related detections.",
            "confirmed": "Confirmed by a strong detector or explicit security action.",
        },
        "limits": {
            "visible_nodes": 24,
            "visible_edges": 60,
            "grouped_targets": max(0, len(visible_targets.get("all_targets", [])) - len(visible_targets.get("visible", []))),
        },
    }


def _add_graph_node(
    nodes: dict[str, dict[str, Any]],
    label: str,
    node_type: str,
    status: str,
    risk: Any,
    confidence: Any,
) -> str:
    node_id = f"{node_type}:{label}"
    if node_id not in nodes:
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "status": status,
            "risk": risk,
            "confidence": confidence,
            "details": {
                "certainty": status,
                "entity": label,
                "type": node_type,
            },
        }
    else:
        current = nodes[node_id]
        if GRAPH_STATUS_RANK.get(status, 0) > GRAPH_STATUS_RANK.get(str(current.get("status")), 0):
            current["status"] = status
        if risk is not None:
            current["risk"] = max(float(current.get("risk") or 0), float(risk))
        if confidence is not None:
            current["confidence"] = max(float(current.get("confidence") or 0), float(confidence))
    return node_id


def _network_label(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_private:
        return None
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _node_type(value: str) -> str:
    if value == "Host baseline":
        return "behavior_model"
    if value.startswith("External targets"):
        return "external_group"
    if "/" in value:
        return "internal_network"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "target"
    return "target_host" if address.is_private else "external_target"


def _role_node_type(value: str, roles: dict[str, Any], fallback: str) -> str:
    if value == roles.get("external_actor"):
        return "external_actor"
    if value == roles.get("victim"):
        return "victim_host"
    if value == roles.get("pivot_host"):
        return "pivot_host"
    if value == roles.get("affected_host"):
        return "affected_host"
    if value == roles.get("response_target"):
        return "response_target"
    return fallback


def _dedupe_graph_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in edges:
        key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("kind")), str(edge.get("stage")))
        if key not in grouped:
            item = dict(edge)
            item["count"] = int(item.get("count") or 1)
            grouped[key] = item
            continue
        current = grouped[key]
        current["count"] = int(current.get("count") or 1) + 1
        current["risk_contribution"] = max(int(current.get("risk_contribution") or 0), int(edge.get("risk_contribution") or 0))
        current["confidence"] = max(float(current.get("confidence") or 0), float(edge.get("confidence") or 0))
        current["detection_ids"] = list(dict.fromkeys((current.get("detection_ids") or []) + (edge.get("detection_ids") or [])))
        current_ports = current.get("ports") if isinstance(current.get("ports"), list) else []
        edge_ports = edge.get("ports") if isinstance(edge.get("ports"), list) else []
        current["ports"] = list(dict.fromkeys(current_ports + edge_ports))[:12]
        current["last_seen"] = edge.get("timestamp") or current.get("last_seen") or current.get("timestamp")
    return list(grouped.values())


def _visible_targets(incident: dict[str, Any], detections: list[dict[str, Any]], targets: list[Any]) -> dict[str, Any]:
    all_targets: list[str] = []
    for target in list(targets or []) + [incident.get("destination_ip")]:
        if target and str(target) not in all_targets:
            all_targets.append(str(target))
    for detection in detections:
        target = detection.get("destination_ip") if isinstance(detection, dict) else None
        if target and str(target) not in all_targets:
            all_targets.append(str(target))
    visible = all_targets[:10]
    return {"all_targets": all_targets, "visible": visible}


def _target_group(target: str, visible_targets: dict[str, Any]) -> str:
    if target in visible_targets.get("visible", []):
        return target
    if target == "Host baseline":
        return target
    network = _network_label(target)
    if network:
        return network
    return "External targets (grouped)"


def _ports_for_detection(detection: dict[str, Any]) -> list[Any]:
    evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
    ports = evidence.get("ports") or evidence.get("destination_ports") or evidence.get("target_ports") or []
    if isinstance(ports, list):
        return ports[:12]
    if ports:
        return [ports]
    return []


def _graph_status_for_detection(detection: dict[str, Any], incident: dict[str, Any]) -> str:
    certainty = _certainty_for_detection(detection)
    if certainty == "confirmed":
        return "confirmed"
    evidence = incident.get("evidence") if isinstance(incident.get("evidence"), dict) else {}
    correlation = evidence.get("correlation") if isinstance(evidence, dict) else {}
    if isinstance(correlation, dict) and correlation.get("deduplicated"):
        return "correlated"
    if certainty == "observed":
        return "observed"
    return "inferred"


def _group_timeline(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in sorted(timeline, key=lambda row: str(row.get("timestamp") or "")):
        key = "|".join(str(item.get(part) or "") for part in ("stage", "edge_kind", "detector_id", "title"))
        if key not in grouped:
            grouped[key] = dict(item, count=0, first_seen=item.get("timestamp"), last_seen=item.get("timestamp"), detections=[])
        entry = grouped[key]
        entry["count"] += 1
        entry["last_seen"] = item.get("timestamp") or entry["last_seen"]
        entry["risk_delta"] = max(int(entry.get("risk_delta") or 0), int(item.get("risk_delta") or 0))
        entry["detections"].append(item)
    return list(grouped.values())


def _infer_entity_roles(detections: list[dict[str, Any]], incident: dict[str, Any]) -> dict[str, Any]:
    ordered = sorted((item for item in detections if isinstance(item, dict)), key=lambda row: str(row.get("timestamp") or ""))
    if not ordered and incident.get("source_ip"):
        ordered = [incident]
    sources = [str(item.get("source_ip")) for item in ordered if item.get("source_ip")]
    destinations = [str(item.get("destination_ip")) for item in ordered if item.get("destination_ip")]
    external_actor = None
    victim = None
    for item in ordered:
        src = str(item.get("source_ip") or "")
        dst = str(item.get("destination_ip") or "")
        if src and dst and not _is_internal_case_address(src) and _is_internal_case_address(dst):
            external_actor = src
            victim = dst
            break
    if external_actor is None:
        external_actor = next((src for src in sources if not _is_internal_case_address(src)), None)
    affected_host = victim or next((src for src in sources if _is_internal_case_address(src)), None) or incident.get("source_ip")
    pivot_host = None
    if affected_host:
        for item in ordered:
            src = str(item.get("source_ip") or "")
            dst = str(item.get("destination_ip") or "")
            if src == affected_host and dst and dst != affected_host:
                pivot_host = src
                break
    destination = incident.get("destination_ip") or (destinations[0] if destinations else None)
    response_target = external_actor or affected_host
    roles = {
        "external_actor": external_actor,
        "threat_source": external_actor or incident.get("source_ip"),
        "affected_host": affected_host,
        "victim": victim,
        "pivot_host": pivot_host,
        "destination": destination,
        "response_target": response_target,
    }
    return {key: value for key, value in roles.items() if value}


def _is_internal_case_address(value: str | None) -> bool:
    if not value or "/" in str(value) or str(value).startswith("port:"):
        return False
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    internal_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    )
    return any(address.version == network.version and address in network for network in internal_networks) or address.is_loopback


def _case_summary(
    incident: dict[str, Any],
    targets: list[Any],
    admin_guidance: list[str],
    response_block: dict[str, Any] | None,
    entity_roles: dict[str, Any] | None = None,
    response_blocks: list[dict[str, Any]] | None = None,
    threat_intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entity_roles = entity_roles or {}
    response_blocks = response_blocks or []
    threat_intel = threat_intel or {}
    source_ip = incident.get("source_ip")
    destination = incident.get("destination_ip")
    affected_host = entity_roles.get("affected_host") or entity_roles.get("victim") or source_ip
    source_private = False
    if affected_host:
        try:
            source_private = ipaddress.ip_address(str(affected_host)).is_private
        except ValueError:
            source_private = False
    if entity_roles.get("external_actor"):
        entry_source = {
            "value": entity_roles["external_actor"],
            "certainty": "observed",
            "reason": "The source participated in inbound detections against an internal target.",
        }
    elif source_private:
        entry_source = {
            "value": "Internal host behavior observed",
            "certainty": "inferred",
            "reason": "The source is inside a private address range; PondSec cannot prove initial compromise from this incident alone.",
        }
    else:
        entry_source = {
            "value": "External source",
            "certainty": "observed",
            "reason": "The source address is outside private address space.",
        }
    response = {
        "status": response_block.get("status") if response_block else "none",
        "block_id": response_block.get("block_id") if response_block else None,
        "automatic": bool(response_block.get("automatic")) if response_block else False,
        "isolation": "active" if response_block and response_block.get("status") == "active" and source_private else "none",
        "active_blocks": response_blocks,
        "release_available": any(item.get("status") in {"active", "proposed"} for item in response_blocks),
    }
    narrative = _case_narrative(incident, entity_roles, response, threat_intel)
    return {
        "affected_host": affected_host,
        "entity_roles": entity_roles,
        "narrative": narrative,
        "possible_entry_source": entry_source,
        "primary_destination": destination,
        "targets": targets,
        "first_seen": incident.get("first_seen") or incident.get("created_at"),
        "last_seen": incident.get("last_seen") or incident.get("updated_at"),
        "risk_score": incident.get("risk_score"),
        "confidence": incident.get("confidence"),
        "response": response,
        "threat_intel_risk_modifier": threat_intel.get("risk_modifier", 0),
        "recommended_actions": admin_guidance[:6],
        "certainty": {
            "confirmed": ["Stored incident fields", "Recorded detection metadata"],
            "observed": ["Telemetry-backed source and detection timestamps"],
            "inferred": ["Possible entry source", "Grouped networks", "Ungrouped target clusters"],
            "not_claimed": ["Successful compromise", "confirmed exploit execution", "confirmed zero-day root cause"],
        },
    }


def _case_narrative(
    incident: dict[str, Any],
    roles: dict[str, Any],
    response: dict[str, Any],
    threat_intel: dict[str, Any],
) -> dict[str, Any]:
    source = roles.get("external_actor") or roles.get("threat_source") or incident.get("source_ip") or "unknown source"
    victim = roles.get("victim") or roles.get("affected_host") or incident.get("destination_ip") or "unknown target"
    categories = []
    evidence = incident.get("evidence") if isinstance(incident.get("evidence"), dict) else {}
    correlation = evidence.get("correlation") if isinstance(evidence, dict) else {}
    if isinstance(correlation, dict):
        categories = correlation.get("categories") or []
    if not categories and incident.get("category"):
        categories = [incident["category"]]
    response_text = "No active PondSec block or isolation is recorded for this case."
    if response.get("status") in {"active", "proposed"}:
        action = "active" if response.get("status") == "active" else "proposed"
        response_text = f"A PondSec response is {action} for response target {roles.get('response_target') or source}."
    cve_count = len((threat_intel or {}).get("cves", []))
    intel_text = ""
    if cve_count:
        intel_text = f" Local CVE context found {cve_count} referenced CVE(s); this prioritizes review but does not prove vulnerability or exploitation success."
    return {
        "what_happened": (
            f"PondSec correlated {incident.get('detection_count', 0)} detection(s) from {source} involving {victim}"
            f" across {', '.join(str(item) for item in categories) or 'recorded telemetry'}."
            f" {response_text}{intel_text}"
        ),
        "confirmed": [
            "Detection timestamps and stored incident metadata",
            "Observed source/destination relationships from local telemetry",
        ],
        "not_confirmed": [
            "Successful initial access",
            "Successful exploit execution",
            "Confirmed vulnerable product/version unless version-matched CVE evidence is shown",
        ],
    }


def _case_threat_intelligence(detections: list[dict[str, Any]], config: Any | None) -> dict[str, Any]:
    if not config or not getattr(config, "threat_intel", None) or not config.threat_intel.cve_enrichment:
        return {"enabled": False, "cves": [], "risk_modifier": 0}
    return enrich_case_cves(
        detections,
        config.data_dir,
        CveEnrichmentOptions(
            cache_ttl_hours=config.threat_intel.cache_ttl_hours,
            external_lookup=config.threat_intel.external_lookup,
        ),
    )


def _related_cases(store: EventStore | None, incident: dict[str, Any], roles: dict[str, Any]) -> list[dict[str, Any]]:
    if store is None:
        return []
    current_id = incident.get("incident_id")
    current_entities = _case_entities(incident, roles)
    first_seen = _parse_analysis_time(incident.get("first_seen") or incident.get("created_at"))
    related = []
    for row in store.list_rows("incidents", limit=200):
        if row.get("incident_id") == current_id:
            continue
        other = _decode_rows([row])[0]
        other_evidence = other.get("evidence", {}) if isinstance(other.get("evidence"), dict) else {}
        other_roles = other_evidence.get("entity_roles", {}) if isinstance(other_evidence, dict) else {}
        other_entities = _case_entities(other, other_roles)
        reasons = []
        if incident.get("source_ip") and incident.get("source_ip") == other.get("source_ip"):
            reasons.append("same source")
        shared = sorted(current_entities & other_entities)
        if shared:
            reasons.append("shared entity " + ", ".join(shared[:3]))
        other_time = _parse_analysis_time(other.get("first_seen") or other.get("created_at"))
        if first_seen and other_time and abs((first_seen - other_time).total_seconds()) <= 1800:
            reasons.append("close time window")
        if not reasons:
            continue
        related.append({
            "incident_id": other.get("incident_id"),
            "title": other.get("title"),
            "status": other.get("status"),
            "risk_score": other.get("risk_score"),
            "category": other.get("category"),
            "reasons": reasons,
            "actions": ["merge", "link_as_related", "keep_separate"],
        })
    return related[:8]


def _case_entities(incident: dict[str, Any], roles: dict[str, Any]) -> set[str]:
    entities = {str(incident[key]) for key in ("source_ip", "destination_ip") if incident.get(key)}
    entities.update(str(target) for target in incident.get("affected_targets", []) if target)
    if isinstance(roles, dict):
        entities.update(str(value) for value in roles.values() if value)
    return entities


def _parse_analysis_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def _decode_blocklist_view(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["items"] = _decode_rows(result.get("items", []))
    result["history"] = _decode_rows(result.get("history", []))
    return result


def emit(result: dict[str, Any], as_json: bool) -> None:
    try:
        if as_json:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
            return
        status = result.get("status")
        if status:
            print(status)
        else:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
