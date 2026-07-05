"""Command line interface for PondSec NDR."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.config import ensure_directories, load_config
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import default_detectors
from pondsec_ndr.diagnostics import diagnostics as diagnostics_payload
from pondsec_ndr.diagnostics import self_test, service_status
from pondsec_ndr.features.aggregator import aggregate_features
from pondsec_ndr.models.manager import ModelError, download_model_artifacts, model_inventory, write_runtime_selftest
from pondsec_ndr.models.runtime import MODEL_ID, SYNTHETIC_AI_VALIDATION_VECTOR, ModelRuntimeUnavailable, SaidimnIdsCnnRuntime
from pondsec_ndr.response.engine import ResponseDenied, activate_block, propose_block_for_incident, remove_block, validate_ip_or_network
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.sensor import harden_sensor, sensor_status
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
    model_sub.add_parser("self-test")
    validate_model_flow = model_sub.add_parser("validate-flow")
    validate_model_flow.add_argument("--kind", choices=("attack", "benign"), default="attack")
    validate_model_flow.add_argument("--source-ip", default=None)
    validate_model_flow.add_argument("--device", default="igb0_vlan10")

    database = sub.add_parser("database")
    database_sub = database.add_subparsers(dest="database_command", required=True)
    database_sub.add_parser("check")
    database_sub.add_parser("migrate")

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
            return {"status": "ok", "schema_version": 1}, 0
        payload = store.check()
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
    incidents = correlate_detections(detections)
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
    incidents = correlate_detections(detections)
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
    incidents = correlate_detections(detections)
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
