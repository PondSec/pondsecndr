#!/usr/bin/env python3
"""Safe PondSec NDR validation scenario generator and replay helper."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "src" / "usr" / "local" / "share" / "pondsec-ndr"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import default_detectors
from pondsec_ndr.features.aggregator import aggregate_features


LAB_STARTED_AT = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class LabScenario:
    name: str
    title: str
    description: str
    expected_detectors: tuple[str, ...]
    build: Callable[[], list[dict[str, Any]]]


def _ts(offset_seconds: int) -> str:
    return (LAB_STARTED_AT + timedelta(seconds=offset_seconds)).isoformat()


def _flow(
    offset_seconds: int,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    index: int,
    *,
    interface: str = "igb0_vlan10",
    source_port: int = 42000,
    bytes_out: int = 2000,
    bytes_in: int = 200,
    packets_out: int = 3,
    packets_in: int = 1,
    reason: str = "timeout",
    app_proto: str | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "flow",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": source_port + index,
        "dest_ip": destination_ip,
        "dest_port": destination_port,
        "proto": "TCP",
        "app_proto": app_proto,
        "flow": {
            "state": "closed",
            "reason": reason,
            "age": 1,
            "pkts_toserver": packets_out,
            "pkts_toclient": packets_in,
            "bytes_toserver": bytes_out,
            "bytes_toclient": bytes_in,
        },
    }


def _dns(offset_seconds: int, source_ip: str, resolver_ip: str, index: int, *, interface: str = "igb0_vlan10") -> dict[str, Any]:
    label = f"q9w8e7r6t5y4u3i2o1p0asdfghjklzxcvbnm{index:02d}"
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "dns",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": 53000 + index,
        "dest_ip": resolver_ip,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {
            "rrname": f"{label}.validation.pondsec.test",
            "rrtype": "TXT",
            "rcode": "NXDOMAIN",
        },
    }


def _tls(offset_seconds: int, source_ip: str, destination_ip: str, index: int, *, interface: str = "igb0_vlan10") -> dict[str, Any]:
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "tls",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": 44000 + index,
        "dest_ip": destination_ip,
        "dest_port": 443,
        "proto": "TCP",
        "tls": {
            "sni": f"cdn-{index}.validation.pondsec.test",
            "issuerdn": "CN=PondSec Validation CA",
            "subject": f"CN=lab-{index}.validation.pondsec.test",
            "version": "TLS 1.3",
            "ja3": f"{index:032x}",
        },
    }


def _alert(
    offset_seconds: int,
    source_ip: str,
    destination_ip: str,
    signature_id: int,
    signature: str,
    *,
    category: str,
    severity: int = 2,
    destination_port: int = 443,
    interface: str = "igb0_vlan10",
) -> dict[str, Any]:
    return {
        "timestamp": _ts(offset_seconds),
        "event_type": "alert",
        "in_iface": interface,
        "src_ip": source_ip,
        "src_port": 45000 + signature_id % 1000,
        "dest_ip": destination_ip,
        "dest_port": destination_port,
        "proto": "TCP",
        "alert": {
            "signature_id": signature_id,
            "signature": signature,
            "category": category,
            "severity": severity,
            "gid": 1,
            "rev": 1,
            "action": "allowed",
        },
    }


def _wan_scan() -> list[dict[str, Any]]:
    return [
        _flow(index, "8.8.8.241", "192.168.30.3", 20 + index, index, interface="pppoe0")
        for index in range(18)
    ]


def _credential_access() -> list[dict[str, Any]]:
    events = [
        _flow(index, "192.168.20.55", f"192.168.30.{20 + index}", 445 if index % 2 else 3389, index, interface="igb0_vlan20", reason="reset")
        for index in range(14)
    ]
    events.append(_alert(
        18,
        "192.168.20.55",
        "192.168.30.21",
        9101001,
        "PondSec validation marker: credential spraying and brute force pattern",
        category="Potential Credential Access",
        destination_port=445,
        interface="igb0_vlan20",
    ))
    return events


def _exploit_attempt() -> list[dict[str, Any]]:
    return [
        _alert(
            0,
            "8.8.8.77",
            "192.168.30.44",
            9101501,
            "PondSec validation marker: CVE-2026-0001 remote code execution exploit attempt",
            category="Attempted Administrator Privilege Gain",
            destination_port=443,
            interface="pppoe0",
        ),
        _flow(1, "8.8.8.77", "192.168.30.44", 443, 1, interface="pppoe0", reason="reset", app_proto="http"),
    ]


def _dns_tunnel() -> list[dict[str, Any]]:
    return [_dns(index, "192.168.30.241", "9.9.9.9", index, interface="re0") for index in range(12)]


def _tls_evasion() -> list[dict[str, Any]]:
    return [_tls(index, "192.168.10.81", "8.8.4.90", index, interface="igb0_vlan10") for index in range(8)]


def _exfiltration() -> list[dict[str, Any]]:
    return [
        _flow(
            index,
            "192.168.10.242",
            "8.8.4.88",
            443,
            index,
            interface="igb0_vlan10",
            bytes_out=30_000_000,
            bytes_in=1000,
            packets_out=2000,
            packets_in=20,
            reason="finished",
            app_proto="tls",
        )
        for index in range(2)
    ]


def _beaconing() -> list[dict[str, Any]]:
    return [
        _flow(index * 60, "192.168.10.241", "8.8.4.44", 443, index, interface="igb0_vlan10", reason="finished", app_proto="tls")
        for index in range(6)
    ]


def _supply_chain_callback() -> list[dict[str, Any]]:
    events = [
        _flow(index % 10, "192.168.10.70", f"8.8.4.{10 + index}", 443, index, interface="igb0_vlan10", reason="finished", app_proto="tls")
        for index in range(55)
    ]
    events.extend(_dns(20 + index, "192.168.10.70", "9.9.9.9", index, interface="igb0_vlan10") for index in range(12))
    events.append(_alert(
        35,
        "192.168.10.70",
        "8.8.4.77",
        9102001,
        "PondSec validation marker: supply-chain callback pattern",
        category="Potential Supply Chain Callback",
        interface="igb0_vlan10",
    ))
    return events


def _malware_callback() -> list[dict[str, Any]]:
    events = [
        _flow(index * 45, "192.168.10.85", "8.8.4.64", 443, index, interface="igb0_vlan10", reason="finished", app_proto="tls")
        for index in range(6)
    ]
    events.append(_alert(
        280,
        "192.168.10.85",
        "8.8.4.64",
        9102501,
        "PondSec validation marker: malware loader payload download callback",
        category="A Network Trojan was Detected",
        destination_port=443,
        interface="igb0_vlan10",
    ))
    return events


def _multi_stage_intrusion() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    events.extend(
        _flow(index, "8.8.8.66", "192.168.30.50", 20 + index, index, interface="pppoe0")
        for index in range(18)
    )
    events.append(_alert(
        25,
        "8.8.8.66",
        "192.168.30.50",
        9103001,
        "PondSec validation marker: exploit attempt pattern",
        category="Attempted Administrator Privilege Gain",
        destination_port=443,
        interface="pppoe0",
    ))
    events.extend(
        _flow(120 + index * 60, "192.168.30.50", "8.8.4.44", 443, 100 + index, interface="re0", reason="finished", app_proto="tls")
        for index in range(6)
    )
    events.extend(
        _flow(520 + index, "192.168.30.50", f"192.168.20.{30 + index}", 445 if index % 2 else 3389, 200 + index, interface="re0", reason="reset")
        for index in range(14)
    )
    events.extend(
        _flow(
            700 + index,
            "192.168.30.50",
            "8.8.4.88",
            443,
            300 + index,
            interface="re0",
            bytes_out=30_000_000,
            bytes_in=1000,
            packets_out=2000,
            packets_in=20,
            reason="finished",
            app_proto="tls",
        )
        for index in range(2)
    )
    return events


SCENARIOS: dict[str, LabScenario] = {
    "wan_scan": LabScenario(
        "wan_scan",
        "WAN reconnaissance",
        "External vertical scan against an internal DMZ host.",
        ("pondsec.portscan", "pondsec.vertical_scan"),
        _wan_scan,
    ),
    "credential_access": LabScenario(
        "credential_access",
        "Credential pressure pattern",
        "Internal SMB/RDP fan-out and repeated failed auth-service connections; no credentials are used.",
        ("pondsec.credential_bruteforce", "pondsec.lateral_movement", "pondsec.suricata_alert"),
        _credential_access,
    ),
    "exploit_attempt": LabScenario(
        "exploit_attempt",
        "Exploit attempt pattern",
        "A harmless Suricata-style marker that resembles an exploit attempt against a service.",
        ("pondsec.exploit_attempt", "pondsec.suricata_alert"),
        _exploit_attempt,
    ),
    "dns_tunnel": LabScenario(
        "dns_tunnel",
        "DNS tunneling pattern",
        "High-entropy NXDOMAIN TXT lookups resembling tunnel metadata.",
        ("pondsec.dns_tunneling",),
        _dns_tunnel,
    ),
    "tls_evasion": LabScenario(
        "tls_evasion",
        "TLS fingerprint churn",
        "One host presenting many TLS fingerprints in a short window.",
        ("pondsec.unusual_tls_fingerprint",),
        _tls_evasion,
    ),
    "exfiltration": LabScenario(
        "exfiltration",
        "Data exfiltration pattern",
        "Large asymmetric outbound transfer represented as Suricata flow metadata.",
        ("pondsec.data_exfiltration",),
        _exfiltration,
    ),
    "beaconing": LabScenario(
        "beaconing",
        "Command-and-control beaconing",
        "Periodic outbound TLS connections to one destination.",
        ("pondsec.beaconing",),
        _beaconing,
    ),
    "supply_chain_callback": LabScenario(
        "supply_chain_callback",
        "Supply-chain callback pattern",
        "Installer-like destination fan-out, DNS tunneling metadata and a validation marker; no code is downloaded or executed.",
        ("pondsec.supply_chain_callback", "pondsec.unusual_destination", "pondsec.dns_tunneling", "pondsec.suricata_alert"),
        _supply_chain_callback,
    ),
    "malware_callback": LabScenario(
        "malware_callback",
        "Malware callback pattern",
        "Beacon-like outbound traffic plus a harmless malware-loader marker.",
        ("pondsec.malware_callback", "pondsec.beaconing", "pondsec.suricata_alert"),
        _malware_callback,
    ),
    "multi_stage_intrusion": LabScenario(
        "multi_stage_intrusion",
        "Multi-stage intrusion chain",
        "Reconnaissance, exploit marker, beaconing, lateral movement and exfiltration tied to one victim.",
        (
            "pondsec.portscan",
            "pondsec.vertical_scan",
            "pondsec.exploit_attempt",
            "pondsec.suricata_alert",
            "pondsec.beaconing",
            "pondsec.credential_bruteforce",
            "pondsec.lateral_movement",
            "pondsec.data_exfiltration",
        ),
        _multi_stage_intrusion,
    ),
}


def _selected_scenarios(name: str) -> list[LabScenario]:
    if name == "all":
        return list(SCENARIOS.values())
    return [SCENARIOS[name]]


def _build_events(scenarios: list[LabScenario]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for scenario in scenarios:
        events.extend(scenario.build())
    return sorted(events, key=lambda item: str(item.get("timestamp", "")))


def _expected_detectors(scenarios: list[LabScenario]) -> list[str]:
    expected = {detector for scenario in scenarios for detector in scenario.expected_detectors}
    return sorted(expected)


def _write_jsonl(path: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def _write_manifest(path: Path, scenarios: list[LabScenario], output: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "eve_file": str(output),
        "event_count": len(events),
        "safe_lab": True,
        "response_mode": "simulation_only",
        "expected_detectors": _expected_detectors(scenarios),
        "scenarios": [
            {
                "name": scenario.name,
                "title": scenario.title,
                "description": scenario.description,
                "expected_detectors": list(scenario.expected_detectors),
            }
            for scenario in scenarios
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_manifest(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _read_events(path: Path, max_lines: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    offset = path.parent / f".{path.name}.pondsec-lab-offset"
    offset.unlink(missing_ok=True)
    collector = EveCollector(path, offset, queue_limit=max_lines)
    events, stats = collector.read_once(max_lines=max_lines)
    offset.unlink(missing_ok=True)
    return events, {
        "read_lines": stats.read_lines,
        "accepted_events": stats.accepted_events,
        "parser_errors": stats.parser_errors,
        "normalization_errors": stats.normalization_errors,
        "duplicates": stats.duplicates,
        "queue_drops": stats.queue_drops,
        "last_error": stats.last_error,
    }


def analyze_file(path: Path, max_lines: int, manifest: Path | None = None) -> dict[str, Any]:
    events, collector = _read_events(path, max_lines)
    features = aggregate_features(events)
    detections: list[dict[str, Any]] = []
    for detector in default_detectors():
        detections.extend(detector.detect(events, features))
    incidents = correlate_detections(detections)
    detector_ids = sorted({str(item.get("detector_id")) for item in detections if item.get("detector_id")})
    expected = sorted(set((_load_manifest(manifest) or {}).get("expected_detectors") or []))
    missing = [detector for detector in expected if detector not in detector_ids]
    return {
        "status": "ok" if collector["accepted_events"] and not missing and incidents else "failed",
        "input": str(path),
        "safe_lab": True,
        "response_mode": "simulation_only",
        "events": len(events),
        "collector": collector,
        "features": len(features),
        "detectors": detector_ids,
        "expected_detectors": expected,
        "missing_detectors": missing,
        "detections": [
            {
                "detector_id": item.get("detector_id"),
                "category": item.get("category"),
                "source_ip": item.get("source_ip"),
                "destination_ip": item.get("destination_ip"),
                "severity": item.get("severity"),
                "confidence": item.get("confidence"),
                "title": item.get("title"),
            }
            for item in detections
        ],
        "incidents": [
            {
                "incident_id": item.get("incident_id"),
                "category": item.get("category"),
                "attack_stage": item.get("attack_stage"),
                "risk_score": item.get("risk_score"),
                "confidence": item.get("confidence"),
                "source_ip": item.get("source_ip"),
                "destination_ip": item.get("destination_ip"),
                "detection_count": item.get("detection_count"),
            }
            for item in incidents
        ],
    }


def _safe_remote_name(path: Path) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", path.name)
    return f"/tmp/pondsec-lab-{name}"


def replay_file(path: Path, max_lines: int, command: str, ssh_target: str | None) -> dict[str, Any]:
    if ssh_target:
        remote_path = _safe_remote_name(path)
        copy = subprocess.run(["scp", str(path), f"{ssh_target}:{remote_path}"], text=True, capture_output=True, check=False)
        if copy.returncode != 0:
            return {"status": "failed", "step": "copy", "stderr": copy.stderr.strip(), "stdout": copy.stdout.strip()}
        replay_command = f"sudo {shlex.quote(command)} --json replay --max-lines {int(max_lines)} {shlex.quote(remote_path)}"
        cleanup_command = f"rm -f {shlex.quote(remote_path)} {shlex.quote(str(Path(remote_path).parent / ('.' + Path(remote_path).name + '.pondsec-replay-offset')))}"
        result = subprocess.run(["ssh", ssh_target, f"{replay_command}; {cleanup_command}"], text=True, capture_output=True, check=False)
    else:
        result = subprocess.run([command, "--json", "replay", "--max-lines", str(max_lines), str(path)], text=True, capture_output=True, check=False)
    parsed: dict[str, Any] | None = None
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        parsed = None
    return {
        "status": "ok" if result.returncode == 0 else "failed",
        "safe_lab": True,
        "response_mode": "simulation_only",
        "command_returncode": result.returncode,
        "stdout_json": parsed,
        "stdout": result.stdout.strip() if parsed is None else None,
        "stderr": result.stderr.strip(),
    }


def write_report(analysis_path: Path, output_path: Path, replay_path: Path | None = None) -> dict[str, Any]:
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    replay = json.loads(replay_path.read_text(encoding="utf-8")) if replay_path else None
    output_path.parent.mkdir(parents=True, exist_ok=True)
    missing = analysis.get("missing_detectors") or []
    status = "PASS" if analysis.get("status") == "ok" and not missing else "FAIL"
    lines = [
        "# PondSec NDR Validation Lab Report",
        "",
        f"- Status: {status}",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Input: `{analysis.get('input')}`",
        f"- Safe lab: {analysis.get('safe_lab')}",
        f"- Response mode: `{analysis.get('response_mode')}`",
        f"- Events accepted: {analysis.get('events')}",
        f"- Feature rows: {analysis.get('features')}",
        f"- Incidents correlated: {len(analysis.get('incidents') or [])}",
        "",
        "## Expected Coverage",
        "",
    ]
    for detector in analysis.get("expected_detectors") or []:
        marker = "pass" if detector in set(analysis.get("detectors") or []) else "missing"
        lines.append(f"- {marker}: `{detector}`")
    lines.extend(["", "## Detectors Observed", ""])
    for detector in analysis.get("detectors") or []:
        lines.append(f"- `{detector}`")
    lines.extend(["", "## Incidents", ""])
    for incident in analysis.get("incidents") or []:
        lines.append(
            "- "
            f"`{incident.get('incident_id')}` "
            f"category={incident.get('category')} "
            f"stage={incident.get('attack_stage')} "
            f"risk={incident.get('risk_score')} "
            f"confidence={incident.get('confidence')} "
            f"source={incident.get('source_ip')} "
            f"destination={incident.get('destination_ip')} "
            f"detections={incident.get('detection_count')}"
        )
    lines.extend(["", "## Gaps", ""])
    if missing:
        for detector in missing:
            lines.append(f"- Missing expected detector: `{detector}`")
    else:
        lines.append("- No expected detector gaps in this run.")
    if replay is not None:
        replay_payload = replay.get("stdout_json") if isinstance(replay.get("stdout_json"), dict) else {}
        lines.extend([
            "",
            "## Replay Result",
            "",
            f"- Replay status: {replay.get('status')}",
            f"- Replay command return code: {replay.get('command_returncode')}",
            f"- Replay response mode: `{replay_payload.get('response_mode')}`",
            f"- Replay events: {replay_payload.get('events')}",
            f"- Replay detections: {len(replay_payload.get('detections') or [])}",
            f"- Replay incidents: {len(replay_payload.get('incidents') or [])}",
            f"- Replay would execute response: {bool((replay_payload.get('shadow_response') or {}).get('would_execute'))}",
        ])
    lines.extend([
        "",
        "## Safety Notes",
        "",
        "- The lab data is synthetic Suricata EVE telemetry.",
        "- The lab does not contain working exploits, credentials, malware, or destructive payloads.",
        "- Replay is simulation-only and must not create block entries or modify PF, firewall, DNS, CrowdSec, or alias state.",
    ])
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"status": "ok", "output": str(output_path), "validation_status": status}


def cmd_list(_: argparse.Namespace) -> dict[str, Any]:
    return {
        "status": "ok",
        "scenarios": [
            {
                "name": scenario.name,
                "title": scenario.title,
                "description": scenario.description,
                "expected_detectors": list(scenario.expected_detectors),
            }
            for scenario in SCENARIOS.values()
        ],
    }


def cmd_generate(args: argparse.Namespace) -> dict[str, Any]:
    scenarios = _selected_scenarios(args.scenario)
    events = _build_events(scenarios)
    output = Path(args.output)
    manifest = Path(args.manifest) if args.manifest else output.with_suffix(output.suffix + ".manifest.json")
    _write_jsonl(output, events)
    _write_manifest(manifest, scenarios, output, events)
    return {
        "status": "ok",
        "output": str(output),
        "manifest": str(manifest),
        "event_count": len(events),
        "expected_detectors": _expected_detectors(scenarios),
        "safe_lab": True,
    }


def cmd_analyze(args: argparse.Namespace) -> dict[str, Any]:
    return analyze_file(Path(args.input), args.max_lines, Path(args.manifest) if args.manifest else None)


def cmd_replay(args: argparse.Namespace) -> dict[str, Any]:
    return replay_file(Path(args.input), args.max_lines, args.command, args.ssh)


def cmd_report(args: argparse.Namespace) -> dict[str, Any]:
    return write_report(Path(args.analysis), Path(args.output), Path(args.replay) if args.replay else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate and replay safe PondSec NDR validation telemetry.")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    sub = parser.add_subparsers(dest="command_name", required=True)

    list_cmd = sub.add_parser("list")
    list_cmd.set_defaults(func=cmd_list)

    generate = sub.add_parser("generate")
    generate.add_argument("--scenario", choices=["all", *SCENARIOS.keys()], default="all")
    generate.add_argument("--output", required=True)
    generate.add_argument("--manifest", default=None)
    generate.set_defaults(func=cmd_generate)

    analyze = sub.add_parser("analyze")
    analyze.add_argument("--input", required=True)
    analyze.add_argument("--manifest", default=None)
    analyze.add_argument("--max-lines", type=int, default=100000)
    analyze.set_defaults(func=cmd_analyze)

    replay = sub.add_parser("replay")
    replay.add_argument("--input", required=True)
    replay.add_argument("--max-lines", type=int, default=100000)
    replay.add_argument("--command", default="pondsec-ndrctl")
    replay.add_argument("--ssh", default=None, help="optional user@host target for remote replay")
    replay.set_defaults(func=cmd_replay)

    report = sub.add_parser("report")
    report.add_argument("--analysis", required=True)
    report.add_argument("--output", required=True)
    report.add_argument("--replay", default=None)
    report.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = args.func(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result.get("status", "unknown"))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
