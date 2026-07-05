from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest

import pondsec_ndr.diagnostics as diagnostics_mod
from pondsec_ndr.cli import main as cli_main
from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.config import PondSecConfig, ResponseConfig
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import BeaconingDetector, DNSTunnelingDetector, PortScanDetector, SuricataAlertAdapter
from pondsec_ndr.diagnostics import eve_access_status
from pondsec_ndr.features.aggregator import aggregate_features, shannon_entropy
from pondsec_ndr.models.cicids_features import CICIDS2017_FEATURES, cicids_vector_from_feature
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.normalizers.suricata import normalize_eve
from pondsec_ndr.response.engine import ResponseDenied, activate_block, is_protected_target, propose_block_for_incident, remove_block
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.service import PondSecService
from pondsec_ndr.storage.database import EventStore


def flow_event(timestamp: str, src: str, dst: str, port: int, reason: str = "timeout") -> dict:
    return {
        "timestamp": timestamp,
        "event_type": "flow",
        "src_ip": src,
        "src_port": 51000 + port % 1000,
        "dest_ip": dst,
        "dest_port": port,
        "proto": "TCP",
        "flow": {
            "state": "closed",
            "reason": reason,
            "age": 1,
            "pkts_toserver": 3,
            "pkts_toclient": 1,
            "bytes_toserver": 2000,
            "bytes_toclient": 200,
        },
    }


class BackendTests(unittest.TestCase):
    def test_suricata_normalizer_redacts_http_query_and_validates_ports(self) -> None:
        event = normalize_eve({
            "timestamp": "2026-07-05T10:00:00+00:00",
            "event_type": "http",
            "src_ip": "192.168.10.10",
            "src_port": 51515,
            "dest_ip": "1.1.1.1",
            "dest_port": 80,
            "proto": "TCP",
            "http": {
                "hostname": "example.test",
                "url": "/login?token=secret",
                "http_method": "POST",
                "status": 200,
                "headers": {"Authorization": "secret", "X-Test": "ok"},
            },
        })
        self.assertEqual(event["metadata"]["url_path"], "/login")
        self.assertNotIn("Authorization", event["metadata"]["headers"])
        self.assertEqual(event["direction"], "egress")

    def test_collector_skips_corrupt_json_and_persists_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eve = Path(tmp) / "eve.json"
            offset = Path(tmp) / "offset.json"
            lines = [
                json.dumps(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.20", "198.51.100.10", 80)),
                "{not-json",
                json.dumps(flow_event("2026-07-05T10:00:01+00:00", "192.168.10.20", "198.51.100.11", 443)),
            ]
            eve.write_text("\n".join(lines) + "\n", encoding="utf-8")
            events, stats = EveCollector(eve, offset).read_once(max_lines=10)
            self.assertEqual(len(events), 2)
            self.assertEqual(stats.parser_errors, 1)
            events2, stats2 = EveCollector(eve, offset).read_once(max_lines=10)
            self.assertEqual(events2, [])
            self.assertEqual(stats2.read_lines, 0)

    def test_portscan_detector_requires_multiple_ports_and_failures(self) -> None:
        events = [
            normalize_eve(flow_event(f"2026-07-05T10:00:{i:02d}+00:00", "192.168.10.50", "192.168.20.10", 20 + i))
            for i in range(15)
        ]
        features = aggregate_features(events)
        detections = PortScanDetector().detect(events, features)
        self.assertTrue(any(item["detector_id"] == "pondsec.portscan" for item in detections))
        self.assertGreaterEqual(detections[0]["confidence"], 0.8)

    def test_beaconing_detector_finds_periodic_connections(self) -> None:
        events = [
            normalize_eve(flow_event(f"2026-07-05T10:0{i}:00+00:00", "192.168.10.60", "203.0.113.44", 443, "finished"))
            for i in range(6)
        ]
        detections = BeaconingDetector().detect(events, aggregate_features(events))
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["category"], "command_and_control")

    def test_dns_tunneling_detector_uses_entropy_and_nxdomain(self) -> None:
        names = [
            f"z9x8c7v6b5n4m3a2s1d0{i}qwertyuiopasdfghjkl.example.test"
            for i in range(12)
        ]
        events = [
            normalize_eve({
                "timestamp": f"2026-07-05T10:00:{i:02d}+00:00",
                "event_type": "dns",
                "src_ip": "192.168.10.70",
                "src_port": 53000 + i,
                "dest_ip": "192.168.10.1",
                "dest_port": 53,
                "proto": "UDP",
                "dns": {"rrname": name, "rrtype": "TXT", "rcode": "NXDOMAIN"},
            })
            for i, name in enumerate(names)
        ]
        features = aggregate_features(events)
        self.assertGreater(shannon_entropy(names[0].split(".")[0]), 3.0)
        detections = DNSTunnelingDetector().detect(events, features)
        self.assertEqual(len(detections), 1)

    def test_suricata_drop_event_is_imported_as_signature_detection(self) -> None:
        event = normalize_eve({
            "timestamp": "2026-07-05T12:21:17.149193+0200",
            "flow_id": 1485206591406768,
            "event_type": "drop",
            "src_ip": "13.89.125.229",
            "src_port": 56922,
            "dest_ip": "192.168.30.3",
            "dest_port": 443,
            "proto": "TCP",
            "drop": {"len": 52, "syn": True, "ack": False, "reason": "rules"},
            "alert": {
                "action": "blocked",
                "gid": 1,
                "signature_id": 2403313,
                "rev": 109952,
                "signature": "ET CINS Active Threat Intelligence Poor Reputation IP group 14",
                "category": "Misc Attack",
                "severity": 2,
            },
        })
        self.assertEqual(event["event_type"], "drop")
        self.assertEqual(event["metadata"]["drop_reason"], "rules")
        detection = [item for item in SuricataAlertAdapter().detect([event], []) if item["detector_id"] == "pondsec.suricata_drop"]
        self.assertEqual(len(detection), 1)
        self.assertEqual(detection[0]["evidence"]["suricata_action"], "blocked")

    def test_store_migration_inserts_events_and_dashboard_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            events = [normalize_eve(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.80", "198.51.100.80", 443))]
            self.assertEqual(store.insert_events(events), 1)
            summary = store.dashboard_summary()
            self.assertIn("metrics", summary)
            self.assertGreaterEqual(summary["metrics"]["events_last_24h"], 0)
            self.assertEqual(store.check()["status"], "ok")

    def test_correlation_creates_explainable_incident(self) -> None:
        events = [
            normalize_eve(flow_event(f"2026-07-05T10:00:{i:02d}+00:00", "192.168.10.90", "192.168.20.90", 20 + i))
            for i in range(15)
        ]
        detections = PortScanDetector().detect(events, aggregate_features(events))
        incidents = correlate_detections(detections)
        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0]["risk_factors"])

    def test_external_model_catalog_prefers_public_trained_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = model_inventory(Path(tmp))
            preferred = [item for item in inventory if item["preferred"]]
            self.assertEqual(preferred[0]["model_id"], "saidimn-ids-cnn-cicids2017")
            self.assertEqual(preferred[0]["license"].lower(), "mit")

    def test_cicids_feature_vector_has_expected_dimensions(self) -> None:
        feature = aggregate_features([
            normalize_eve(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.91", "198.51.100.91", 443))
        ])[0]
        vector = cicids_vector_from_feature(feature)
        self.assertEqual(len(vector), len(CICIDS2017_FEATURES))
        self.assertTrue(all(isinstance(value, float) for value in vector))

    def test_service_run_once_processes_synthetic_eve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text("\n".join(
                json.dumps(flow_event(f"2026-07-05T10:00:{i:02d}+00:00", "192.168.10.92", "192.168.20.92", 20 + i))
                for i in range(15)
            ) + "\n", encoding="utf-8")
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(eve),
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
            )
            service = PondSecService(config)
            result = service.run_once(max_lines=100)
            self.assertEqual(result["status"], "healthy")
            self.assertGreaterEqual(result["inserted_events"], 15)
            self.assertGreaterEqual(result["detections"], 1)

    def test_eve_access_status_checks_service_user_read_permission(self) -> None:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        with tempfile.TemporaryDirectory() as tmp:
            eve = Path(tmp) / "eve.json"
            eve.write_text(json.dumps(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.93", "198.51.100.93", 443)), encoding="utf-8")
            config = PondSecConfig(suricata_eve_path=str(eve))
            readable = eve_access_status(config, service_user=current_user)
            self.assertEqual(readable["status"], "ok")
            eve.chmod(0)
            unreadable = eve_access_status(config, service_user=current_user)
            self.assertEqual(unreadable["status"], "failed")
            self.assertFalse(unreadable["readable"])

    def test_eve_access_status_trusts_actual_service_user_probe_for_acls(self) -> None:
        current_user = pwd.getpwuid(os.getuid()).pw_name
        original_probe = diagnostics_mod._actual_read_probe
        original_ancestor = diagnostics_mod._ancestor_access
        try:
            diagnostics_mod._actual_read_probe = lambda _path, _user: {"attempted": True, "readable": True, "returncode": 0}
            diagnostics_mod._ancestor_access = lambda _path, _uid, _groups: {"ok": False, "path": str(_path)}
            status = diagnostics_mod.eve_access_status(PondSecConfig(suricata_eve_path="/var/log/suricata/eve.json"), service_user=current_user)
            self.assertEqual(status["status"], "ok")
            self.assertEqual(status["checked_by"], "service-user-probe")
        finally:
            diagnostics_mod._actual_read_probe = original_probe
            diagnostics_mod._ancestor_access = original_ancestor

    def test_response_engine_proposes_blocks_without_pf_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = {
                "incident_id": "incident-response-test",
                "title": "Response test",
                "status": "open",
                "risk_score": 80,
                "severity": 8,
                "confidence": 0.85,
                "source_ip": "192.168.10.200",
                "destination_ip": "1.1.1.1",
                "category": "command_and_control",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [{"name": "test", "value": 80}],
                "detection_ids": [],
            }
            store.insert_incidents([incident])
            config = PondSecConfig(response=ResponseConfig(minimum_risk_score=50, minimum_confidence=50))
            proposal = propose_block_for_incident(store, config, "incident-response-test", actor="test", duration_seconds=300)
            self.assertEqual(proposal["status"], "proposed")
            self.assertEqual(proposal["automatic"], 0)
            self.assertEqual(store.list_rows("block_entries")[0]["source_ip"], "192.168.10.200")

    def test_response_engine_activates_and_removes_pf_table_blocks(self) -> None:
        commands: list[list[str]] = []

        def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command == ["/sbin/pfctl", "-sr"]:
                return subprocess.CompletedProcess(command, 0, "block drop in quick from <virusprot> to any", "")
            return subprocess.CompletedProcess(command, 0, "1/1 addresses processed", "")

        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = {
                "incident_id": "incident-pf-test",
                "title": "PF response test",
                "status": "open",
                "risk_score": 90,
                "severity": 9,
                "confidence": 0.95,
                "source_ip": "203.0.113.250",
                "destination_ip": "192.168.30.3",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [{"name": "test", "value": 90}],
                "detection_ids": [],
            }
            store.insert_incidents([incident])
            config = PondSecConfig(response=ResponseConfig(minimum_risk_score=50, minimum_confidence=50))
            proposal = propose_block_for_incident(store, config, "incident-pf-test", actor="test", duration_seconds=300)
            enforcer = PFTableEnforcer(runner=fake_runner)
            activation = activate_block(store, config, proposal["block_id"], actor="test", enforcer=enforcer)
            self.assertEqual(activation["status"], "ok")
            self.assertEqual(store.get_block_entry(proposal["block_id"])["status"], "active")
            self.assertIn(["/sbin/pfctl", "-t", "virusprot", "-T", "add", "203.0.113.250"], commands)
            removal = remove_block(store, proposal["block_id"], "test cleanup", actor="test", enforcer=enforcer)
            self.assertEqual(removal["status"], "ok")
            self.assertIn(["/sbin/pfctl", "-t", "virusprot", "-T", "delete", "203.0.113.250"], commands)

    def test_response_engine_denies_allowlisted_and_protected_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = {
                "incident_id": "incident-allowlist-test",
                "title": "Allowlist test",
                "status": "open",
                "risk_score": 90,
                "severity": 9,
                "confidence": 0.95,
                "source_ip": "192.168.10.210",
                "destination_ip": "1.1.1.1",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [{"name": "test", "value": 90}],
                "detection_ids": [],
            }
            store.insert_incidents([incident])
            store.add_allowlist_entry("192.168.10.0/24", "admin network", actor="test")
            config = PondSecConfig(response=ResponseConfig(minimum_risk_score=50, minimum_confidence=50))
            with self.assertRaises(ResponseDenied):
                propose_block_for_incident(store, config, "incident-allowlist-test", actor="test")
            self.assertTrue(is_protected_target("127.0.0.1", config))


class CliTests(unittest.TestCase):
    def test_cli_config_validate_accepts_json_flag_after_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_env = dict()
            for key, value in {
                "PONDSEC_NDR_DATA_DIR": str(root / "db"),
                "PONDSEC_NDR_LOG_DIR": str(root / "log"),
                "PONDSEC_NDR_RUN_DIR": str(root / "run"),
                "PONDSEC_NDR_CONFIG": str(root / "missing.json"),
            }.items():
                old_env[key] = __import__("os").environ.get(key)
                __import__("os").environ[key] = value
            try:
                self.assertEqual(cli_main(["config", "validate", "--json"]), 0)
            finally:
                for key, value in old_env.items():
                    if value is None:
                        __import__("os").environ.pop(key, None)
                    else:
                        __import__("os").environ[key] = value

    def test_cli_allowlist_add_accepts_json_flag_after_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_env = dict()
            for key, value in {
                "PONDSEC_NDR_DATA_DIR": str(root / "db"),
                "PONDSEC_NDR_LOG_DIR": str(root / "log"),
                "PONDSEC_NDR_RUN_DIR": str(root / "run"),
                "PONDSEC_NDR_CONFIG": str(root / "missing.json"),
            }.items():
                old_env[key] = __import__("os").environ.get(key)
                __import__("os").environ[key] = value
            try:
                self.assertEqual(cli_main(["allowlist", "add", "192.168.10.0/24", "--json"]), 0)
                self.assertEqual(cli_main(["allowlist", "list", "--json"]), 0)
            finally:
                for key, value in old_env.items():
                    if value is None:
                        __import__("os").environ.pop(key, None)
                    else:
                        __import__("os").environ[key] = value


if __name__ == "__main__":
    unittest.main()
