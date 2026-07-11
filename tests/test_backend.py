from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import pondsec_ndr.diagnostics as diagnostics_mod
from pondsec_ndr.cli import _incident_analysis, main as cli_main
from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.collectors.filterlog import FilterLogCollector, FilterLogStats, normalize_filterlog_line
from pondsec_ndr.config import DetectionConfig, PondSecConfig, ResponseConfig
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import BeaconingDetector, DNSTunnelingDetector, PortScanDetector, SuricataAlertAdapter
from pondsec_ndr.diagnostics import diagnostic_archive, eve_access_status
from pondsec_ndr.features.aggregator import aggregate_features, shannon_entropy
from pondsec_ndr.models.cicids_features import CICIDS2017_FEATURES, cicids_vector_from_feature
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.normalizers.suricata import normalize_eve
from pondsec_ndr.privacy import export_privacy_bundle, purge_telemetry_before
from pondsec_ndr.response.engine import ResponseDenied, activate_block, is_protected_target, propose_block_for_incident, propose_manual_block, remove_block
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.sensor import eve_types_from_suricata_yaml, patch_suricata_yaml_text, required_eve_types
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

    def test_filterlog_block_lines_feed_portscan_detection(self) -> None:
        def filterlog_line(port: int) -> str:
            return (
                "<134>1 2026-07-05T23:35:53+02:00 HWFirewall01.internal filterlog 92957 - "
                "[meta sequenceId=\"127149\"] "
                f"161,,,caea0fd1aafabc0f78ce7311d238342c,igb0_vlan10,match,block,in,4,0x0,,255,0,0,DF,6,tcp,64,"
                f"192.168.10.20,192.168.30.3,65393,{port},0,SEC"
            )

        event = normalize_filterlog_line(filterlog_line(202))
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["raw_source"], "opnsense_filterlog")
        self.assertEqual(event["source"]["interface"], "igb0_vlan10")
        self.assertEqual(event["destination"]["port"], 202)
        self.assertEqual(event["metadata"]["flow_reason"], "reject")

        events = [normalize_filterlog_line(filterlog_line(20 + index)) for index in range(15)]
        normalized = [event for event in events if event is not None]
        features = aggregate_features(normalized)
        detections = PortScanDetector().detect(normalized, features)
        self.assertTrue(any(item["detector_id"] == "pondsec.portscan" for item in detections))

    def test_filterlog_collector_starts_at_end_and_tracks_new_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "filter.log"
            offset = root / "offset.json"
            log.write_text(
                "<134>1 2026-07-05T23:35:53+02:00 HWFirewall01.internal filterlog 92957 - "
                "[meta sequenceId=\"1\"] "
                "161,,,tracker,igb0_vlan10,match,block,in,4,0x0,,255,0,0,DF,6,tcp,64,"
                "192.168.10.20,192.168.30.3,65393,22,0,SEC\n",
                encoding="utf-8",
            )
            events, stats = FilterLogCollector(log, offset).read_once(max_lines=100)
            self.assertEqual(events, [])
            self.assertEqual(stats.read_lines, 0)

            with log.open("a", encoding="utf-8") as handle:
                handle.write(
                    "<134>1 2026-07-05T23:35:54+02:00 HWFirewall01.internal filterlog 92957 - "
                    "[meta sequenceId=\"2\"] "
                    "161,,,tracker,igb0_vlan10,match,block,in,4,0x0,,255,0,0,DF,6,tcp,64,"
                    "192.168.10.20,192.168.30.3,65394,23,0,SEC\n"
                )
            events, stats = FilterLogCollector(log, offset).read_once(max_lines=100)
            self.assertEqual(len(events), 1)
            self.assertEqual(stats.accepted_events, 1)

    def test_service_run_once_tolerates_unreadable_filterlog(self) -> None:
        class DeniedFilterLogCollector:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def read_once(self, max_lines: int = 1000) -> tuple[list[dict], FilterLogStats]:
                del max_lines
                return [], FilterLogStats(last_error="filter log is not readable by pondsec-ndr: /var/log/filter/latest.log")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text("", encoding="utf-8")
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(eve),
                data_dir=root / "data",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(machine_learning=False),
            )
            service = PondSecService(config)
            with patch("pondsec_ndr.service.FilterLogCollector", DeniedFilterLogCollector):
                result = service.run_once(max_lines=100)
            self.assertEqual(result["status"], "healthy")
            self.assertIn("filter log is not readable", result["collector"]["opnsense_filterlog"]["last_error"])
            self.assertIn("filter log is not readable", result["optional_collector_warnings"][0])

    def test_filterlog_short_lines_are_ignored_without_parser_error(self) -> None:
        line = (
            "<134>1 2026-07-05T23:35:53+02:00 HWFirewall01.internal filterlog 92957 - "
            "[meta sequenceId=\"127149\"] 161,,,tracker,igb0_vlan10,match,block,in,4"
        )
        self.assertIsNone(normalize_filterlog_line(line))

    def test_filterlog_pass_lines_are_not_ingested(self) -> None:
        line = (
            "<134>1 2026-07-05T23:48:21+02:00 HWFirewall01.internal filterlog 92957 - "
            "[meta sequenceId=\"130536\"] "
            "157,,,tracker,igb0_vlan10,match,pass,in,4,0x2,0,64,0,0,DF,17,udp,1228,"
            "192.168.10.128,17.248.213.70,53202,443,1208"
        )
        self.assertIsNone(normalize_filterlog_line(line))

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

    def test_store_migration_upgrades_legacy_incidents_before_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "pondsec-ndr.db"
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        severity INTEGER NOT NULL,
                        confidence REAL NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        category TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        risk_factors_json TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO incidents(
                        incident_id, title, status, risk_score, severity,
                        confidence, source_ip, destination_ip, category,
                        created_at, updated_at, evidence_json, risk_factors_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "legacy-incident-1",
                        "Legacy incident",
                        "open",
                        80,
                        8,
                        0.9,
                        "192.168.10.77",
                        "192.168.20.10",
                        "reconnaissance",
                        "2026-07-05T10:00:00+00:00",
                        "2026-07-05T10:02:00+00:00",
                        json.dumps({"validation": {"scenario": "legacy-upgrade"}}),
                        "[]",
                    ),
                )

            store = EventStore(db_path)
            store.migrate()

            with sqlite3.connect(db_path) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
                indexes = {row[1] for row in conn.execute("PRAGMA index_list(incidents)").fetchall()}
                row = conn.execute(
                    """
                    SELECT first_seen, last_seen, event_count, detection_count,
                           affected_targets_json, attack_stage, validation_tag,
                           suppressed_count
                    FROM incidents WHERE incident_id = ?
                    """,
                    ("legacy-incident-1",),
                ).fetchone()
                version = conn.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            self.assertIn("validation_tag", columns)
            self.assertIn("idx_incidents_dedupe", indexes)
            self.assertEqual(row[0], "2026-07-05T10:00:00+00:00")
            self.assertEqual(row[1], "2026-07-05T10:02:00+00:00")
            self.assertEqual(row[2], 1)
            self.assertEqual(row[3], 0)
            self.assertEqual(json.loads(row[4]), ["192.168.20.10"])
            self.assertEqual(row[5], "reconnaissance")
            self.assertEqual(row[6], "legacy-upgrade")
            self.assertEqual(row[7], 0)
            self.assertEqual(version, 2)
            self.assertTrue(any((db_path.parent / "backups").glob("pondsec-ndr.db.schema0-to-2.*.bak")))

    def test_store_canonicalizes_structured_tls_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            event = normalize_eve({
                "timestamp": "2026-07-05T10:00:00+00:00",
                "event_type": "tls",
                "src_ip": "192.168.10.81",
                "src_port": 51515,
                "dest_ip": "203.0.113.81",
                "dest_port": 443,
                "proto": "TCP",
                "tls": {
                    "sni": "example.test",
                    "ja3": {"hash": "abc123", "string": "771,4865-4866"},
                },
            })
            self.assertEqual(store.insert_events([event]), 1)
            host = store.list_rows("hosts")[0]
            fingerprints = json.loads(host["known_tls_fingerprints_json"])
            self.assertEqual(fingerprints, ['{"hash":"abc123","string":"771,4865-4866"}'])

    def test_privacy_export_anonymizes_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.insert_events([
                normalize_eve(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.51", "198.51.100.51", 443))
            ])
            output = root / "privacy-export.json"
            result = export_privacy_bundle(PondSecConfig(data_dir=root), store, output, anonymize=True, include_events=True)
            self.assertEqual(result["status"], "ok")
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("192.168.10.51", text)
            self.assertNotIn("198.51.100.51", text)
            self.assertIn("anon-ip4", text)

    def test_privacy_purge_deletes_old_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_events([
                normalize_eve(flow_event("2020-01-01T10:00:00+00:00", "192.168.10.52", "198.51.100.52", 443))
            ])
            result = purge_telemetry_before(store, older_than_days=1)
            self.assertEqual(result["status"], "ok")
            self.assertEqual(store.list_rows("events"), [])

    def test_diagnostic_archive_excludes_sensitive_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            output = root / "diagnostics.tar.gz"
            result = diagnostic_archive(PondSecConfig(data_dir=root), store, output)
            self.assertEqual(result["status"], "ok")
            self.assertTrue(output.exists())
            self.assertFalse(result["sensitive_payloads_included"])

    def test_correlation_creates_explainable_incident(self) -> None:
        events = [
            normalize_eve(flow_event(f"2026-07-05T10:00:{i:02d}+00:00", "192.168.10.90", "192.168.20.90", 20 + i))
            for i in range(15)
        ]
        detections = PortScanDetector().detect(events, aggregate_features(events))
        incidents = correlate_detections(detections)
        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0]["risk_factors"])
        explanation = detections[0]["evidence"]["explainability"]
        self.assertIn("why", explanation)
        self.assertTrue(explanation["thresholds_exceeded"])
        self.assertTrue(explanation["administrator_guidance"])

    def test_incident_analysis_builds_threat_graph_and_stage_view(self) -> None:
        incident = {
            "incident_id": "incident-analysis-1",
            "title": "Possible C2",
            "status": "open",
            "risk_score": 82,
            "severity": 8,
            "confidence": 0.91,
            "source_ip": "192.168.10.50",
            "destination_ip": "203.0.113.50",
            "category": "command_and_control",
            "created_at": "2026-07-05T10:00:00+00:00",
            "updated_at": "2026-07-05T10:10:00+00:00",
            "first_seen": "2026-07-05T10:00:00+00:00",
            "last_seen": "2026-07-05T10:10:00+00:00",
            "event_count": 6,
            "detection_count": 1,
            "suppressed_count": 0,
            "affected_targets": ["203.0.113.50"],
            "attack_stage": "command_and_control",
            "evidence": {
                "correlation": {"deduplicated": True},
                "detections": [{
                    "detection_id": "d-c2",
                    "detector_id": "pondsec.beaconing",
                    "title": "Possible command-and-control beaconing",
                    "category": "command_and_control",
                    "timestamp": "2026-07-05T10:00:00+00:00",
                    "source_ip": "192.168.10.50",
                    "destination_ip": "203.0.113.50",
                    "severity": 8,
                    "confidence": 0.91,
                    "anomaly_score": 0.9,
                    "description": "Connections recur at regular intervals.",
                    "evidence": {"port": 443, "explainability": {"administrator_guidance": ["Check endpoint process tree."]}},
                }],
            },
            "risk_factors": [{"name": "confidence", "value": 18}],
        }
        analysis = _incident_analysis(incident, {"status": "active", "risk_score": 82, "confidence": 0.91, "created_at": "2026-07-05T10:11:00+00:00"})
        self.assertIn("attack_graph", analysis)
        self.assertGreaterEqual(len(analysis["attack_graph"]["nodes"]), 3)
        self.assertTrue(any(edge["kind"] == "command_and_control" for edge in analysis["attack_graph"]["edges"]))
        self.assertTrue(any(stage["stage"] == "response" and stage["status"] == "prevented" for stage in analysis["attack_stages"]))
        self.assertEqual(analysis["visual_timeline"][0]["count"], 1)
        self.assertEqual(analysis["case_summary"]["response"]["status"], "active")

    def test_cross_category_correlation_builds_one_multistage_case_with_roles_and_cve_context(self) -> None:
        detections = [
            {
                "detection_id": "d-stage-scan",
                "detector_id": "pondsec.vertical_scan",
                "detector_version": "1",
                "category": "reconnaissance",
                "title": "External scan",
                "description": "External actor scanned the DMZ host.",
                "timestamp": "2026-07-05T10:00:00+00:00",
                "source_ip": "199.45.155.75",
                "destination_ip": "192.168.30.3",
                "severity": 7,
                "confidence": 0.86,
                "anomaly_score": 0.7,
                "evidence": {"ports": [80, 443, 8443]},
                "recommended_action": "Investigate",
            },
            {
                "detection_id": "d-stage-exploit",
                "detector_id": "pondsec.suricata_alert",
                "detector_version": "1",
                "category": "signature",
                "title": "Exploit attempt CVE-2024-12345",
                "description": "Suricata observed an exploit attempt.",
                "timestamp": "2026-07-05T10:02:00+00:00",
                "source_ip": "199.45.155.75",
                "destination_ip": "192.168.30.3",
                "severity": 9,
                "confidence": 0.94,
                "anomaly_score": 0.8,
                "evidence": {
                    "signature_id": 900001,
                    "references": ["cve,CVE-2024-12345"],
                    "product": "example-web",
                    "version": "1.2.3",
                    "ports": [443],
                },
                "recommended_action": "Patch and investigate",
            },
            {
                "detection_id": "d-stage-anomaly",
                "detector_id": "pondsec.host_baseline_anomaly",
                "detector_version": "1",
                "category": "anomaly",
                "title": "Host baseline anomaly",
                "description": "The DMZ host deviated from baseline.",
                "timestamp": "2026-07-05T10:08:00+00:00",
                "source_ip": "192.168.30.3",
                "destination_ip": "192.168.20.115",
                "severity": 8,
                "confidence": 0.82,
                "anomaly_score": 0.9,
                "evidence": {"baseline_deviation": 7.4},
                "recommended_action": "Check host process tree",
            },
            {
                "detection_id": "d-stage-c2",
                "detector_id": "pondsec.beaconing",
                "detector_version": "1",
                "category": "command_and_control",
                "title": "Outbound beaconing",
                "description": "The DMZ host contacted an external destination periodically.",
                "timestamp": "2026-07-05T10:15:00+00:00",
                "source_ip": "192.168.30.3",
                "destination_ip": "8.8.8.8",
                "severity": 8,
                "confidence": 0.88,
                "anomaly_score": 0.8,
                "evidence": {"ports": [443]},
                "recommended_action": "Contain if confirmed",
            },
        ]
        incidents = correlate_detections(detections, window_seconds=1800)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["category"], "multi_stage")
        self.assertEqual(incident["evidence"]["entity_roles"]["external_actor"], "199.45.155.75")
        self.assertEqual(incident["evidence"]["entity_roles"]["victim"], "192.168.30.3")
        self.assertEqual(incident["evidence"]["entity_roles"]["affected_host"], "192.168.30.3")
        self.assertIn("command_and_control", incident["evidence"]["correlation"]["categories"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            intel = root / "intel"
            intel.mkdir(parents=True)
            (intel / "nvd_cve_cache.json").write_text(json.dumps({
                "CVE-2024-12345": {
                    "descriptions": [{"lang": "en", "value": "Example product vulnerability."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                }
            }), encoding="utf-8")
            (intel / "cisa_kev.json").write_text(json.dumps({
                "vulnerabilities": [{
                    "cveID": "CVE-2024-12345",
                    "vendorProject": "Example",
                    "product": "example-web",
                    "requiredAction": "Apply vendor mitigation.",
                }]
            }), encoding="utf-8")
            (intel / "epss_cache.json").write_text(json.dumps({
                "data": [{"cve": "CVE-2024-12345", "epss": "0.92", "percentile": "0.99"}]
            }), encoding="utf-8")
            analysis = _incident_analysis(incident, config=PondSecConfig(data_dir=root))
        stages = {item["stage"]: item for item in analysis["attack_stages"]}
        self.assertEqual(stages["initial_access"]["status"], "observed")
        self.assertNotEqual(stages["initial_access"]["status"], "confirmed")
        self.assertEqual(analysis["case_summary"]["affected_host"], "192.168.30.3")
        self.assertTrue(analysis["threat_intelligence"]["cves"])
        self.assertEqual(analysis["threat_intelligence"]["cves"][0]["evidence_level"], "exploitation_attempt_observed")
        self.assertFalse(analysis["threat_intelligence"]["cves"][0]["automatic_block_basis_allowed"])

    def test_incident_analysis_infers_entity_roles_for_legacy_case_without_saved_roles(self) -> None:
        incident = {
            "incident_id": "legacy-case",
            "title": "Legacy multi-stage case",
            "status": "open",
            "risk_score": 91,
            "severity": 9,
            "confidence": 0.9,
            "source_ip": "199.45.155.75",
            "destination_ip": "192.168.30.3",
            "category": "multi_stage",
            "created_at": "2026-07-05T10:00:00+00:00",
            "updated_at": "2026-07-05T10:05:00+00:00",
            "first_seen": "2026-07-05T10:00:00+00:00",
            "last_seen": "2026-07-05T10:05:00+00:00",
            "event_count": 2,
            "detection_count": 2,
            "affected_targets": ["192.168.30.3"],
            "attack_stage": "multi_stage",
            "evidence": {"detections": [
                {
                    "detection_id": "legacy-scan",
                    "detector_id": "pondsec.vertical_scan",
                    "category": "reconnaissance",
                    "timestamp": "2026-07-05T10:00:00+00:00",
                    "source_ip": "199.45.155.75",
                    "destination_ip": "192.168.30.3",
                    "severity": 7,
                    "confidence": 0.8,
                    "anomaly_score": 0.7,
                    "title": "Scan",
                    "description": "Scan",
                    "evidence": {},
                }
            ]},
            "risk_factors": [],
        }
        analysis = _incident_analysis(incident)
        self.assertEqual(analysis["entity_roles"]["external_actor"], "199.45.155.75")
        self.assertEqual(analysis["entity_roles"]["victim"], "192.168.30.3")
        self.assertEqual(analysis["case_summary"]["affected_host"], "192.168.30.3")

    def test_incident_dedup_merges_same_source_category_target_network_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            first = {
                "incident_id": "incident-dedupe-1",
                "title": "First scan",
                "status": "open",
                "risk_score": 80,
                "severity": 8,
                "confidence": 0.9,
                "source_ip": "192.168.10.77",
                "destination_ip": "192.168.20.10",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "first_seen": "2026-07-05T10:00:00+00:00",
                "last_seen": "2026-07-05T10:00:20+00:00",
                "event_count": 15,
                "evidence": {"detections": [{"detection_id": "d1", "destination_ip": "192.168.20.10"}]},
                "risk_factors": [{"name": "scan", "value": 80}],
                "detection_ids": ["d1"],
            }
            second = dict(
                first,
                incident_id="incident-dedupe-2",
                title="Second scan",
                destination_ip="192.168.20.42",
                created_at="2026-07-05T10:30:00+00:00",
                updated_at="2026-07-05T10:30:00+00:00",
                first_seen="2026-07-05T10:30:00+00:00",
                last_seen="2026-07-05T10:30:10+00:00",
                event_count=9,
                detection_ids=["d2"],
                evidence={"detections": [{"detection_id": "d2", "destination_ip": "192.168.20.42"}]},
            )
            self.assertEqual(store.insert_incidents([first]), 1)
            self.assertEqual(store.insert_incidents([second]), 0)
            self.assertEqual(second["incident_id"], "incident-dedupe-1")
            rows = store.list_rows("incidents")
            self.assertEqual(len(rows), 1)
            merged = store.get_incident("incident-dedupe-1")
            self.assertIsNotNone(merged)
            assert merged is not None
            self.assertEqual(merged["event_count"], 24)
            self.assertEqual(merged["detection_count"], 2)
            self.assertEqual(merged["suppressed_count"], 1)
            self.assertEqual(sorted(merged["affected_targets"]), ["192.168.20.10", "192.168.20.42"])
            self.assertTrue(merged["evidence"]["correlation"]["deduplicated"])

    def test_incident_dedup_merges_cross_category_related_entities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            first = {
                "incident_id": "incident-cross-1",
                "title": "External scan",
                "status": "open",
                "risk_score": 82,
                "severity": 8,
                "confidence": 0.9,
                "source_ip": "199.45.155.75",
                "destination_ip": "192.168.30.3",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "first_seen": "2026-07-05T10:00:00+00:00",
                "last_seen": "2026-07-05T10:01:00+00:00",
                "event_count": 12,
                "evidence": {"entity_roles": {"external_actor": "199.45.155.75", "victim": "192.168.30.3"}, "detections": [{"detection_id": "d1", "destination_ip": "192.168.30.3"}]},
                "risk_factors": [{"name": "scan", "value": 80}],
                "detection_ids": ["d1"],
            }
            second = dict(
                first,
                incident_id="incident-cross-2",
                title="Outbound beacon",
                source_ip="192.168.30.3",
                destination_ip="8.8.8.8",
                category="command_and_control",
                created_at="2026-07-05T10:20:00+00:00",
                updated_at="2026-07-05T10:20:00+00:00",
                first_seen="2026-07-05T10:20:00+00:00",
                last_seen="2026-07-05T10:20:10+00:00",
                evidence={"entity_roles": {"affected_host": "192.168.30.3", "destination": "8.8.8.8"}, "detections": [{"detection_id": "d2", "source_ip": "192.168.30.3", "destination_ip": "8.8.8.8"}]},
                detection_ids=["d2"],
            )
            self.assertEqual(store.insert_incidents([first]), 1)
            self.assertEqual(store.insert_incidents([second]), 0)
            merged = store.get_incident("incident-cross-1")
            self.assertIsNotNone(merged)
            assert merged is not None
            self.assertEqual(merged["category"], "multi_stage")
            self.assertEqual(merged["attack_stage"], "multi_stage")
            self.assertTrue(merged["evidence"]["correlation"]["deduplicated"])

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

    def test_service_run_once_applies_queue_backpressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text("\n".join(
                json.dumps(flow_event(f"2026-07-05T10:00:{i:02d}+00:00", "192.168.10.94", "192.168.20.94", 1000 + i))
                for i in range(20)
            ) + "\n", encoding="utf-8")
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(eve),
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                max_queue_length=5,
            )
            service = PondSecService(config)
            result = service.run_once(max_lines=100)
            self.assertEqual(result["status"], "degraded")
            self.assertLessEqual(result["inserted_events"], 5)
            self.assertTrue(result["resource_warnings"] == [] or isinstance(result["resource_warnings"], list))

    def test_service_persists_learning_started_at_from_existing_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "db"
            store = EventStore(data_dir / "pondsec-ndr.db")
            store.migrate()
            with store.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO events(
                        event_id, schema_version, event_type, timestamp,
                        source_ip, source_port, source_interface,
                        destination_ip, destination_port, protocol,
                        direction, metadata_json, raw_source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "learning-start-event",
                        1,
                        "flow",
                        "2026-07-01T09:00:00+00:00",
                        "192.168.10.44",
                        51044,
                        "igb0_vlan10",
                        "198.51.100.44",
                        443,
                        "TCP",
                        "egress",
                        "{}",
                        "suricata_eve",
                    ),
                )
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(root / "eve.json"),
                data_dir=data_dir,
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(machine_learning=True, learning_mode=True, learning_days=14),
            )
            service = PondSecService(config)
            self.assertTrue(service.config.detection.learning_started_at.startswith("2026-07-01T09:00:00"))
            self.assertTrue((data_dir / "learning_started_at").exists())

    def test_short_cpu_burst_does_not_raise_resource_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(data_dir=root / "db", log_dir=root / "log", run_dir=root / "run")
            service = PondSecService(config)
            self.assertEqual(
                service._resource_warnings({"inference_and_detection_wall_ms": 120, "cpu_percent": 99, "rss_mb": 32}),
                [],
            )
            self.assertIn(
                "cpu_warning_threshold_exceeded",
                service._resource_warnings({"inference_and_detection_wall_ms": 2000, "cpu_percent": 99, "rss_mb": 32}),
            )

    def test_service_learning_mode_suppresses_ai_baseline_incidents_until_override(self) -> None:
        def anomaly_raw_event() -> dict:
            return {
                "timestamp": "2026-07-05T10:01:00+00:00",
                "event_type": "flow",
                "src_ip": "192.168.10.250",
                "src_port": 52001,
                "dest_ip": "198.51.100.250",
                "dest_port": 443,
                "proto": "TCP",
                "flow": {
                    "state": "closed",
                    "reason": "finished",
                    "age": 1,
                    "pkts_toserver": 3,
                    "pkts_toclient": 1,
                    "bytes_toserver": 1000,
                    "bytes_toclient": 100,
                },
            }

        def seed_baseline(service: PondSecService) -> None:
            normal = [{
                "feature_version": "1",
                "source_ip": "192.168.10.250",
                "bytes_out": 100.0,
                "upload_download_ratio": 1.0,
                "connections_60s": 1.0,
                "external_connections": 1.0,
                "destination_count": 1.0,
                "port_count": 1.0,
                "dns_entropy": 0.0,
                "dns_name_length": 0.0,
                "internal_connections": 0.0,
            }]
            for _ in range(3):
                service.store.update_host_baselines(normal)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text(json.dumps(anomaly_raw_event()) + "\n", encoding="utf-8")
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(eve),
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(machine_learning=True, learning_mode=True, minimum_observations=3),
            )
            service = PondSecService(config)
            seed_baseline(service)
            result = service.run_once(max_lines=10)
            self.assertEqual(result["detections"], 0)
            self.assertIn("pondsec.host_baseline_anomaly", result["learning_suppressed_detectors"])
            self.assertEqual(result["learning_status"]["status"], "learning")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text(json.dumps(anomaly_raw_event()) + "\n", encoding="utf-8")
            config = PondSecConfig(
                enabled=True,
                suricata_eve_path=str(eve),
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(
                    machine_learning=True,
                    learning_mode=True,
                    early_ai_activation_override=True,
                    minimum_observations=3,
                ),
            )
            service = PondSecService(config)
            seed_baseline(service)
            result = service.run_once(max_lines=10)
            self.assertGreaterEqual(result["detections"], 1)
            self.assertEqual(result["learning_status"]["status"], "override")

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

    def test_response_engine_adds_manual_block_proposal_without_pf_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            config = PondSecConfig(response=ResponseConfig(default_block_seconds=300, minimum_risk_score=70))
            proposal = propose_manual_block(store, config, "203.0.113.44", reason="manual test", actor="test")
            self.assertEqual(proposal["status"], "proposed")
            self.assertEqual(proposal["source_ip"], "203.0.113.44")
            self.assertEqual(proposal["policy_id"], "manual")
            self.assertEqual(store.list_rows("block_entries")[0]["status"], "proposed")

    def test_response_engine_reuses_existing_active_source_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            now = "2026-07-05T10:00:00+00:00"
            config = PondSecConfig(response=ResponseConfig(minimum_risk_score=50, minimum_confidence=50))
            first = {
                "incident_id": "incident-source-reuse-1",
                "title": "First incident",
                "status": "open",
                "risk_score": 90,
                "severity": 9,
                "confidence": 0.95,
                "source_ip": "203.0.113.201",
                "destination_ip": "192.168.30.3",
                "category": "reconnaissance",
                "created_at": now,
                "updated_at": now,
                "evidence": {},
                "risk_factors": [{"name": "test", "value": 90}],
                "detection_ids": [],
            }
            second = dict(
                first,
                incident_id="incident-source-reuse-2",
                title="Second incident",
                category="command_and_control",
                created_at="2026-07-05T11:00:00+00:00",
                updated_at="2026-07-05T11:00:00+00:00",
                first_seen="2026-07-05T11:00:00+00:00",
                last_seen="2026-07-05T11:00:10+00:00",
            )
            store.insert_incidents([first, second])
            proposal = propose_block_for_incident(store, config, "incident-source-reuse-1", actor="test")
            store.update_block_status(proposal["block_id"], "active", actor="test")
            reused = propose_block_for_incident(store, config, "incident-source-reuse-2", actor="test")
            self.assertEqual(reused["block_id"], proposal["block_id"])
            self.assertEqual(len(store.list_rows("block_entries")), 1)

    def test_blocklist_view_hides_removed_duplicate_when_current_block_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident_id = "incident-block-duplicate"
            active = store.add_block_entry({
                "block_id": "block-active",
                "incident_id": incident_id,
                "source_ip": "199.45.155.75",
                "destination": "192.168.30.3",
                "reason": "Response proposal",
                "risk_score": 91,
                "confidence": 0.9,
                "expires_at": "2030-01-01T00:00:00+00:00",
                "status": "active",
            }, actor="test")
            removed = store.add_block_entry({
                "block_id": "block-removed",
                "incident_id": incident_id,
                "source_ip": "199.45.155.75",
                "destination": "192.168.30.3",
                "reason": "Older response proposal",
                "risk_score": 91,
                "confidence": 0.9,
                "expires_at": "2030-01-01T00:00:00+00:00",
                "status": "removed",
                "removal_reason": "manual cleanup",
            }, actor="test")
            view = store.blocklist_view()
            self.assertIn(active["block_id"], {item["block_id"] for item in view["items"]})
            self.assertNotIn(removed["block_id"], {item["block_id"] for item in view["items"]})
            self.assertEqual(view["summary"]["hidden_historical_duplicates"], 1)

    def test_service_auto_response_skips_baseline_only_anomaly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                enabled=True,
                mode="prevent",
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                response=ResponseConfig(automatic_blocking=True, manual_confirmation=False, isolate_internal=True),
            )
            service = PondSecService(config)
            incident = {
                "incident_id": "baseline-only-incident",
                "source_ip": "192.168.20.115",
                "risk_score": 90,
                "confidence": 0.95,
                "evidence": {"detections": [{"detector_id": "pondsec.host_baseline_anomaly"}]},
            }
            actions = service._auto_response([incident])
            self.assertEqual(actions[0]["status"], "skipped")
            self.assertEqual(service.store.list_rows("block_entries"), [])

    def test_service_expected_response_denials_do_not_pollute_error_state(self) -> None:
        self.assertTrue(PondSecService._is_expected_response_denial("source IP is protected"))
        self.assertTrue(PondSecService._is_expected_response_denial("incident risk score is below response threshold"))
        self.assertFalse(PondSecService._is_expected_response_denial("PF table add failed: permission denied"))

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

    def test_pf_enforcer_falls_back_to_configd_on_permission_denied(self) -> None:
        commands: list[list[str]] = []

        def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[:2] == ["/sbin/pfctl", "-t"]:
                return subprocess.CompletedProcess(command, 1, "", "pfctl: /dev/pf: Permission denied")
            if command[:3] == ["/usr/local/sbin/configctl", "pondsecndr", "pf_table"]:
                payload = {
                    "status": "ok",
                    "pf_result": {
                        "table": "virusprot",
                        "target": "203.0.113.9",
                        "command": command[3],
                        "returncode": 0,
                        "stdout": "1/1 addresses processed",
                        "stderr": "",
                        "ok": True,
                    },
                }
                return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
            return subprocess.CompletedProcess(command, 1, "", "unexpected command")

        result = PFTableEnforcer(runner=fake_runner).add("203.0.113.9")
        self.assertTrue(result.ok)
        self.assertEqual(result.command, "configctl:add")
        self.assertIn(["/usr/local/sbin/configctl", "pondsecndr", "pf_table", "add", "203.0.113.9"], commands)

    def test_pf_enforcer_treats_configd_execute_error_as_failure(self) -> None:
        def fake_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["/sbin/pfctl", "-t"]:
                return subprocess.CompletedProcess(command, 1, "", "pfctl: /dev/pf: Permission denied")
            return subprocess.CompletedProcess(command, 0, "Execute error", "")

        result = PFTableEnforcer(runner=fake_runner).test("203.0.113.10")
        self.assertFalse(result.ok)
        self.assertEqual(result.command, "configctl:test")
        self.assertEqual(result.returncode, 1)

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

    def test_sensor_patch_adds_flow_and_dns_to_first_eve_log(self) -> None:
        original = """outputs:
  - eve-log:
      enabled: yes
      types:
        - alert:
             tagged-packets: yes
        - drop:
            alerts: yes

  - stats:
      enabled: yes
"""
        patched, changed, added = patch_suricata_yaml_text(original, ["alert", "drop", "flow", "dns"])
        self.assertTrue(changed)
        self.assertEqual(added, ["flow", "dns"])
        self.assertEqual(eve_types_from_suricata_yaml(patched)[:4], ["flow", "dns", "alert", "drop"])
        patched_again, changed_again, added_again = patch_suricata_yaml_text(patched, ["alert", "drop", "flow", "dns"])
        self.assertFalse(changed_again)
        self.assertEqual(added_again, [])
        self.assertEqual(patched_again, patched)

    def test_required_eve_types_include_behavior_and_metadata_sources(self) -> None:
        config = PondSecConfig()
        self.assertEqual(required_eve_types(config), ["alert", "drop", "flow", "dns", "http", "tls"])


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
