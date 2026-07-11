from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
import pwd
import sqlite3
import struct
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import pondsec_ndr.diagnostics as diagnostics_mod
from pondsec_ndr.cli import _incident_analysis, main as cli_main, reset_runtime_state
from pondsec_ndr.collectors.dnsmasq import DnsmasqCollector, normalize_dnsmasq_lease, normalize_dnsmasq_line
from pondsec_ndr.collectors.eve import EveCollector
from pondsec_ndr.collectors.filterlog import FilterLogCollector, FilterLogStats, normalize_filterlog_line
from pondsec_ndr.collectors.netflow import NETFLOW_V5_HEADER, NETFLOW_V5_RECORD, NetFlowCollector
from pondsec_ndr.collectors.zeek import ZeekLogCollector, normalize_zeek_row
from pondsec_ndr.collectors.zenarmor import ZenarmorCollector, ZenarmorSyslogCollector, normalize_zenarmor_event, parse_zenarmor_line
from pondsec_ndr.config import DetectionConfig, DnsmasqConfig, InterfaceConfig, PondSecConfig, ResponseConfig, ZeekConfig, ZenarmorConfig, load_config
from pondsec_ndr.correlation import correlate_detections
from pondsec_ndr.detection.detectors import BeaconingDetector, DNSTunnelingDetector, PortScanDetector, SuricataAlertAdapter
from pondsec_ndr.diagnostics import diagnostic_archive, diagnostics as diagnostics_payload, eve_access_status
from pondsec_ndr.features.aggregator import aggregate_features, shannon_entropy
from pondsec_ndr.models.cicids_features import CICIDS2017_FEATURES, cicids_vector_from_feature
from pondsec_ndr.models.manager import model_inventory
from pondsec_ndr.models.runtime import SaidimnIdsCnnRuntime
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


def ipv4_int(value: str) -> int:
    parts = [int(part) for part in value.split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def netflow_v5_datagram(sequence: int = 100) -> bytes:
    header = NETFLOW_V5_HEADER.pack(5, 1, 123456, 1783260000, 0, sequence, 0, 0, 1)
    record = NETFLOW_V5_RECORD.pack(
        ipv4_int("10.10.10.20"),
        ipv4_int("8.8.8.8"),
        0,
        10,
        20,
        12,
        2400,
        1000,
        2000,
        51515,
        443,
        0,
        0x12,
        6,
        0,
        64512,
        15169,
        24,
        24,
        0,
    )
    return header + record


def seed_host_baseline(store: EventStore, host_ip: str, observations: int = 100) -> None:
    with store.connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO host_baselines(host_ip, observation_count, first_observation, last_observation, baseline_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                host_ip,
                observations,
                "2026-07-01T00:00:00+00:00",
                "2026-07-05T10:00:00+00:00",
                json.dumps({"connections_60s": 5, "bytes_out": 1000}, sort_keys=True),
            ),
        )


def robust_internal_incident(incident_id: str = "incident-robust-internal", source_ip: str = "192.168.30.3") -> dict:
    return {
        "incident_id": incident_id,
        "title": "Corroborated internal compromise behavior",
        "status": "open",
        "risk_score": 97,
        "severity": 10,
        "confidence": 0.97,
        "source_ip": "8.8.4.4",
        "destination_ip": source_ip,
        "category": "multi_stage",
        "created_at": "2026-07-05T10:00:00+00:00",
        "updated_at": "2026-07-05T10:20:00+00:00",
        "event_count": 6,
        "detection_count": 4,
        "evidence": {
            "entity_roles": {
                "external_actor": "8.8.4.4",
                "victim": source_ip,
                "affected_host": source_ip,
                "response_target": "8.8.4.4",
            },
            "detections": [
                {
                    "detection_id": "d-internal-beacon",
                    "detector_id": "pondsec.beaconing",
                    "category": "command_and_control",
                    "source_ip": source_ip,
                    "destination_ip": "1.1.1.1",
                    "severity": 9,
                    "confidence": 0.96,
                    "title": "Outbound beaconing",
                    "evidence": {"periodicity": 0.94, "raw_sources": ["suricata_eve"]},
                },
                {
                    "detection_id": "d-internal-dns",
                    "detector_id": "pondsec.dns_tunneling",
                    "category": "command_and_control",
                    "source_ip": source_ip,
                    "destination_ip": "9.9.9.9",
                    "severity": 9,
                    "confidence": 0.96,
                    "title": "DNS tunneling",
                    "evidence": {"dns_entropy": 4.5, "raw_sources": ["suricata_eve"]},
                },
                {
                    "detection_id": "d-internal-exfil",
                    "detector_id": "pondsec.data_exfiltration",
                    "category": "exfiltration",
                    "source_ip": source_ip,
                    "destination_ip": "1.0.0.1",
                    "severity": 10,
                    "confidence": 0.97,
                    "title": "Large outbound transfer",
                    "evidence": {"bytes_out": 90000000, "raw_sources": ["suricata_eve"]},
                },
                {
                    "detection_id": "d-internal-baseline",
                    "detector_id": "pondsec.host_baseline_anomaly",
                    "category": "anomaly",
                    "source_ip": source_ip,
                    "destination_ip": None,
                    "severity": 9,
                    "confidence": 0.96,
                    "title": "Host baseline anomaly",
                    "evidence": {"baseline_deviation": 0.91, "raw_sources": ["host_baseline"]},
                },
            ],
        },
        "risk_factors": [],
    }


def armed_detection_config() -> DetectionConfig:
    return DetectionConfig(
        machine_learning=True,
        learning_mode=True,
        learning_started_at="2026-06-01T00:00:00+00:00",
        learning_days=1,
    )


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

    def test_dnsmasq_normalizer_supports_dns_queries_and_dhcp_events(self) -> None:
        dns = normalize_dnsmasq_line(
            "Jul 11 12:00:00 firewall dnsmasq[1234]: query[A] suspicious.example.test from 192.168.10.20",
            sensor_name="edge-dns",
            source_log="/var/log/resolver/latest.log",
        )
        self.assertIsNotNone(dns)
        assert dns is not None
        self.assertEqual(dns["raw_source"], "dnsmasq")
        self.assertEqual(dns["event_type"], "dns")
        self.assertEqual(dns["source"]["ip"], "192.168.10.20")
        self.assertEqual(dns["metadata"]["rrname"], "suspicious.example.test")
        self.assertEqual(dns["metadata"]["rrtype"], "A")
        self.assertEqual(dns["metadata"]["sensor_name"], "edge-dns")

        dhcp = normalize_dnsmasq_line(
            "Jul 11 12:01:00 firewall dnsmasq-dhcp[1234]: DHCPACK(igb1_vlan10) 192.168.10.20 aa:bb:cc:dd:ee:ff laptop-20",
            sensor_name="edge-dns",
        )
        self.assertIsNotNone(dhcp)
        assert dhcp is not None
        self.assertEqual(dhcp["event_type"], "dhcp")
        self.assertEqual(dhcp["source"]["ip"], "192.168.10.20")
        self.assertEqual(dhcp["source"]["interface"], "igb1_vlan10")
        self.assertEqual(dhcp["metadata"]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(dhcp["metadata"]["hostname"], "laptop-20")

        lease = normalize_dnsmasq_lease(
            "1783261000 aa:bb:cc:dd:ee:ff 192.168.10.20 laptop-20 01:aa:bb:cc:dd:ee:ff",
            "2026-07-05T10:00:00+00:00",
        )
        self.assertIsNotNone(lease)
        assert lease is not None
        self.assertEqual(lease["event_type"], "dhcp")
        self.assertEqual(lease["metadata"]["dhcp_action"], "lease")
        self.assertEqual(lease["metadata"]["entity_confidence"], 0.95)

    def test_dnsmasq_collector_tails_logs_and_snapshots_leases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dns_log = root / "resolver.log"
            dhcp_log = root / "dhcp.log"
            leases = root / "dnsmasq.leases"
            dns_log.write_text(
                "Jul 11 12:00:00 firewall dnsmasq[1234]: query[A] example.test from 192.168.10.20\n",
                encoding="utf-8",
            )
            dhcp_log.write_text(
                "Jul 11 12:01:00 firewall dnsmasq-dhcp[1234]: DHCPACK(igb1_vlan10) 192.168.10.20 aa:bb:cc:dd:ee:ff laptop-20\n",
                encoding="utf-8",
            )
            leases.write_text(
                "1783261000 aa:bb:cc:dd:ee:ff 192.168.10.20 laptop-20 01:aa:bb:cc:dd:ee:ff\n",
                encoding="utf-8",
            )
            collector = DnsmasqCollector(dns_log, dhcp_log, leases, root / "offsets", start_at_end=False)
            events, stats = collector.read_once(max_lines=10)
            self.assertEqual(len(events), 3)
            self.assertEqual(stats.accepted_events, 3)
            self.assertIn("dns_log", stats.sources)
            self.assertIn("dhcp_log", stats.sources)
            self.assertIn("leases", stats.sources)
            self.assertEqual({event["event_type"] for event in events}, {"dns", "dhcp"})

            events2, stats2 = collector.read_once(max_lines=10)
            self.assertEqual(events2, [])
            self.assertGreaterEqual(stats2.duplicates, 1)

    def test_zeek_normalizer_supports_required_log_types(self) -> None:
        conn = normalize_zeek_row("conn", {
            "ts": "2026-07-05T10:00:00+00:00",
            "uid": "C1",
            "id.orig_h": "192.168.10.20",
            "id.orig_p": "51515",
            "id.resp_h": "198.51.100.10",
            "id.resp_p": "443",
            "proto": "tcp",
            "service": "ssl",
            "orig_bytes": "1200",
            "resp_bytes": "800",
            "orig_pkts": "9",
            "resp_pkts": "8",
        }, sensor_name="edge-zeek", interface="igb1")
        self.assertIsNotNone(conn)
        assert conn is not None
        self.assertEqual(conn["event_type"], "flow")
        self.assertEqual(conn["raw_source"], "zeek")
        self.assertEqual(conn["metadata"]["byte_count"], 2000)
        self.assertEqual(conn["metadata"]["sensor_name"], "edge-zeek")

        dns = normalize_zeek_row("dns", {
            "ts": "2026-07-05T10:00:01+00:00",
            "uid": "D1",
            "id.orig_h": "192.168.10.20",
            "id.orig_p": "53000",
            "id.resp_h": "9.9.9.9",
            "id.resp_p": "53",
            "proto": "udp",
            "query": "example.test",
            "qtype_name": "A",
            "answers": "198.51.100.10,198.51.100.11",
        })
        self.assertEqual(dns["event_type"], "dns")
        self.assertEqual(dns["metadata"]["answers"], ["198.51.100.10", "198.51.100.11"])

        ssl = normalize_zeek_row("ssl", {
            "ts": "2026-07-05T10:00:02+00:00",
            "uid": "S1",
            "id.orig_h": "192.168.10.20",
            "id.orig_p": "53001",
            "id.resp_h": "203.0.113.10",
            "id.resp_p": "443",
            "version": "TLSv13",
            "server_name": "tls.example.test",
            "ja3": "abcd",
            "ja3s": "ef01",
        })
        self.assertEqual(ssl["event_type"], "tls")
        self.assertEqual(ssl["metadata"]["ja3"], "abcd")

        x509 = normalize_zeek_row("x509", {
            "ts": "2026-07-05T10:00:03+00:00",
            "id": "F1",
            "fingerprint": "SHA256:abc",
            "certificate.subject": "CN=example.test",
            "san.dns": "example.test,www.example.test",
        })
        self.assertEqual(x509["event_type"], "tls")
        self.assertEqual(x509["metadata"]["certificate_fingerprint"], "SHA256:abc")

        http = normalize_zeek_row("http", {
            "ts": "2026-07-05T10:00:04+00:00",
            "uid": "H1",
            "id.orig_h": "192.168.10.20",
            "id.orig_p": "53002",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": "80",
            "method": "GET",
            "host": "web.example.test",
            "uri": "/login?token=secret",
            "status_code": "200",
        })
        self.assertEqual(http["event_type"], "http")
        self.assertEqual(http["metadata"]["url_path"], "/login")

        files = normalize_zeek_row("files", {
            "ts": "2026-07-05T10:00:05+00:00",
            "fuid": "F2",
            "tx_hosts": "192.168.10.20",
            "rx_hosts": "198.51.100.21",
            "filename": "/tmp/sample.bin",
            "mime_type": "application/octet-stream",
            "seen_bytes": "4096",
            "sha256": "abc123",
        })
        self.assertEqual(files["event_type"], "fileinfo")
        self.assertEqual(files["metadata"]["filename"], "sample.bin")

        notice = normalize_zeek_row("notice", {
            "ts": "2026-07-05T10:00:06+00:00",
            "uid": "N1",
            "id.orig_h": "192.168.10.20",
            "id.resp_h": "198.51.100.22",
            "note": "Scan::Port_Scan",
            "msg": "scan detected",
            "actions": "Notice::ACTION_LOG",
        })
        self.assertEqual(notice["event_type"], "notice")
        self.assertEqual(notice["metadata"]["note"], "Scan::Port_Scan")

        weird = normalize_zeek_row("weird", {
            "ts": "2026-07-05T10:00:07+00:00",
            "uid": "W1",
            "id.orig_h": "192.168.10.20",
            "id.resp_h": "198.51.100.23",
            "name": "bad_TCP_checksum",
            "notice": "F",
        })
        self.assertEqual(weird["event_type"], "anomaly")
        self.assertEqual(weird["metadata"]["notice"], False)

    def test_zeek_collector_tails_tsv_logs_and_persists_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn_log = root / "conn.log"
            conn_log.write_text(
                "#separator \\x09\n"
                "#set_separator\t,\n"
                "#empty_field\t(empty)\n"
                "#unset_field\t-\n"
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
                "2026-07-05T10:00:00+00:00\tC1\t192.168.10.20\t51515\t198.51.100.10\t443\ttcp\tssl\t1200\t800\t9\t8\n",
                encoding="utf-8",
            )
            collector = ZeekLogCollector({"conn": conn_log}, root / "offsets", start_at_end=False)
            events, stats = collector.read_once(max_lines=10)
            self.assertEqual(len(events), 1)
            self.assertEqual(stats.accepted_events, 1)
            self.assertEqual(stats.sources["conn"]["accepted_events"], 1)
            self.assertEqual(events[0]["raw_source"], "zeek")

            events2, stats2 = collector.read_once(max_lines=10)
            self.assertEqual(events2, [])
            self.assertEqual(stats2.read_lines, 0)

    def test_zeek_collector_can_start_at_end_on_first_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn_log = root / "conn.log"
            header = (
                "#separator \\x09\n"
                "#set_separator\t,\n"
                "#empty_field\t(empty)\n"
                "#unset_field\t-\n"
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
            )
            conn_log.write_text(
                header
                + "2026-07-05T10:00:00+00:00\tC1\t192.168.10.20\t51515\t198.51.100.10\t443\ttcp\tssl\t1200\t800\t9\t8\n",
                encoding="utf-8",
            )
            collector = ZeekLogCollector({"conn": conn_log}, root / "offsets")
            events, stats = collector.read_once(max_lines=10)
            self.assertEqual(events, [])
            self.assertEqual(stats.read_lines, 0)
            self.assertFalse(stats.rotation_detected)

            with conn_log.open("a", encoding="utf-8") as handle:
                handle.write(
                    "2026-07-05T10:00:01+00:00\tC2\t192.168.10.21\t51516\t198.51.100.11\t443\ttcp\tssl\t1400\t700\t10\t7\n"
                )
            events2, stats2 = collector.read_once(max_lines=10)
            self.assertEqual(len(events2), 1)
            self.assertEqual(stats2.accepted_events, 1)

    def test_zenarmor_normalizer_keeps_policy_tls_and_app_context(self) -> None:
        event = normalize_zenarmor_event({
            "timestamp": "2026-07-05T10:00:00+00:00",
            "src_ip": "192.168.10.20",
            "src_port": 51515,
            "dst_ip": "198.51.100.30",
            "dst_port": 443,
            "protocol": "tcp",
            "application": "YouTube",
            "application_category": "Streaming Media",
            "web_category": "Entertainment",
            "security_category": "Cloud Application",
            "decision": "blocked",
            "policy_name": "Workstations",
            "url": "https://video.example.test/watch?token=secret",
            "tls_sni": "video.example.test",
            "tls_version": "TLSv1.3",
            "device_name": "laptop-20",
            "session_id": "sess-1",
            "user": "alice",
            "bytes_out": 1500,
            "bytes_in": 4500,
            "indexes": ["Connections", "Web", "TLS"],
        }, sensor_name="zenarmor-edge")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["raw_source"], "zenarmor")
        self.assertEqual(event["event_type"], "drop")
        self.assertEqual(event["metadata"]["application"], "YouTube")
        self.assertEqual(event["metadata"]["policy_name"], "Workstations")
        self.assertEqual(event["metadata"]["tls_sni"], "video.example.test")
        self.assertEqual(event["metadata"]["url_path"], "/watch")
        self.assertEqual(event["metadata"]["byte_count"], 6000)
        self.assertNotIn("token=secret", json.dumps(event["metadata"]))

    def test_zenarmor_collector_reads_json_and_key_value_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "zenarmor.log"
            json_line = json.dumps({
                "timestamp": "2026-07-05T10:00:00+00:00",
                "src_ip": "192.168.10.20",
                "dst_ip": "198.51.100.30",
                "dst_port": 443,
                "application": "Slack",
                "decision": "allowed",
            })
            kv_line = (
                "ts=2026-07-05T10:00:01+00:00 src_ip=192.168.10.21 dst_ip=198.51.100.31 "
                "dst_port=443 protocol=tcp app=GitHub action=blocked sni=github.example.test"
            )
            log.write_text(json_line + "\n" + kv_line + "\n", encoding="utf-8")
            collector = ZenarmorCollector(log, root / "offsets" / "zenarmor.json", start_at_end=False)
            events, stats = collector.read_once(max_lines=10)
            self.assertEqual(len(events), 2)
            self.assertEqual(stats.accepted_events, 2)
            self.assertEqual(events[0]["metadata"]["application"], "Slack")
            self.assertEqual(events[1]["event_type"], "drop")
            self.assertEqual(events[1]["metadata"]["application"], "GitHub")

            parsed = parse_zenarmor_line(kv_line)
            self.assertEqual(parsed["src_ip"], "192.168.10.21")
            events2, stats2 = collector.read_once(max_lines=10)
            self.assertEqual(events2, [])
            self.assertEqual(stats2.read_lines, 0)

    def test_zenarmor_syslog_data_export_uses_real_field_names(self) -> None:
        line = (
            '<6>2026-07-11T15:19:47+02:00 HWFirewall01.internal zenarmor[79555]: '
            'daemon=zenarmor, index=tls, data={"start_time":1783775983000,'
            '"transport_proto":"TCP","interface":"igb0_vlan10","vlanid":"0",'
            '"conn_uuid":"af494f36-86fd-4f9a-8793-eb77caf55128",'
            '"ip_src_saddr":"192.168.10.146","ip_src_port":38736,'
            '"ip_dst_saddr":"13.217.9.161","ip_dst_port":443,'
            '"is_blocked":0,"src_npackets":6,"dst_npackets":7,'
            '"src_nbytes":762,"dst_nbytes":5013,"app_name":"Dynamic Classifier",'
            '"app_category":"Dynamic Classifier","server_name":"dcape-na.amazon.com",'
            '"category":"Shopping","device":{"id":"b4107a5a9bc9","name":"Other Device",'
            '"vendor":"Amazon Technologies Inc.","os":"Android OS"},'
            '"community_id":"1:nNLbsf4PZjmT6d/IPwWRLmx3ZUM=","ja3":"5b5b"}'
        )
        raw = parse_zenarmor_line(line)
        self.assertEqual(raw["index"], "tls")
        event = normalize_zenarmor_event(raw, sensor_name="zenarmor-local")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["timestamp"], "2026-07-11T13:19:43+00:00")
        self.assertEqual(event["event_type"], "tls")
        self.assertEqual(event["source"]["ip"], "192.168.10.146")
        self.assertEqual(event["destination"]["ip"], "13.217.9.161")
        self.assertEqual(event["destination"]["port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["metadata"]["decision"], "allowed")
        self.assertEqual(event["metadata"]["application"], "Dynamic Classifier")
        self.assertEqual(event["metadata"]["tls_sni"], "dcape-na.amazon.com")
        self.assertEqual(event["metadata"]["device_id"], "b4107a5a9bc9")
        self.assertEqual(event["metadata"]["device_os"], "Android OS")
        self.assertEqual(event["metadata"]["packet_count"], 13)
        self.assertEqual(event["metadata"]["byte_count"], 5775)
        self.assertEqual(event["metadata"]["indexes"], ["tls"])

    def test_zenarmor_import_options_filter_optional_context(self) -> None:
        event = normalize_zenarmor_event({
            "timestamp": "2026-07-05T10:00:00+00:00",
            "src_ip": "192.168.10.20",
            "dst_ip": "198.51.100.30",
            "dst_port": 443,
            "application": "YouTube",
            "application_category": "Streaming Media",
            "web_category": "Entertainment",
            "decision": "blocked",
            "policy_name": "Workstations",
            "tls_sni": "video.example.test",
            "tls_version": "TLSv1.3",
            "ja3": "abc",
            "ja4": "def",
            "device_name": "laptop-20",
            "session_id": "sess-1",
            "user": "alice",
            "bytes_out": 1500,
            "bytes_in": 4500,
            "threat_name": "Blocked app",
        }, import_options={
            "import_applications": False,
            "import_categories": False,
            "import_tls_metadata": False,
            "import_session_context": False,
            "import_policy_actions": False,
            "import_device_context": False,
            "import_security_events": False,
        })
        self.assertIsNotNone(event)
        assert event is not None
        metadata = event["metadata"]
        self.assertNotIn("application", metadata)
        self.assertNotIn("application_category", metadata)
        self.assertNotIn("web_category", metadata)
        self.assertNotIn("tls_sni", metadata)
        self.assertNotIn("ja3", metadata)
        self.assertNotIn("session_id", metadata)
        self.assertNotIn("policy_name", metadata)
        self.assertNotIn("device_name", metadata)
        self.assertNotIn("threat_name", metadata)
        self.assertEqual(metadata["event_source"], "zenarmor")

    def test_zenarmor_syslog_udp_collector_reads_local_stream(self) -> None:
        collector = ZenarmorSyslogCollector(
            "127.0.0.1",
            0,
            allowed_senders=["127.0.0.1"],
            sensor_name="zenarmor-local",
            max_datagrams_per_run=10,
        )
        try:
            port = collector._socket().getsockname()[1]
            payload = (
                "timestamp=2026-07-05T10:00:00+00:00 src_ip=192.168.10.20 "
                "dst_ip=198.51.100.30 dst_port=443 protocol=tcp app=Slack action=allowed "
                "sni=slack.example.test"
            ).encode()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(payload, ("127.0.0.1", port))
            events = []
            stats = None
            for _ in range(20):
                events, stats = collector.read_once(max_datagrams=10)
                if stats.read_datagrams:
                    break
                time.sleep(0.01)
        finally:
            collector.close()
        assert stats is not None
        self.assertEqual(stats.read_datagrams, 1)
        self.assertEqual(stats.accepted_events, 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["raw_source"], "zenarmor")
        self.assertEqual(events[0]["metadata"]["application"], "Slack")
        self.assertEqual(events[0]["metadata"]["sensor_name"], "zenarmor-local")

    def test_netflow_v5_datagram_normalizes_to_flow_event(self) -> None:
        collector = NetFlowCollector("127.0.0.1", 2055, allowed_exporters=["192.0.2.10"])
        events, stats = collector.parse_datagram(netflow_v5_datagram(), "192.0.2.10")
        self.assertEqual(stats.parser_errors, 0)
        self.assertEqual(stats.accepted_events, 1)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["raw_source"], "netflow")
        self.assertEqual(event["event_type"], "flow")
        self.assertEqual(event["source"]["ip"], "10.10.10.20")
        self.assertEqual(event["destination"]["ip"], "8.8.8.8")
        self.assertEqual(event["destination"]["port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["metadata"]["byte_count"], 2400)
        self.assertEqual(event["metadata"]["packet_count"], 12)

    def test_netflow_tracks_exporter_and_template_health(self) -> None:
        collector = NetFlowCollector("127.0.0.1", 2055, allowed_exporters=["192.0.2.10"])
        _, denied = collector.parse_datagram(netflow_v5_datagram(), "192.0.2.11")
        self.assertEqual(denied.bad_exporters, 1)

        collector.parse_datagram(netflow_v5_datagram(sequence=100), "192.0.2.10")
        _, gap_stats = collector.parse_datagram(netflow_v5_datagram(sequence=104), "192.0.2.10")
        self.assertEqual(gap_stats.sequence_gaps, 3)

        template_set = struct.pack("!HHHHHH", 0, 12, 256, 1, 8, 4)
        v9 = struct.pack("!HHIIII", 9, 1, 1234, 1783260000, 10, 7) + template_set
        _, template_stats = collector.parse_datagram(v9, "192.0.2.10")
        self.assertEqual(template_stats.templates_seen, 1)
        self.assertEqual(template_stats.template_errors, 0)

        data_without_template = struct.pack("!HH", 300, 4)
        v9_missing = struct.pack("!HHIIII", 9, 1, 1234, 1783260001, 11, 7) + data_without_template
        _, missing_stats = collector.parse_datagram(v9_missing, "192.0.2.10")
        self.assertEqual(missing_stats.template_errors, 1)

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

    def test_event_store_uses_dnsmasq_dhcp_identity_metadata_for_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            event = normalize_dnsmasq_lease(
                "1783261000 aa:bb:cc:dd:ee:ff 192.168.10.20 laptop-20 01:aa:bb:cc:dd:ee:ff",
                "2026-07-05T10:00:00+00:00",
            )
            assert event is not None
            self.assertEqual(store.insert_events([event]), 1)
            host = store.list_rows("hosts")[0]
            self.assertEqual(host["ip"], "192.168.10.20")
            self.assertEqual(host["mac"], "aa:bb:cc:dd:ee:ff")
            self.assertEqual(host["hostname"], "laptop-20")

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

    def test_diagnostics_exposes_provider_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.set_health("healthy", 123, {
                "collector_sources": {
                    "suricata_eve": {
                        "read_lines": 10,
                        "accepted_events": 8,
                        "parser_errors": 0,
                        "normalization_errors": 0,
                        "queue_drops": 0,
                    },
                    "opnsense_filterlog": {
                        "last_error": "filterlog unavailable in test",
                        "read_lines": 0,
                        "accepted_events": 0,
                    },
                }
            })
            payload = diagnostics_payload(
                PondSecConfig(
                    data_dir=root,
                    zeek=ZeekConfig(enabled=True, sensor_name="zeek-edge", log_dir="/var/log/zeek/current"),
                    zenarmor=ZenarmorConfig(
                        enabled=True,
                        source="official_log",
                        format="json",
                        sensor_name="zenarmor-edge",
                        api_enabled=True,
                        api_base_url="https://127.0.0.1:8090",
                        import_tls_metadata=True,
                    ),
                ),
                store,
            )
            providers = {item["provider_id"]: item for item in payload["providers"]}
            self.assertEqual(providers["suricata_eve"]["health_status"], "healthy")
            self.assertEqual(providers["opnsense_filterlog"]["health_status"], "warning")
            self.assertEqual(providers["zeek_logs"]["health_status"], "waiting")
            self.assertIn("logs", providers["zeek_logs"]["configuration"])
            self.assertEqual(providers["zenarmor"]["configuration"]["source"], "official_log")
            self.assertEqual(providers["zenarmor"]["configuration"]["format"], "json")
            self.assertTrue(providers["zenarmor"]["configuration"]["imports"]["tls_metadata"])
            self.assertIn("flow", providers["netflow"]["event_types"])

    def test_config_loads_extended_zenarmor_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pondsec.json"
            path.write_text(json.dumps({
                "zenarmor": {
                    "enabled": "1",
                    "source": "syslog_udp",
                    "format": "json",
                    "listen_address": "127.0.0.1",
                    "port": "5514",
                    "allowed_senders": "127.0.0.1,192.0.2.10",
                    "max_datagrams_per_run": "250",
                    "api_enabled": "1",
                    "api_base_url": "https://127.0.0.1:8090",
                    "api_timeout_seconds": "9",
                    "api_verify_tls": "0",
                    "import_applications": "0",
                    "import_categories": "1",
                    "import_tls_metadata": "1",
                    "import_session_context": "0",
                    "import_policy_actions": "1",
                    "import_device_context": "0",
                    "import_security_events": "1",
                },
                "response": {
                    "auto_arm_after_learning": "0"
                }
            }), encoding="utf-8")
            config = load_config(path)
            self.assertTrue(config.zenarmor.enabled)
            self.assertEqual(config.zenarmor.source, "syslog_udp")
            self.assertEqual(config.zenarmor.format, "json")
            self.assertEqual(config.zenarmor.listen_address, "127.0.0.1")
            self.assertEqual(config.zenarmor.port, 5514)
            self.assertEqual(config.zenarmor.allowed_senders, ["127.0.0.1", "192.0.2.10"])
            self.assertEqual(config.zenarmor.max_datagrams_per_run, 250)
            self.assertEqual(config.zenarmor.api_timeout_seconds, 9)
            self.assertFalse(config.zenarmor.api_verify_tls)
            self.assertFalse(config.zenarmor.import_applications)
            self.assertFalse(config.zenarmor.import_session_context)
            self.assertFalse(config.zenarmor.import_device_context)
            self.assertFalse(config.response.auto_arm_after_learning)
            self.assertEqual(config.validate(), [])

    def test_diagnostics_exposes_response_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.set_health("healthy", 123, {})
            payload = diagnostics_payload(
                PondSecConfig(
                    enabled=True,
                    data_dir=root,
                    response=ResponseConfig(mode="observe", automatic_blocking=False),
                    detection=DetectionConfig(machine_learning=True, learning_mode=True, learning_days=14),
                ),
                store,
            )
            self.assertEqual(payload["response_mode"], "observe")
            self.assertFalse(payload["readiness"]["automatic_blocking"])
            self.assertEqual(payload["readiness"]["response_mode"], "observe")
            response_check = next(item for item in payload["readiness"]["checks"] if item["id"] == "response_policy")
            self.assertEqual(response_check["status"], "ok")
            self.assertIn("will not change PF", response_check["detail"])

    def test_diagnostics_warns_when_enforce_lacks_completed_learning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.set_health("healthy", 123, {})
            payload = diagnostics_payload(
                PondSecConfig(
                    enabled=True,
                    data_dir=root,
                    response=ResponseConfig(
                        mode="enforce",
                        automatic_blocking=True,
                        isolate_internal=True,
                        ai_full_decision_mode=True,
                    ),
                    detection=DetectionConfig(machine_learning=True, learning_mode=False),
                ),
                store,
            )
            response_check = next(item for item in payload["readiness"]["checks"] if item["id"] == "response_policy")
            self.assertEqual(response_check["status"], "warning")
            self.assertIn("learning phase is not complete", response_check["detail"])
            self.assertEqual(response_check["internal_isolation_cooldown_seconds"], 900)

    def test_diagnostics_exposes_effective_auto_arm_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.set_health("healthy", 123, {
                "response_auto_armed": True,
                "effective_mode": "prevent",
                "effective_response_mode": "enforce",
                "effective_response": {
                    "automatic_blocking": True,
                    "ai_full_decision_mode": True,
                    "isolate_internal": True,
                    "block_external": True,
                    "manual_confirmation": False,
                },
            })
            payload = diagnostics_payload(
                PondSecConfig(
                    enabled=True,
                    data_dir=root,
                    response=ResponseConfig(mode="observe", automatic_blocking=False),
                    detection=DetectionConfig(
                        machine_learning=True,
                        learning_mode=True,
                        learning_started_at="2026-06-01T00:00:00+00:00",
                        learning_days=14,
                    ),
                ),
                store,
            )
            self.assertEqual(payload["mode"], "prevent")
            self.assertEqual(payload["configured_mode"], "monitor")
            self.assertEqual(payload["response_mode"], "enforce")
            self.assertTrue(payload["response_auto_armed"])
            self.assertTrue(payload["readiness"]["automatic_blocking"])
            response_check = next(item for item in payload["readiness"]["checks"] if item["id"] == "response_policy")
            self.assertEqual(response_check["status"], "ok")
            self.assertTrue(response_check["response_auto_armed"])

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

    def test_incident_analysis_includes_response_policy_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = robust_internal_incident("incident-response-decision-analysis")
            store.insert_incidents([incident])
            store.audit_response_decision(
                incident["incident_id"],
                "policy_decision",
                {
                    "status": "denied",
                    "target_ip": "192.168.30.3",
                    "proposal_allowed": False,
                    "activation_allowed": False,
                    "reasons": ["learning phase is active"],
                    "decision_layers": {"compromise_assessment": {"status": "unconfirmed"}},
                },
                actor="test",
            )
            analysis = _incident_analysis(store.get_incident(incident["incident_id"]), store=store)
            self.assertEqual(len(analysis["response_decisions"]), 1)
            self.assertEqual(analysis["response_decisions"][0]["detail"]["status"], "denied")
            self.assertIn("learning phase is active", analysis["response_decisions"][0]["detail"]["reasons"])

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

    def test_reputation_signature_is_reconnaissance_not_initial_access(self) -> None:
        incident = {
            "incident_id": "reputation-case",
            "title": "Signature from 199.45.155.75",
            "status": "open",
            "risk_score": 72,
            "severity": 7,
            "confidence": 0.9,
            "source_ip": "199.45.155.75",
            "destination_ip": "192.168.30.3",
            "category": "signature",
            "created_at": "2026-07-05T10:00:00+00:00",
            "updated_at": "2026-07-05T10:00:00+00:00",
            "first_seen": "2026-07-05T10:00:00+00:00",
            "last_seen": "2026-07-05T10:00:00+00:00",
            "event_count": 1,
            "detection_count": 1,
            "suppressed_count": 0,
            "affected_targets": ["192.168.30.3"],
            "attack_stage": "reconnaissance",
            "evidence": {
                "detections": [{
                    "detection_id": "d-reputation",
                    "detector_id": "pondsec.suricata_alert",
                    "detector_version": "1",
                    "category": "signature",
                    "title": "ET CINS Active Threat Intelligence Poor Reputation IP group 34",
                    "description": "Known internet scanner reputation list hit.",
                    "timestamp": "2026-07-05T10:00:00+00:00",
                    "source_ip": "199.45.155.75",
                    "destination_ip": "192.168.30.3",
                    "severity": 7,
                    "confidence": 0.9,
                    "anomaly_score": 0.5,
                    "evidence": {"suricata_action": "blocked", "signature": "Poor Reputation IP Scanner"},
                    "recommended_action": "Review source reputation",
                }],
            },
            "risk_factors": [],
        }
        analysis = _incident_analysis(incident)
        stages = {item["stage"]: item for item in analysis["attack_stages"]}
        self.assertIn("reconnaissance", stages)
        self.assertEqual(stages["reconnaissance"]["status"], "prevented")
        self.assertNotIn("initial_access", stages)
        self.assertIn("Successful initial access", analysis["case_narrative"]["not_confirmed"])

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

    def test_pretrained_runtime_selftest_reports_model_name(self) -> None:
        payload = SaidimnIdsCnnRuntime().self_test()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["model_id"], "saidimn-ids-cnn-cicids2017")
        self.assertEqual(payload["model_name"], "Saidimn IDS CNN CICIDS2017")
        self.assertTrue(payload["checksum_ok"])

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
                detection=armed_detection_config(),
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

    def test_learning_status_counts_down_and_arms_after_required_days(self) -> None:
        config = DetectionConfig(
            machine_learning=True,
            learning_mode=True,
            learning_started_at="2026-07-01T00:00:00+00:00",
            learning_days=14,
        )
        day_0 = config.learning_status(datetime(2026, 7, 1, tzinfo=timezone.utc))
        day_13 = config.learning_status(datetime(2026, 7, 14, tzinfo=timezone.utc))
        day_14 = config.learning_status(datetime(2026, 7, 15, tzinfo=timezone.utc))
        self.assertEqual(day_0["remaining_days"], 14)
        self.assertEqual(day_13["remaining_days"], 1)
        self.assertTrue(day_13["active"])
        self.assertEqual(day_14["remaining_days"], 0)
        self.assertEqual(day_14["status"], "armed")
        self.assertFalse(day_14["active"])

    def test_service_auto_arms_runtime_response_after_learning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                mode="monitor",
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(
                    machine_learning=True,
                    learning_mode=True,
                    learning_started_at="2026-06-01T00:00:00+00:00",
                    learning_days=14,
                ),
                response=ResponseConfig(
                    mode="observe",
                    auto_arm_after_learning=True,
                    automatic_blocking=False,
                    ai_full_decision_mode=False,
                    isolate_internal=False,
                    block_external=False,
                    manual_confirmation=True,
                ),
            )
            service = PondSecService(config)
            effective = service._effective_runtime_config(config.detection.learning_status(datetime(2026, 7, 1, tzinfo=timezone.utc)))
            self.assertEqual(effective.mode, "prevent")
            self.assertEqual(effective.response.mode, "enforce")
            self.assertTrue(effective.response.automatic_blocking)
            self.assertTrue(effective.response.ai_full_decision_mode)
            self.assertTrue(effective.response.isolate_internal)
            self.assertTrue(effective.response.block_external)
            self.assertFalse(effective.response.manual_confirmation)
            self.assertEqual(config.mode, "monitor")
            self.assertEqual(config.response.mode, "observe")

    def test_service_does_not_auto_arm_before_learning_completes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(
                    machine_learning=True,
                    learning_mode=True,
                    learning_started_at="2026-07-01T00:00:00+00:00",
                    learning_days=14,
                ),
                response=ResponseConfig(auto_arm_after_learning=True),
            )
            service = PondSecService(config)
            effective = service._effective_runtime_config(config.detection.learning_status(datetime(2026, 7, 7, tzinfo=timezone.utc)))
            self.assertIs(effective, config)

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

    def test_delete_incident_removes_case_without_active_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-delete-test",
                "title": "Delete test",
                "status": "open",
                "risk_score": 71,
                "severity": 7,
                "confidence": 0.8,
                "source_ip": "192.168.10.11",
                "destination_ip": "198.51.100.11",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [],
            }])
            result = store.delete_incident("incident-delete-test", actor="test")
            self.assertEqual(result["status"], "ok")
            self.assertIsNone(store.get_incident("incident-delete-test"))

    def test_false_positive_feedback_relaxes_future_host_baseline_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(false_positive_feedback_days=14),
            )
            service = PondSecService(config)
            service.store.insert_incidents([{
                "incident_id": "incident-false-positive-feedback",
                "title": "False positive feedback",
                "status": "open",
                "risk_score": 71,
                "severity": 7,
                "confidence": 0.8,
                "source_ip": "192.168.10.11",
                "destination_ip": "198.51.100.11",
                "category": "anomaly",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [],
            }])
            changed = service.store.update_incident_status("incident-false-positive-feedback", "false_positive", actor="test")
            self.assertTrue(changed)
            self.assertIn("192.168.10.11", service.store.false_positive_feedback_sources(14))
            self.assertEqual(len(service.store.list_rows("incident_feedback")), 1)
            self.assertEqual(service._baseline_skip_sources([{"source_ip": "192.168.10.11"}]), set())
            self.assertEqual(service._baseline_skip_sources([{"source_ip": "192.168.10.12"}]), {"192.168.10.12"})

    def test_delete_incident_denies_active_response_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-delete-blocked-test",
                "title": "Delete blocked test",
                "status": "open",
                "risk_score": 91,
                "severity": 9,
                "confidence": 0.96,
                "source_ip": "192.168.10.12",
                "destination_ip": "198.51.100.12",
                "category": "command_and_control",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [],
            }])
            store.add_block_entry({
                "block_id": "block-delete-deny",
                "incident_id": "incident-delete-blocked-test",
                "source_ip": "192.168.10.12",
                "destination": "198.51.100.12",
                "reason": "test isolation",
                "risk_score": 91,
                "confidence": 0.96,
                "expires_at": "2099-01-01T00:00:00+00:00",
                "status": "active",
            }, actor="test")
            result = store.delete_incident("incident-delete-blocked-test", actor="test")
            self.assertEqual(result["status"], "denied")
            self.assertIsNotNone(store.get_incident("incident-delete-blocked-test"))

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

    def test_response_engine_keeps_external_scanner_as_response_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-external-scanner-target",
                "title": "External scanner",
                "status": "open",
                "risk_score": 91,
                "severity": 9,
                "confidence": 0.96,
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.30.3",
                "category": "reconnaissance",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {
                    "entity_roles": {"external_actor": "8.8.8.8", "victim": "192.168.30.3", "response_target": "8.8.8.8"},
                    "detections": [{
                        "detection_id": "d-scanner-target",
                        "category": "signature",
                        "source_ip": "8.8.8.8",
                        "destination_ip": "192.168.30.3",
                        "severity": 9,
                        "confidence": 0.96,
                        "title": "Poor Reputation IP Scanner",
                    }],
                },
                "risk_factors": [],
            }])
            config = PondSecConfig(response=ResponseConfig(minimum_risk_score=50, minimum_confidence=50))
            proposal = propose_block_for_incident(store, config, "incident-external-scanner-target", actor="test")
            self.assertEqual(proposal["source_ip"], "8.8.8.8")

    def test_response_engine_isolates_internal_actor_in_multistage_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([robust_internal_incident("incident-internal-isolation-target")])
            seed_host_baseline(store, "192.168.30.3")
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True, ai_full_decision_mode=True),
                detection=armed_detection_config(),
            )
            proposal = propose_block_for_incident(store, config, "incident-internal-isolation-target", actor="test", automatic=True)
            self.assertEqual(proposal["source_ip"], "192.168.30.3")
            self.assertIn("Isolation proposal", proposal["reason"])
            layers = proposal["policy_decision"]["decision_layers"]
            self.assertEqual(layers["detection"]["status"], "observed")
            self.assertEqual(layers["compromise_assessment"]["status"], "likely_compromised")
            self.assertEqual(layers["containment_decision"]["status"], "eligible")
            self.assertEqual(layers["execution"]["status"], "allowed")

    def test_response_engine_denies_weak_internal_auto_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-weak-internal-isolation",
                "title": "Weak internal behavior",
                "status": "open",
                "risk_score": 92,
                "severity": 9,
                "confidence": 0.9,
                "source_ip": "192.168.30.3",
                "destination_ip": "192.168.30.3",
                "category": "multi_stage",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:20:00+00:00",
                "evidence": {
                    "entity_roles": {"external_actor": "8.8.4.4", "affected_host": "192.168.30.3"},
                    "detections": [{
                        "detection_id": "d-weak-c2",
                        "category": "command_and_control",
                        "source_ip": "192.168.30.3",
                        "destination_ip": "1.1.1.1",
                        "severity": 8,
                        "confidence": 0.9,
                        "title": "Weak beaconing suspicion",
                    }],
                },
                "risk_factors": [],
            }])
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, minimum_risk_score=50, minimum_confidence=50, isolate_internal=True, block_external=True),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "policy denied"):
                propose_block_for_incident(store, config, "incident-weak-internal-isolation", actor="test", automatic=True)

    def test_response_engine_denies_internal_isolation_during_learning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-learning-internal-isolation",
                "title": "Learning internal behavior",
                "status": "open",
                "risk_score": 96,
                "severity": 10,
                "confidence": 0.98,
                "source_ip": "192.168.10.250",
                "destination_ip": "1.1.1.1",
                "category": "command_and_control",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:20:00+00:00",
                "evidence": {},
                "risk_factors": [],
            }])
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, minimum_risk_score=50, minimum_confidence=50, isolate_internal=True),
                detection=DetectionConfig(machine_learning=True, learning_mode=True, learning_started_at="2026-07-05T10:00:00+00:00", learning_days=14),
            )
            with self.assertRaisesRegex(ResponseDenied, "learning phase"):
                propose_block_for_incident(store, config, "incident-learning-internal-isolation", actor="test", automatic=True)

    def test_response_policy_requires_completed_learning_marker_for_internal_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([robust_internal_incident("incident-learning-not-complete")])
            seed_host_baseline(store, "192.168.30.3")
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True, ai_full_decision_mode=True),
                detection=DetectionConfig(machine_learning=True, learning_mode=False),
            )
            with self.assertRaisesRegex(ResponseDenied, "learning phase is not complete"):
                propose_block_for_incident(store, config, "incident-learning-not-complete", actor="test", automatic=True)

    def test_response_policy_denies_single_suricata_alert_for_internal_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([{
                "incident_id": "incident-single-suricata-alert",
                "title": "Single Suricata alert",
                "status": "open",
                "risk_score": 99,
                "severity": 10,
                "confidence": 0.99,
                "source_ip": "192.168.30.3",
                "destination_ip": "1.1.1.1",
                "category": "signature",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "event_count": 1,
                "detection_count": 1,
                "evidence": {"detections": [{
                    "detection_id": "d-single-alert",
                    "detector_id": "pondsec.suricata_alert",
                    "category": "signature",
                    "source_ip": "192.168.30.3",
                    "destination_ip": "1.1.1.1",
                    "severity": 10,
                    "confidence": 0.99,
                    "evidence": {"signature_id": 1},
                }]},
                "risk_factors": [],
            }])
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "single-signal|not enough"):
                propose_block_for_incident(store, config, "incident-single-suricata-alert", actor="test", automatic=True)

    def test_response_policy_denies_portscan_and_threat_intel_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            base = robust_internal_incident("incident-portscan-alone")
            base.update({
                "title": "Portscan alone",
                "source_ip": "192.168.30.3",
                "category": "reconnaissance",
                "event_count": 20,
                "detection_count": 1,
                "evidence": {"detections": [{
                    "detection_id": "d-portscan-alone",
                    "detector_id": "pondsec.portscan",
                    "category": "reconnaissance",
                    "source_ip": "192.168.30.3",
                    "destination_ip": None,
                    "severity": 10,
                    "confidence": 0.99,
                    "evidence": {"unique_ports": 40},
                }]},
            })
            intel = robust_internal_incident("incident-intel-alone", "192.168.30.4")
            intel.update({
                "title": "Threat intelligence alone",
                "source_ip": "192.168.30.4",
                "destination_ip": "1.1.1.1",
                "category": "threat_intelligence",
                "event_count": 20,
                "detection_count": 1,
                "evidence": {"detections": [{
                "detection_id": "d-intel-alone",
                "detector_id": "pondsec.threat_intel",
                "category": "threat_intelligence",
                "source_ip": "192.168.30.4",
                "destination_ip": "1.1.1.1",
                "severity": 10,
                "confidence": 0.99,
                "evidence": {"indicator": "listed"},
                }]},
            })
            store.insert_incidents([base, intel])
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "single-signal|strong internal"):
                propose_block_for_incident(store, config, "incident-portscan-alone", actor="test", automatic=True)
            with self.assertRaisesRegex(ResponseDenied, "strong internal|not enough"):
                propose_block_for_incident(store, config, "incident-intel-alone", actor="test", automatic=True)

    def test_response_policy_denies_two_weak_internal_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = robust_internal_incident("incident-two-weak-events")
            incident.update({
                "title": "Two weak internal events",
                "source_ip": "192.168.30.3",
                "destination_ip": "1.1.1.1",
                "category": "multi_stage",
                "risk_score": 96,
                "severity": 9,
                "confidence": 0.96,
                "event_count": 2,
                "detection_count": 2,
                "evidence": {"detections": [
                    {
                        "detection_id": "d-weak-anomaly",
                        "detector_id": "pondsec.host_baseline_anomaly",
                        "category": "anomaly",
                        "source_ip": "192.168.30.3",
                        "destination_ip": None,
                        "severity": 9,
                        "confidence": 0.96,
                        "evidence": {"baseline_deviation": 0.7, "raw_sources": ["host_baseline"]},
                    },
                    {
                        "detection_id": "d-weak-intel",
                        "detector_id": "pondsec.threat_intel",
                        "category": "threat_intelligence",
                        "source_ip": "192.168.30.3",
                        "destination_ip": "1.1.1.1",
                        "severity": 9,
                        "confidence": 0.96,
                        "evidence": {"indicator": "listed", "raw_sources": ["threat_intel"]},
                    },
                ]},
            })
            store.insert_incidents([incident])
            seed_host_baseline(store, "192.168.30.3")
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True, ai_full_decision_mode=True),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "not enough|no strong internal"):
                propose_block_for_incident(store, config, "incident-two-weak-events", actor="test", automatic=True)

    def test_response_policy_denies_high_severity_without_independent_engines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            incident = robust_internal_incident("incident-one-engine")
            for detection in incident["evidence"]["detections"]:
                if detection["detector_id"] == "pondsec.dns_tunneling":
                    detection["detector_id"] = "pondsec.beaconing"
            store.insert_incidents([incident])
            seed_host_baseline(store, "192.168.30.3")
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "independent engines"):
                propose_block_for_incident(store, config, "incident-one-engine", actor="test", automatic=True)

    def test_response_policy_denies_protected_and_management_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            protected = robust_internal_incident("incident-protected-host", "192.168.30.3")
            management = robust_internal_incident("incident-management-host", "192.168.99.10")
            store.insert_incidents([protected, management])
            seed_host_baseline(store, "192.168.30.3")
            seed_host_baseline(store, "192.168.99.10")
            config = PondSecConfig(
                interfaces=InterfaceConfig(management=["192.168.99.0/24"]),
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True, protected_hosts=["192.168.30.3"]),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "protected"):
                propose_block_for_incident(store, config, "incident-protected-host", actor="test", automatic=True)
            with self.assertRaisesRegex(ResponseDenied, "protected"):
                propose_block_for_incident(store, config, "incident-management-host", actor="test", automatic=True)

    def test_response_policy_rate_limit_prevents_mass_internal_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([robust_internal_incident("incident-rate-limited")])
            seed_host_baseline(store, "192.168.30.3")
            store.add_block_entry({
                "incident_id": "older-incident",
                "source_ip": "192.168.30.44",
                "destination": None,
                "reason": "older auto isolation",
                "risk_score": 99,
                "confidence": 0.99,
                "expires_at": "2099-01-01T00:00:00+00:00",
                "automatic": True,
                "status": "removed",
            }, actor="test")
            config = PondSecConfig(
                response=ResponseConfig(mode="enforce", automatic_blocking=True, isolate_internal=True, max_internal_isolations_per_hour=1),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "hourly rate limit"):
                propose_block_for_incident(store, config, "incident-rate-limited", actor="test", automatic=True)

    def test_response_policy_cooldown_prevents_rapid_internal_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "pondsec-ndr.db")
            store.migrate()
            store.insert_incidents([robust_internal_incident("incident-cooldown-limited")])
            seed_host_baseline(store, "192.168.30.3")
            store.add_block_entry({
                "incident_id": "recent-incident",
                "source_ip": "192.168.30.44",
                "destination": None,
                "reason": "recent auto isolation",
                "risk_score": 99,
                "confidence": 0.99,
                "expires_at": "2099-01-01T00:00:00+00:00",
                "automatic": True,
                "status": "removed",
            }, actor="test")
            config = PondSecConfig(
                response=ResponseConfig(
                    mode="enforce",
                    automatic_blocking=True,
                    isolate_internal=True,
                    max_internal_isolations_per_hour=10,
                    internal_isolation_cooldown_seconds=900,
                ),
                detection=armed_detection_config(),
            )
            with self.assertRaisesRegex(ResponseDenied, "cooldown"):
                propose_block_for_incident(store, config, "incident-cooldown-limited", actor="test", automatic=True)

    def test_response_modes_observe_recommend_and_enforce_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                enabled=True,
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=armed_detection_config(),
                response=ResponseConfig(mode="observe", automatic_blocking=True, isolate_internal=True, max_internal_isolations_per_hour=10),
            )
            service = PondSecService(config)
            observe_case = robust_internal_incident("incident-observe", "192.168.30.3")
            observe_case["source_ip"] = "8.8.4.3"
            observe_case["evidence"]["entity_roles"]["external_actor"] = "8.8.4.3"
            observe_case["evidence"]["entity_roles"]["response_target"] = "8.8.4.3"
            service.store.insert_incidents([observe_case])
            seed_host_baseline(service.store, "192.168.30.3")
            observed = service._auto_response([service.store.get_incident("incident-observe")])
            self.assertEqual(observed[0]["status"], "observed")
            self.assertEqual(service.store.list_rows("block_entries"), [])

            service.config.response.mode = "recommend"
            recommend_case = robust_internal_incident("incident-recommend", "192.168.30.4")
            recommend_case["source_ip"] = "8.8.4.4"
            recommend_case["created_at"] = "2026-07-05T11:00:00+00:00"
            recommend_case["updated_at"] = "2026-07-05T11:20:00+00:00"
            recommend_case["evidence"]["entity_roles"]["external_actor"] = "8.8.4.4"
            recommend_case["evidence"]["entity_roles"]["response_target"] = "8.8.4.4"
            service.store.insert_incidents([recommend_case])
            seed_host_baseline(service.store, "192.168.30.4")
            recommended = service._auto_response([service.store.get_incident("incident-recommend")])
            self.assertEqual(recommended[0]["status"], "recommended")
            self.assertEqual(service.store.list_rows("block_entries")[0]["status"], "proposed")

            service.config.response.mode = "enforce"
            service.config.response.ai_full_decision_mode = True
            enforce_case = robust_internal_incident("incident-enforce", "192.168.30.5")
            enforce_case["source_ip"] = "8.8.4.5"
            enforce_case["created_at"] = "2026-07-05T12:00:00+00:00"
            enforce_case["updated_at"] = "2026-07-05T12:20:00+00:00"
            enforce_case["evidence"]["entity_roles"]["external_actor"] = "8.8.4.5"
            enforce_case["evidence"]["entity_roles"]["response_target"] = "8.8.4.5"
            service.store.insert_incidents([enforce_case])
            seed_host_baseline(service.store, "192.168.30.5")
            with patch("pondsec_ndr.service.activate_block", return_value={"status": "ok", "pf_table": "virusprot", "pf_rule_present": True, "pf_verify": {"ok": True}}):
                enforced = service._auto_response([service.store.get_incident("incident-enforce")])
            self.assertEqual(enforced[0]["status"], "ok")
            audit_actions = [row["action"] for row in service.store.list_rows("audit_log", limit=20)]
            self.assertTrue(any(action.startswith("response.") for action in audit_actions))

    def test_enforce_without_ai_full_decision_falls_back_to_recommend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                enabled=True,
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=armed_detection_config(),
                response=ResponseConfig(
                    mode="enforce",
                    ai_full_decision_mode=False,
                    automatic_blocking=True,
                    isolate_internal=True,
                    max_internal_isolations_per_hour=10,
                ),
            )
            service = PondSecService(config)
            incident = robust_internal_incident("incident-enforce-without-ai-full", "192.168.30.8")
            incident["source_ip"] = "8.8.4.8"
            incident["evidence"]["entity_roles"]["external_actor"] = "8.8.4.8"
            incident["evidence"]["entity_roles"]["response_target"] = "8.8.4.8"
            service.store.insert_incidents([incident])
            seed_host_baseline(service.store, "192.168.30.8")

            with patch("pondsec_ndr.service.activate_block") as activate_mock:
                actions = service._auto_response([service.store.get_incident("incident-enforce-without-ai-full")])

            self.assertEqual(actions[0]["status"], "recommended")
            self.assertIn("AI full decision mode", actions[0]["reason"])
            self.assertEqual(service.store.list_rows("block_entries")[0]["status"], "proposed")
            activate_mock.assert_not_called()

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

    def test_runtime_reset_keeps_allowlist_and_models(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = EventStore(root / "pondsec-ndr.db")
            store.migrate()
            store.insert_events([normalize_eve(flow_event("2026-07-05T10:00:00+00:00", "192.168.10.20", "1.1.1.1", 443))])
            store.insert_detections([{
                "detection_id": "runtime-reset-detection",
                "detector_id": "pondsec.test",
                "detector_version": "1.0.0",
                "category": "anomaly",
                "title": "Reset test",
                "description": "Reset test",
                "timestamp": "2026-07-05T10:00:00+00:00",
                "source_ip": "192.168.10.20",
                "destination_ip": "1.1.1.1",
                "severity": 7,
                "confidence": 0.8,
                "anomaly_score": 0.8,
                "evidence": {},
                "recommended_action": "investigate",
            }])
            store.insert_incidents([{
                "incident_id": "runtime-reset-incident",
                "title": "Runtime reset incident",
                "status": "open",
                "risk_score": 80,
                "severity": 8,
                "confidence": 0.8,
                "source_ip": "192.168.10.20",
                "destination_ip": "1.1.1.1",
                "category": "anomaly",
                "created_at": "2026-07-05T10:00:00+00:00",
                "updated_at": "2026-07-05T10:00:00+00:00",
                "evidence": {},
                "risk_factors": [],
            }])
            store.add_allowlist_entry("192.168.10.0/24", "trusted network", actor="test")
            eve = root / "eve.json"
            eve.write_text('{"event_type":"flow"}\n', encoding="utf-8")
            config = PondSecConfig(data_dir=root, suricata_eve_path=str(eve))
            (root / "learning_started_at").write_text("2026-07-05T10:00:00+00:00\n", encoding="utf-8")
            offset_dir = root / "collector_offsets"
            offset_dir.mkdir()
            (offset_dir / "suricata_eve.json").write_text("{}", encoding="utf-8")

            payload = reset_runtime_state(store, config, restart_service=False, flush_pf=False)

            self.assertEqual(payload["status"], "ok")
            self.assertEqual(store.list_rows("events"), [])
            self.assertEqual(store.list_rows("detections"), [])
            self.assertEqual(store.list_rows("incidents"), [])
            self.assertEqual(store.list_rows("block_entries"), [])
            self.assertEqual(store.list_rows("allowlist_entries")[0]["value"], "192.168.10.0/24")
            self.assertFalse((root / "learning_started_at").exists())
            offset = json.loads((offset_dir / "suricata_eve.json").read_text(encoding="utf-8"))
            self.assertEqual(offset["offset"], eve.stat().st_size)

    def test_service_auto_response_skips_baseline_only_anomaly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = PondSecConfig(
                enabled=True,
                mode="prevent",
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                response=ResponseConfig(mode="enforce", automatic_blocking=True, manual_confirmation=False, isolate_internal=True),
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

    def test_service_learning_phase_keeps_deterministic_detections_but_blocks_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            eve = root / "eve.json"
            eve.write_text(
                "\n".join(
                    json.dumps(flow_event(f"2026-07-05T10:00:{index:02d}+00:00", "192.168.10.20", "192.168.20.10", 20 + index))
                    for index in range(18)
                ) + "\n",
                encoding="utf-8",
            )
            config = PondSecConfig(
                enabled=True,
                mode="prevent",
                suricata_eve_path=str(eve),
                data_dir=root / "db",
                log_dir=root / "log",
                run_dir=root / "run",
                detection=DetectionConfig(machine_learning=True, learning_mode=True, learning_started_at="2026-07-05T10:00:00+00:00", learning_days=14),
                response=ResponseConfig(mode="enforce", automatic_blocking=True, manual_confirmation=False, block_external=True, isolate_internal=True),
            )
            service = PondSecService(config)
            result = service.run_once(max_lines=100)

            self.assertEqual(result["inserted_events"], 18)
            self.assertGreater(result["detections"], 0)
            self.assertGreater(result["incidents"], 0)
            self.assertFalse(result["learning_collection_only"])
            self.assertTrue(result["learning_ai_suppressed"])
            self.assertTrue(result["response_actions"])
            self.assertTrue(all(action["status"] == "denied" for action in result["response_actions"]))
            self.assertTrue(any("learning phase is active" in action["reason"] for action in result["response_actions"]))
            self.assertGreater(len(service.store.list_rows("detections")), 0)
            self.assertGreater(len(service.store.list_rows("incidents")), 0)
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
