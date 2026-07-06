"""SQLite local event store for PondSec NDR."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import sqlite3
from typing import Any, Iterator
from uuid import uuid4


SCHEMA_VERSION = 2
INCIDENT_DEDUPE_WINDOW_SECONDS = 3600
OPEN_INCIDENT_STATUSES = ("open",)
ARCHIVED_INCIDENT_STATUSES = ("closed", "false_positive", "archived")


def _json_default(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_set_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _target_network_key(value: str | None, category: str | None = None) -> str:
    if category == "anomaly" and not value:
        return "host-baseline"
    if not value:
        return "any"
    value = str(value)
    if value in {"internal", "external"} or value.startswith("port:"):
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _attack_stage(category: str | None) -> str:
    return {
        "reconnaissance": "reconnaissance",
        "command_and_control": "command_and_control",
        "lateral_movement": "lateral_movement",
        "exfiltration": "exfiltration",
        "machine_learning": "classification",
        "signature": "signature",
        "anomaly": "host_observation",
    }.get(str(category or ""), "unknown")


def _validation_tag_from_evidence(evidence: dict[str, Any]) -> str | None:
    validation = evidence.get("validation")
    if isinstance(validation, dict):
        return str(validation.get("scenario") or validation.get("kind") or "validation")
    if validation:
        return "validation"
    return None


def _is_private_address(value: str | None) -> bool:
    if not value or "/" in str(value):
        return False
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        source_port INTEGER,
        source_interface TEXT,
        destination_ip TEXT,
        destination_port INTEGER,
        protocol TEXT,
        direction TEXT,
        metadata_json TEXT NOT NULL,
        raw_source TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS flows (
        flow_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        destination_port INTEGER,
        protocol TEXT,
        started_at TEXT,
        byte_count INTEGER DEFAULT 0,
        packet_count INTEGER DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hosts (
        ip TEXT PRIMARY KEY,
        hostname TEXT,
        mac TEXT,
        interface TEXT,
        vlan TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        risk_score INTEGER DEFAULT 0,
        open_incidents INTEGER DEFAULT 0,
        known_destinations_json TEXT NOT NULL DEFAULT '[]',
        known_ports_json TEXT NOT NULL DEFAULT '[]',
        known_tls_fingerprints_json TEXT NOT NULL DEFAULT '[]',
        learning_status TEXT NOT NULL DEFAULT 'learning',
        baseline_deviation REAL DEFAULT 0,
        block_status TEXT NOT NULL DEFAULT 'none',
        allowlist_status TEXT NOT NULL DEFAULT 'none'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS host_baselines (
        host_ip TEXT PRIMARY KEY,
        observation_count INTEGER NOT NULL DEFAULT 0,
        first_observation TEXT,
        last_observation TEXT,
        baseline_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS features (
        feature_id TEXT PRIMARY KEY,
        feature_version TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        feature_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS detections (
        detection_id TEXT PRIMARY KEY,
        detector_id TEXT NOT NULL,
        detector_version TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        severity INTEGER NOT NULL,
        confidence REAL NOT NULL,
        anomaly_score REAL NOT NULL,
        evidence_json TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        model_version TEXT,
        feature_version TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
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
        first_seen TEXT,
        last_seen TEXT,
        event_count INTEGER NOT NULL DEFAULT 0,
        detection_count INTEGER NOT NULL DEFAULT 0,
        affected_targets_json TEXT NOT NULL DEFAULT '[]',
        attack_stage TEXT,
        validation_tag TEXT,
        suppressed_count INTEGER NOT NULL DEFAULT 0,
        evidence_json TEXT NOT NULL,
        risk_factors_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_detections (
        incident_id TEXT NOT NULL,
        detection_id TEXT NOT NULL,
        PRIMARY KEY (incident_id, detection_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS responses (
        response_id TEXT PRIMARY KEY,
        incident_id TEXT,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        detail_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS block_entries (
        block_id TEXT PRIMARY KEY,
        incident_id TEXT,
        source_ip TEXT NOT NULL,
        destination TEXT,
        reason TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        confidence REAL NOT NULL,
        policy_id TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        automatic INTEGER NOT NULL,
        status TEXT NOT NULL,
        removal_reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS allowlist_entries (
        allowlist_id TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policies (
        policy_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        priority INTEGER NOT NULL,
        policy_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS models (
        model_id TEXT PRIMARY KEY,
        model_type TEXT NOT NULL,
        model_version TEXT,
        created_at TEXT,
        trained_at TEXT,
        feature_schema_version TEXT,
        training_dataset TEXT,
        training_window TEXT,
        hyperparameters_json TEXT NOT NULL DEFAULT '{}',
        input_dimensions INTEGER,
        sha256 TEXT,
        status TEXT NOT NULL,
        metrics_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS model_metrics (
        model_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        metrics_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_health (
        health_id INTEGER PRIMARY KEY CHECK (health_id = 1),
        status TEXT NOT NULL,
        pid INTEGER,
        updated_at TEXT NOT NULL,
        detail_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS collector_offsets (
        source TEXT PRIMARY KEY,
        inode INTEGER,
        offset INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        audit_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail_json TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_dedupe ON incidents(status, source_ip, category, destination_ip, validation_tag, last_seen)",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            self._fix_ownership()

    def _fix_ownership(self) -> None:
        if os.geteuid() != 0:
            return
        try:
            user = pwd.getpwnam("pondsecndr")
            group = grp.getgrnam("pondsecndr")
        except KeyError:
            return
        paths = [self.db_path, self.db_path.with_name(self.db_path.name + "-wal"), self.db_path.with_name(self.db_path.name + "-shm")]
        for path in paths:
            if path.exists():
                os.chown(path, user.pw_uid, group.gr_gid)

    def migrate(self) -> None:
        with self.connect() as conn:
            for statement in SCHEMA:
                conn.execute(statement)
            current_version = self._schema_version(conn)
            if current_version > SCHEMA_VERSION:
                raise RuntimeError(f"database schema {current_version} is newer than supported schema {SCHEMA_VERSION}")
            if current_version < 2:
                if current_version > 0:
                    self._backup_database(conn, current_version, 2)
                self._migrate_to_v2(conn)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, now_iso()),
            )

    def _schema_version(self, conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT max(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    def _backup_database(self, conn: sqlite3.Connection, from_version: int, to_version: int) -> Path:
        backup_dir = self.db_path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = backup_dir / f"{self.db_path.name}.schema{from_version}-to-{to_version}.{stamp}.bak"
        with sqlite3.connect(backup_path) as backup:
            conn.backup(backup)
        return backup_path

    def _migrate_to_v2(self, conn: sqlite3.Connection) -> None:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        additions = {
            "first_seen": "ALTER TABLE incidents ADD COLUMN first_seen TEXT",
            "last_seen": "ALTER TABLE incidents ADD COLUMN last_seen TEXT",
            "event_count": "ALTER TABLE incidents ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0",
            "detection_count": "ALTER TABLE incidents ADD COLUMN detection_count INTEGER NOT NULL DEFAULT 0",
            "affected_targets_json": "ALTER TABLE incidents ADD COLUMN affected_targets_json TEXT NOT NULL DEFAULT '[]'",
            "attack_stage": "ALTER TABLE incidents ADD COLUMN attack_stage TEXT",
            "validation_tag": "ALTER TABLE incidents ADD COLUMN validation_tag TEXT",
            "suppressed_count": "ALTER TABLE incidents ADD COLUMN suppressed_count INTEGER NOT NULL DEFAULT 0",
        }
        for column, statement in additions.items():
            if column not in columns:
                conn.execute(statement)
        rows = conn.execute(
            """
            SELECT incident_id, created_at, updated_at, destination_ip, category,
                   evidence_json, affected_targets_json
            FROM incidents
            """
        ).fetchall()
        for row in rows:
            try:
                existing_targets = set(json.loads(row["affected_targets_json"] or "[]"))
            except json.JSONDecodeError:
                existing_targets = set()
            if row["destination_ip"]:
                existing_targets.add(row["destination_ip"])
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except json.JSONDecodeError:
                evidence = {}
            validation_tag = _validation_tag_from_evidence(evidence)
            detection_count = int(conn.execute(
                "SELECT count(*) FROM incident_detections WHERE incident_id = ?",
                (row["incident_id"],),
            ).fetchone()[0])
            conn.execute(
                """
                UPDATE incidents
                SET first_seen = COALESCE(first_seen, ?),
                    last_seen = COALESCE(last_seen, ?),
                    event_count = CASE WHEN event_count > 0 THEN event_count ELSE ? END,
                    detection_count = CASE WHEN detection_count > 0 THEN detection_count ELSE ? END,
                    affected_targets_json = ?,
                    attack_stage = COALESCE(attack_stage, ?),
                    validation_tag = COALESCE(validation_tag, ?),
                    suppressed_count = COALESCE(suppressed_count, 0)
                WHERE incident_id = ?
                """,
                (
                    row["created_at"],
                    row["updated_at"],
                    max(1, detection_count),
                    detection_count,
                    json.dumps(sorted(existing_targets)),
                    _attack_stage(row["category"]),
                    validation_tag,
                    row["incident_id"],
                ),
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (2, now_iso()),
        )

    def check(self) -> dict[str, Any]:
        with self.connect() as conn:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            version = conn.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {"status": "ok" if result == "ok" else "corrupt", "integrity": result, "schema_version": version, "size_bytes": size}

    def insert_events(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        rows = []
        for event in events:
            rows.append((
                event["event_id"],
                event["schema_version"],
                event["event_type"],
                event["timestamp"],
                event.get("source", {}).get("ip"),
                event.get("source", {}).get("port"),
                event.get("source", {}).get("interface"),
                event.get("destination", {}).get("ip"),
                event.get("destination", {}).get("port"),
                event.get("protocol"),
                event.get("direction"),
                json.dumps(event.get("metadata", {}), sort_keys=True),
                event.get("raw_source", "suricata"),
            ))
        with self.connect() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO events(
                    event_id, schema_version, event_type, timestamp, source_ip,
                    source_port, source_interface, destination_ip, destination_port,
                    protocol, direction, metadata_json, raw_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            inserted_events = conn.total_changes - before
            self._upsert_hosts(conn, events)
            return inserted_events

    def _upsert_hosts(self, conn: sqlite3.Connection, events: list[dict[str, Any]]) -> None:
        by_host: dict[str, dict[str, Any]] = {}
        for event in events:
            src = event.get("source", {}).get("ip")
            if not src:
                continue
            item = by_host.setdefault(src, {"first": event["timestamp"], "last": event["timestamp"], "destinations": set(), "ports": set(), "fingerprints": set(), "interface": event.get("source", {}).get("interface")})
            item["first"] = min(item["first"], event["timestamp"])
            item["last"] = max(item["last"], event["timestamp"])
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            fingerprint = event.get("metadata", {}).get("fingerprint")
            if dst:
                item["destinations"].add(dst)
            if port is not None:
                item["ports"].add(port)
            if fingerprint:
                item["fingerprints"].add(_stable_set_value(fingerprint))
        for ip, item in by_host.items():
            row = conn.execute("SELECT known_destinations_json, known_ports_json, known_tls_fingerprints_json, first_seen FROM hosts WHERE ip = ?", (ip,)).fetchone()
            if row:
                destinations = set(json.loads(row["known_destinations_json"])) | item["destinations"]
                ports = set(json.loads(row["known_ports_json"])) | {str(port) for port in item["ports"]}
                fingerprints = set(json.loads(row["known_tls_fingerprints_json"])) | item["fingerprints"]
                first_seen = min(row["first_seen"], item["first"])
                conn.execute(
                    """
                    UPDATE hosts
                    SET first_seen = ?, last_seen = ?, interface = COALESCE(?, interface),
                        known_destinations_json = ?, known_ports_json = ?,
                        known_tls_fingerprints_json = ?
                    WHERE ip = ?
                    """,
                    (first_seen, item["last"], item["interface"], json.dumps(sorted(destinations)), json.dumps(sorted(ports)), json.dumps(sorted(fingerprints)), ip),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO hosts(ip, interface, first_seen, last_seen, known_destinations_json, known_ports_json, known_tls_fingerprints_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ip, item["interface"], item["first"], item["last"], json.dumps(sorted(item["destinations"])), json.dumps(sorted(str(port) for port in item["ports"])), json.dumps(sorted(item["fingerprints"]))),
                )

    def insert_features(self, features: list[dict[str, Any]]) -> int:
        if not features:
            return 0
        timestamp = now_iso()
        rows = []
        for item in features:
            feature_id = f"{item['source_ip']}:{timestamp}:{item.get('feature_version', '1')}"
            rows.append((feature_id, item.get("feature_version", "1"), item["source_ip"], timestamp, json.dumps(item, sort_keys=True)))
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO features(feature_id, feature_version, source_ip, timestamp, feature_json) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def score_features_against_baselines(self, features: list[dict[str, Any]], minimum_observations: int = 50) -> list[dict[str, Any]]:
        if not features:
            return features
        metrics = [
            "destination_count",
            "port_count",
            "bytes_out",
            "upload_download_ratio",
            "dns_entropy",
            "dns_name_length",
            "connections_60s",
            "internal_connections",
            "external_connections",
        ]
        with self.connect() as conn:
            baseline_rows = {
                row["host_ip"]: row
                for row in conn.execute(
                    "SELECT host_ip, observation_count, baseline_json FROM host_baselines WHERE host_ip IN ({})".format(
                        ",".join("?" for _ in features)
                    ),
                    [item["source_ip"] for item in features],
                ).fetchall()
            } if features else {}
        scored = []
        for item in features:
            enriched = dict(item)
            row = baseline_rows.get(item["source_ip"])
            reasons: list[dict[str, Any]] = []
            score = float(enriched.get("baseline_deviation") or 0)
            if row and int(row["observation_count"]) >= minimum_observations:
                baseline = json.loads(row["baseline_json"] or "{}")
                for metric in metrics:
                    current = float(enriched.get(metric) or 0)
                    expected = float(baseline.get(metric) or 0)
                    if current <= 0 or expected <= 0:
                        continue
                    ratio = current / max(expected, 1.0)
                    if ratio >= 3:
                        metric_score = min(1.0, (ratio - 1) / 10)
                        score = max(score, metric_score)
                        reasons.append({"metric": metric, "current": round(current, 4), "baseline": round(expected, 4), "ratio": round(ratio, 4)})
                enriched["baseline_status"] = "established"
                enriched["baseline_observations"] = int(row["observation_count"])
                enriched["baseline_anomaly_reasons"] = reasons[:6]
            else:
                enriched["baseline_status"] = "learning"
                enriched["baseline_observations"] = int(row["observation_count"]) if row else 0
                enriched["baseline_anomaly_reasons"] = []
            enriched["baseline_deviation"] = round(min(1.0, score), 4)
            scored.append(enriched)
        return scored

    def update_host_baselines(self, features: list[dict[str, Any]], skip_sources: set[str] | None = None) -> int:
        if not features:
            return 0
        skip_sources = skip_sources or set()
        metrics = [
            "destination_count",
            "port_count",
            "bytes_out",
            "upload_download_ratio",
            "dns_entropy",
            "dns_name_length",
            "connections_60s",
            "internal_connections",
            "external_connections",
        ]
        updated = 0
        with self.connect() as conn:
            for item in features:
                source_ip = item["source_ip"]
                if source_ip in skip_sources:
                    continue
                now = now_iso()
                row = conn.execute("SELECT observation_count, first_observation, baseline_json FROM host_baselines WHERE host_ip = ?", (source_ip,)).fetchone()
                if row:
                    count = int(row["observation_count"])
                    baseline = json.loads(row["baseline_json"] or "{}")
                    next_count = count + 1
                    for metric in metrics:
                        current = float(item.get(metric) or 0)
                        baseline[metric] = ((float(baseline.get(metric) or 0) * count) + current) / next_count
                    conn.execute(
                        """
                        UPDATE host_baselines
                        SET observation_count = ?, last_observation = ?, baseline_json = ?
                        WHERE host_ip = ?
                        """,
                        (next_count, now, json.dumps(baseline, sort_keys=True), source_ip),
                    )
                else:
                    baseline = {metric: float(item.get(metric) or 0) for metric in metrics}
                    conn.execute(
                        """
                        INSERT INTO host_baselines(host_ip, observation_count, first_observation, last_observation, baseline_json)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (source_ip, 1, now, now, json.dumps(baseline, sort_keys=True)),
                    )
                conn.execute(
                    "UPDATE hosts SET learning_status = ?, baseline_deviation = ? WHERE ip = ?",
                    (
                        "established" if int((row["observation_count"] if row else 0)) + 1 >= 50 else "learning",
                        float(item.get("baseline_deviation") or 0),
                        source_ip,
                    ),
                )
                updated += 1
        return updated

    def insert_detections(self, detections: list[dict[str, Any]]) -> int:
        if not detections:
            return 0
        rows = []
        for detection in detections:
            rows.append((
                detection["detection_id"],
                detection["detector_id"],
                detection["detector_version"],
                detection["category"],
                detection["title"],
                detection["description"],
                detection["timestamp"],
                detection.get("source_ip"),
                detection.get("destination_ip"),
                detection["severity"],
                detection["confidence"],
                detection["anomaly_score"],
                json.dumps(detection.get("evidence", {}), sort_keys=True),
                detection["recommended_action"],
                detection.get("model_version"),
                detection.get("feature_version"),
            ))
        with self.connect() as conn:
            before = conn.total_changes
            conn.executemany(
                """
                INSERT OR IGNORE INTO detections(
                    detection_id, detector_id, detector_version, category, title,
                    description, timestamp, source_ip, destination_ip, severity,
                    confidence, anomaly_score, evidence_json, recommended_action,
                    model_version, feature_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            return conn.total_changes - before

    def insert_incidents(self, incidents: list[dict[str, Any]]) -> int:
        if not incidents:
            return 0
        created = 0
        with self.connect() as conn:
            for incident in incidents:
                prepared = self._prepare_incident_record(incident)
                existing = self._find_merge_incident(conn, prepared)
                if existing:
                    incident["incident_id"] = existing["incident_id"]
                    prepared["incident_id"] = existing["incident_id"]
                    self._merge_incident(conn, existing, prepared)
                else:
                    self._insert_incident(conn, prepared)
                    created += 1
                for detection_id in prepared["detection_ids"]:
                    conn.execute("INSERT OR IGNORE INTO incident_detections(incident_id, detection_id) VALUES (?, ?)", (prepared["incident_id"], detection_id))
                if prepared.get("source_ip"):
                    self._refresh_host_incident_count(conn, prepared["source_ip"], prepared["risk_score"])
            return created

    def _prepare_incident_record(self, incident: dict[str, Any]) -> dict[str, Any]:
        evidence = incident.get("evidence", {}) if isinstance(incident.get("evidence"), dict) else {}
        detection_ids = list(dict.fromkeys(str(item) for item in incident.get("detection_ids", []) if item))
        detections = evidence.get("detections", [])
        if isinstance(detections, list):
            for detection in detections:
                if isinstance(detection, dict) and detection.get("detection_id"):
                    detection_ids.append(str(detection["detection_id"]))
        detection_ids = list(dict.fromkeys(detection_ids))
        targets = self._incident_targets(incident, evidence)
        first_seen = str(incident.get("first_seen") or incident.get("created_at") or now_iso())
        last_seen = str(incident.get("last_seen") or incident.get("updated_at") or first_seen)
        validation_tag = incident.get("validation_tag") or _validation_tag_from_evidence(evidence)
        return {
            "incident_id": incident["incident_id"],
            "title": incident["title"],
            "status": incident.get("status", "open"),
            "risk_score": int(incident["risk_score"]),
            "severity": int(incident["severity"]),
            "confidence": float(incident["confidence"]),
            "source_ip": incident.get("source_ip"),
            "destination_ip": incident.get("destination_ip"),
            "category": incident.get("category"),
            "created_at": incident["created_at"],
            "updated_at": incident["updated_at"],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_count": int(incident.get("event_count") or max(1, len(detection_ids))),
            "detection_count": int(incident.get("detection_count") or len(detection_ids)),
            "affected_targets": targets,
            "attack_stage": incident.get("attack_stage") or _attack_stage(incident.get("category")),
            "validation_tag": validation_tag,
            "suppressed_count": int(incident.get("suppressed_count") or 0),
            "evidence": evidence,
            "risk_factors": incident.get("risk_factors", []),
            "detection_ids": detection_ids,
            "target_key": _target_network_key(incident.get("destination_ip"), incident.get("category")),
        }

    @staticmethod
    def _incident_targets(incident: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
        targets = set()
        if incident.get("destination_ip"):
            targets.add(str(incident["destination_ip"]))
        detections = evidence.get("detections", [])
        if isinstance(detections, list):
            for detection in detections:
                if isinstance(detection, dict) and detection.get("destination_ip"):
                    targets.add(str(detection["destination_ip"]))
        return sorted(targets)

    def _find_merge_incident(self, conn: sqlite3.Connection, incident: dict[str, Any]) -> sqlite3.Row | None:
        if incident["status"] not in OPEN_INCIDENT_STATUSES:
            return None
        cutoff = (_parse_time(incident["first_seen"]) - timedelta(seconds=INCIDENT_DEDUPE_WINDOW_SECONDS)).isoformat()
        rows = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE status = 'open'
              AND source_ip IS ?
              AND category IS ?
              AND COALESCE(validation_tag, '') = COALESCE(?, '')
              AND COALESCE(last_seen, updated_at) >= ?
            ORDER BY COALESCE(last_seen, updated_at) DESC
            LIMIT 20
            """,
            (incident.get("source_ip"), incident.get("category"), incident.get("validation_tag"), cutoff),
        ).fetchall()
        for row in rows:
            if self._incident_target_matches(row, incident):
                return row
        return None

    @staticmethod
    def _incident_target_matches(row: sqlite3.Row, incident: dict[str, Any]) -> bool:
        candidate = _target_network_key(row["destination_ip"], row["category"])
        incoming = incident["target_key"]
        if candidate == "any" or incoming == "any":
            return True
        if candidate == incoming:
            return True
        try:
            row_targets = json.loads(row["affected_targets_json"] or "[]")
        except json.JSONDecodeError:
            row_targets = []
        target_keys = {_target_network_key(str(target), row["category"]) for target in row_targets}
        return incoming in target_keys or candidate in {_target_network_key(target, incident["category"]) for target in incident["affected_targets"]}

    @staticmethod
    def _merge_evidence(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = dict(existing if isinstance(existing, dict) else {})
        incoming = incoming if isinstance(incoming, dict) else {}
        detections_by_id: dict[str, dict[str, Any]] = {}
        ordered_ids: list[str] = []
        for evidence in (existing, incoming):
            detections = evidence.get("detections", []) if isinstance(evidence, dict) else []
            if not isinstance(detections, list):
                continue
            for detection in detections:
                if not isinstance(detection, dict):
                    continue
                detection_id = str(detection.get("detection_id") or _stable_set_value(detection))
                if detection_id not in detections_by_id:
                    ordered_ids.append(detection_id)
                detections_by_id[detection_id] = detection
        if detections_by_id:
            merged["detections"] = [detections_by_id[detection_id] for detection_id in ordered_ids[-50:]]
        for key, value in incoming.items():
            if key == "detections":
                continue
            if key not in merged or merged[key] in (None, {}, [], ""):
                merged[key] = value
        correlation = merged.get("correlation") if isinstance(merged.get("correlation"), dict) else {}
        correlation.update({
            "deduplicated": True,
            "dedupe_rule": "same source, category, target or target network, validation tag, and time window",
            "retained_detection_records": len(merged.get("detections", [])),
        })
        merged["correlation"] = correlation
        return merged

    @staticmethod
    def _merge_risk_factors(existing: list[Any], incoming: list[Any]) -> list[Any]:
        merged: list[Any] = []
        seen: set[str] = set()
        for factor in list(existing if isinstance(existing, list) else []) + list(incoming if isinstance(incoming, list) else []):
            key = _stable_set_value(factor)
            if key in seen:
                continue
            seen.add(key)
            merged.append(factor)
        return merged[-50:]

    def _insert_incident(self, conn: sqlite3.Connection, incident: dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT INTO incidents(
                incident_id, title, status, risk_score, severity, confidence,
                source_ip, destination_ip, category, created_at, updated_at,
                first_seen, last_seen, event_count, detection_count,
                affected_targets_json, attack_stage, validation_tag, suppressed_count,
                evidence_json, risk_factors_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident["incident_id"], incident["title"], incident["status"],
                incident["risk_score"], incident["severity"], incident["confidence"],
                incident.get("source_ip"), incident.get("destination_ip"), incident.get("category"),
                incident["created_at"], incident["updated_at"], incident["first_seen"], incident["last_seen"],
                incident["event_count"], incident["detection_count"], json.dumps(incident["affected_targets"], sort_keys=True),
                incident["attack_stage"], incident["validation_tag"], incident["suppressed_count"],
                json.dumps(incident["evidence"], sort_keys=True), json.dumps(incident["risk_factors"], sort_keys=True),
            ),
        )

    def _merge_incident(self, conn: sqlite3.Connection, existing: sqlite3.Row, incoming: dict[str, Any]) -> None:
        existing_evidence = json.loads(existing["evidence_json"] or "{}")
        existing_risk = json.loads(existing["risk_factors_json"] or "[]")
        merged_evidence = self._merge_evidence(existing_evidence, incoming["evidence"])
        merged_risk = self._merge_risk_factors(existing_risk, incoming["risk_factors"])
        try:
            existing_targets = set(json.loads(existing["affected_targets_json"] or "[]"))
        except json.JSONDecodeError:
            existing_targets = set()
        targets = sorted(existing_targets | set(incoming["affected_targets"]))
        first_seen = min(str(existing["first_seen"] or existing["created_at"]), incoming["first_seen"])
        last_seen = max(str(existing["last_seen"] or existing["updated_at"]), incoming["last_seen"])
        existing_detection_count = int(existing["detection_count"] or 0)
        existing_event_count = int(existing["event_count"] or 0)
        existing_suppressed = int(existing["suppressed_count"] or 0)
        conn.execute(
            """
            UPDATE incidents
            SET title = ?,
                risk_score = max(risk_score, ?),
                severity = max(severity, ?),
                confidence = max(confidence, ?),
                destination_ip = COALESCE(destination_ip, ?),
                updated_at = ?,
                first_seen = ?,
                last_seen = ?,
                event_count = ?,
                detection_count = ?,
                affected_targets_json = ?,
                attack_stage = COALESCE(attack_stage, ?),
                validation_tag = COALESCE(validation_tag, ?),
                suppressed_count = ?,
                evidence_json = ?,
                risk_factors_json = ?
            WHERE incident_id = ?
            """,
            (
                existing["title"],
                incoming["risk_score"],
                incoming["severity"],
                incoming["confidence"],
                incoming.get("destination_ip"),
                max(str(existing["updated_at"]), incoming["updated_at"]),
                first_seen,
                last_seen,
                existing_event_count + incoming["event_count"],
                existing_detection_count + max(0, incoming["detection_count"]),
                json.dumps(targets, sort_keys=True),
                incoming["attack_stage"],
                incoming["validation_tag"],
                existing_suppressed + 1 + incoming["suppressed_count"],
                json.dumps(merged_evidence, sort_keys=True),
                json.dumps(merged_risk, sort_keys=True),
                existing["incident_id"],
            ),
        )

    def _refresh_host_incident_count(self, conn: sqlite3.Connection, source_ip: str, risk_score: int) -> None:
        conn.execute(
            """
            UPDATE hosts
            SET risk_score = max(risk_score, ?),
                open_incidents = (
                    SELECT count(*)
                    FROM incidents
                    WHERE status = 'open' AND source_ip = ?
                )
            WHERE ip = ?
            """,
            (risk_score, source_ip, source_ip),
        )

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["risk_factors"] = json.loads(item.pop("risk_factors_json"))
        item["affected_targets"] = json.loads(item.pop("affected_targets_json", "[]") or "[]")
        return item

    def update_incident_status(self, incident_id: str, status: str, actor: str = "system") -> bool:
        if status not in {"open", "closed", "false_positive", "archived"}:
            raise ValueError("invalid incident status")
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?", (status, now_iso(), incident_id))
            changed = conn.total_changes - before
            self._audit(conn, actor, f"incident.{status}", incident_id, {})
            source = conn.execute("SELECT source_ip FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if source and source["source_ip"]:
                conn.execute(
                    "UPDATE hosts SET open_incidents = (SELECT count(*) FROM incidents WHERE status = 'open' AND source_ip = ?) WHERE ip = ?",
                    (source["source_ip"], source["source_ip"]),
                )
            return changed > 0

    def add_allowlist_entry(self, value: str, reason: str | None = None, expires_at: str | None = None, actor: str = "system") -> dict[str, Any]:
        entry = {
            "allowlist_id": str(uuid4()),
            "value": value,
            "reason": reason,
            "created_at": now_iso(),
            "expires_at": expires_at,
        }
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO allowlist_entries(allowlist_id, value, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (entry["allowlist_id"], entry["value"], entry["reason"], entry["created_at"], entry["expires_at"]),
            )
            conn.execute("UPDATE hosts SET allowlist_status = 'allowlisted' WHERE ip = ?", (value,))
            self._audit(conn, actor, "allowlist.add", value, entry)
        return entry

    def remove_allowlist_entry(self, allowlist_id: str, actor: str = "system") -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM allowlist_entries WHERE allowlist_id = ?", (allowlist_id,)).fetchone()
            before = conn.total_changes
            conn.execute("DELETE FROM allowlist_entries WHERE allowlist_id = ?", (allowlist_id,))
            changed = conn.total_changes - before
            if row:
                conn.execute("UPDATE hosts SET allowlist_status = 'none' WHERE ip = ?", (row["value"],))
            self._audit(conn, actor, "allowlist.delete", allowlist_id, {"value": row["value"] if row else None})
            return changed > 0

    def allowlist_values(self) -> list[str]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute("SELECT value FROM allowlist_entries WHERE expires_at IS NULL OR expires_at > ?", (now,)).fetchall()
        return [row["value"] for row in rows]

    def add_block_entry(self, entry: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        block_id = entry.get("block_id") or str(uuid4())
        created_at = entry.get("created_at") or now_iso()
        record = {
            "block_id": block_id,
            "incident_id": entry.get("incident_id"),
            "source_ip": entry["source_ip"],
            "destination": entry.get("destination"),
            "reason": entry["reason"],
            "risk_score": int(entry["risk_score"]),
            "confidence": float(entry["confidence"]),
            "policy_id": entry.get("policy_id"),
            "created_at": created_at,
            "expires_at": entry["expires_at"],
            "created_by": entry.get("created_by") or actor,
            "automatic": 1 if entry.get("automatic") else 0,
            "status": entry.get("status", "proposed"),
            "removal_reason": entry.get("removal_reason"),
        }
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO block_entries(
                    block_id, incident_id, source_ip, destination, reason, risk_score,
                    confidence, policy_id, created_at, expires_at, created_by,
                    automatic, status, removal_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["block_id"], record["incident_id"], record["source_ip"], record["destination"],
                    record["reason"], record["risk_score"], record["confidence"], record["policy_id"],
                    record["created_at"], record["expires_at"], record["created_by"], record["automatic"],
                    record["status"], record["removal_reason"],
                ),
            )
            if record["status"] in {"proposed", "active"}:
                conn.execute("UPDATE hosts SET block_status = ? WHERE ip = ?", (record["status"], record["source_ip"]))
            self._audit(conn, actor, f"block.{record['status']}", record["source_ip"], record)
        return record

    def get_block_entry(self, block_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM block_entries WHERE block_id = ?", (block_id,)).fetchone()
        return dict(row) if row else None

    def existing_response_block(self, incident_id: str | None, source_ip: str | None) -> dict[str, Any] | None:
        if not incident_id and not source_ip:
            return None
        now = now_iso()
        clauses = ["status IN ('proposed', 'active')", "expires_at > ?"]
        values: list[Any] = [now]
        if incident_id:
            clauses.append("incident_id = ?")
            values.append(incident_id)
        elif source_ip:
            clauses.append("source_ip = ?")
            values.append(source_ip)
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT * FROM block_entries WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 1",
                values,
            ).fetchone()
        return dict(row) if row else None

    def active_block_count(self) -> int:
        now = now_iso()
        with self.connect() as conn:
            return int(conn.execute("SELECT count(*) FROM block_entries WHERE status = 'active' AND expires_at > ?", (now,)).fetchone()[0])

    def active_block_sources(self) -> list[str]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT source_ip FROM block_entries WHERE status = 'active' AND expires_at > ?",
                (now,),
            ).fetchall()
        return [row["source_ip"] for row in rows]

    def expired_active_block_sources(self) -> list[str]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT source_ip FROM block_entries WHERE status = 'active' AND expires_at <= ?",
                (now,),
            ).fetchall()
        return [row["source_ip"] for row in rows]

    def update_block_status(self, block_id: str, status: str, removal_reason: str | None = None, actor: str = "system") -> bool:
        if status not in {"proposed", "active", "removed", "expired", "rejected"}:
            raise ValueError("invalid block status")
        with self.connect() as conn:
            row = conn.execute("SELECT source_ip FROM block_entries WHERE block_id = ?", (block_id,)).fetchone()
            before = conn.total_changes
            conn.execute(
                "UPDATE block_entries SET status = ?, removal_reason = COALESCE(?, removal_reason) WHERE block_id = ?",
                (status, removal_reason, block_id),
            )
            changed = conn.total_changes - before
            if row:
                host_status = status if status in {"proposed", "active"} else "none"
                conn.execute("UPDATE hosts SET block_status = ? WHERE ip = ?", (host_status, row["source_ip"]))
            self._audit(conn, actor, f"block.{status}", block_id, {"removal_reason": removal_reason})
            return changed > 0

    def expire_block_entries(self, actor: str = "system") -> int:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute("SELECT block_id FROM block_entries WHERE status IN ('proposed', 'active') AND expires_at <= ?", (now,)).fetchall()
            for row in rows:
                conn.execute("UPDATE block_entries SET status = 'expired', removal_reason = 'expired' WHERE block_id = ?", (row["block_id"],))
                self._audit(conn, actor, "block.expired", row["block_id"], {})
            return len(rows)

    def _audit(self, conn: sqlite3.Connection, actor: str, action: str, target: str | None, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO audit_log(audit_id, timestamp, actor, action, target, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid4()), now_iso(), actor, action, target, json.dumps(detail, sort_keys=True)),
        )

    def set_health(self, status: str, pid: int | None, detail: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO service_health(health_id, status, pid, updated_at, detail_json)
                VALUES (1, ?, ?, ?, ?)
                """,
                (status, pid, now_iso(), json.dumps(detail, sort_keys=True)),
            )

    def get_health(self) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM service_health WHERE health_id = 1").fetchone()
        if not row:
            return {"status": "stopped", "pid": None, "updated_at": None, "detail": {}}
        return {"status": row["status"], "pid": row["pid"], "updated_at": row["updated_at"], "detail": json.loads(row["detail_json"])}

    def list_rows(self, table: str, limit: int = 100) -> list[dict[str, Any]]:
        allowed = {"events", "detections", "incidents", "hosts", "block_entries", "allowlist_entries", "policies", "models", "audit_log"}
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        order = "timestamp" if table in {"events", "detections", "audit_log"} else "rowid"
        if table == "incidents":
            order = "updated_at"
        if table == "hosts":
            order = "last_seen"
        with self.connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY {order} DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def incident_status_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute("SELECT status, count(*) AS count FROM incidents GROUP BY status").fetchall()
            open_count = int(conn.execute("SELECT count(*) FROM incidents WHERE status = 'open'").fetchone()[0])
            active_count = int(conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND last_seen >= ?", ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchone()[0])
            high_risk_count = int(conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 70").fetchone()[0])
            critical_count = int(conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 90").fetchone()[0])
        return {
            "counts_by_status": {row["status"]: int(row["count"]) for row in rows},
            "open": open_count,
            "active": active_count,
            "high_risk": high_risk_count,
            "critical": critical_count,
            "definitions": {
                "open": "Incidents with status=open; archived, closed, and false-positive incidents are excluded.",
                "active": "Open incidents with last_seen in the last 24 hours.",
                "high_risk": "Open incidents with risk_score >= 70.",
                "critical": "Open incidents with risk_score >= 90.",
                "time_window": "24 hours for active incidents and telemetry rate metrics; lifetime for open/high-risk/critical counts.",
                "test_data": "Validation incidents are included unless filtered by validation_tag in the API consumer.",
            },
        }

    def telemetry_type_counts(self, hours: int = 24) -> dict[str, int]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, count(*) AS count
                FROM events
                WHERE timestamp >= ?
                GROUP BY event_type
                """,
                (cutoff,),
            ).fetchall()
        return {row["event_type"]: int(row["count"]) for row in rows}

    def baseline_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = int(conn.execute("SELECT count(*) FROM host_baselines").fetchone()[0])
            established = int(conn.execute("SELECT count(*) FROM host_baselines WHERE observation_count >= 50").fetchone()[0])
            learning = max(0, total - established)
            max_observations = int(conn.execute("SELECT COALESCE(max(observation_count), 0) FROM host_baselines").fetchone()[0])
        return {
            "total_hosts": total,
            "established_hosts": established,
            "learning_hosts": learning,
            "max_observations": max_observations,
        }

    def dashboard_summary(self) -> dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            events_24h = conn.execute("SELECT count(*) FROM events WHERE timestamp >= ?", (cutoff,)).fetchone()[0]
            open_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open'").fetchone()[0]
            active_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND COALESCE(last_seen, updated_at) >= ?", (cutoff,)).fetchone()[0]
            high_risk_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 70").fetchone()[0]
            critical_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 90").fetchone()[0]
            block_rows = conn.execute("SELECT DISTINCT source_ip FROM block_entries WHERE status = 'active'").fetchall()
            blocked_sources = len(block_rows)
            isolated_clients = sum(1 for row in block_rows if _is_private_address(row["source_ip"]))
            categories = conn.execute("SELECT category, count(*) AS count FROM detections GROUP BY category ORDER BY count DESC").fetchall()
            top_hosts = conn.execute("SELECT ip, risk_score, open_incidents, block_status, allowlist_status, interface FROM hosts ORDER BY risk_score DESC, last_seen DESC LIMIT 10").fetchall()
            latest_event = conn.execute("SELECT max(timestamp) FROM events").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        delay = None
        if latest_event:
            delay = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(latest_event.replace("Z", "+00:00"))).total_seconds()))
        return {
            "metrics": {
                "events_last_24h": events_24h,
                "open_incidents": open_incidents,
                "active_incidents": active_incidents,
                "high_risk_incidents": high_risk_incidents,
                "critical_incidents": critical_incidents,
                "blocked_sources": blocked_sources,
                "isolated_clients": isolated_clients,
                "database_size_bytes": size,
                "telemetry_delay_seconds": delay,
            },
            "incident_definitions": {
                "open": "status=open; archived, closed, and false-positive incidents are excluded.",
                "active": "status=open and last_seen within the last 24 hours.",
                "high_risk": "status=open and risk_score >= 70.",
                "critical": "status=open and risk_score >= 90.",
                "telemetry_window": "events_last_24h uses the last 24 hours.",
                "test_data": "Validation incidents remain visible and carry validation_tag.",
            },
            "detections_by_category": [dict(row) for row in categories],
            "top_hosts": [dict(row) for row in top_hosts],
        }

    def dashboard_timeline(self) -> dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT substr(timestamp, 1, 13) AS hour, count(*) AS events
                FROM events
                WHERE timestamp >= ?
                GROUP BY hour
                ORDER BY hour
                """,
                (cutoff,),
            ).fetchall()
        return {"items": [dict(row) for row in rows]}

    def cleanup(self, retention_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM features WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM detections WHERE timestamp < ?", (cutoff,))
            return conn.total_changes - before
