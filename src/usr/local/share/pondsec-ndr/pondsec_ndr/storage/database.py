"""SQLite local event store for PondSec NDR."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator


SCHEMA_VERSION = 1


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

    def migrate(self) -> None:
        with self.connect() as conn:
            for statement in SCHEMA:
                conn.execute(statement)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, now_iso()),
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
                item["fingerprints"].add(fingerprint)
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
        with self.connect() as conn:
            before = conn.total_changes
            for incident in incidents:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO incidents(
                        incident_id, title, status, risk_score, severity, confidence,
                        source_ip, destination_ip, category, created_at, updated_at,
                        evidence_json, risk_factors_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident["incident_id"], incident["title"], incident.get("status", "open"),
                        incident["risk_score"], incident["severity"], incident["confidence"],
                        incident.get("source_ip"), incident.get("destination_ip"), incident.get("category"),
                        incident["created_at"], incident["updated_at"],
                        json.dumps(incident.get("evidence", {}), sort_keys=True),
                        json.dumps(incident.get("risk_factors", []), sort_keys=True),
                    ),
                )
                for detection_id in incident.get("detection_ids", []):
                    conn.execute("INSERT OR IGNORE INTO incident_detections(incident_id, detection_id) VALUES (?, ?)", (incident["incident_id"], detection_id))
                if incident.get("source_ip"):
                    conn.execute(
                        """
                        UPDATE hosts
                        SET risk_score = max(risk_score, ?),
                            open_incidents = (SELECT count(*) FROM incidents WHERE status = 'open' AND source_ip = ?)
                        WHERE ip = ?
                        """,
                        (incident["risk_score"], incident["source_ip"], incident["source_ip"]),
                    )
            return conn.total_changes - before

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

    def dashboard_summary(self) -> dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            events_24h = conn.execute("SELECT count(*) FROM events WHERE timestamp >= ?", (cutoff,)).fetchone()[0]
            open_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open'").fetchone()[0]
            critical_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 90").fetchone()[0]
            blocked_sources = conn.execute("SELECT count(*) FROM block_entries WHERE status = 'active'").fetchone()[0]
            categories = conn.execute("SELECT category, count(*) AS count FROM detections GROUP BY category ORDER BY count DESC").fetchall()
            top_hosts = conn.execute("SELECT ip, risk_score, open_incidents FROM hosts ORDER BY risk_score DESC, last_seen DESC LIMIT 10").fetchall()
            latest_event = conn.execute("SELECT max(timestamp) FROM events").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        delay = None
        if latest_event:
            delay = max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(latest_event.replace("Z", "+00:00"))).total_seconds()))
        return {
            "metrics": {
                "events_last_24h": events_24h,
                "open_incidents": open_incidents,
                "critical_incidents": critical_incidents,
                "blocked_sources": blocked_sources,
                "database_size_bytes": size,
                "telemetry_delay_seconds": delay,
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
