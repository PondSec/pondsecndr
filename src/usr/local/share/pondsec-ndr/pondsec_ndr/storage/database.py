"""SQLite local event store for PondSec NDR."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import pwd
import grp
import sqlite3
from typing import Any, Iterator
from uuid import uuid4


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

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["risk_factors"] = json.loads(item.pop("risk_factors_json"))
        return item

    def update_incident_status(self, incident_id: str, status: str, actor: str = "system") -> bool:
        if status not in {"open", "closed", "false_positive"}:
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
            critical_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 90").fetchone()[0]
            blocked_sources = conn.execute("SELECT count(DISTINCT source_ip) FROM block_entries WHERE status = 'active'").fetchone()[0]
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
