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
from uuid import NAMESPACE_URL, uuid4, uuid5


SCHEMA_VERSION = 7
INCIDENT_DEDUPE_WINDOW_SECONDS = 1800
OPEN_INCIDENT_STATUSES = ("open",)
ARCHIVED_INCIDENT_STATUSES = ("closed", "false_positive", "archived")
BASELINE_MINIMUM_OBSERVATIONS = 50
BASELINE_METRICS = [
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
BASELINE_STATUS_LABELS = {
    "building": "im_aufbau",
    "incomplete": "unvollstaendig",
    "complete": "vollstaendig",
    "updated": "aktualisiert",
    "uncertain": "unsicher",
    "learning": "im_aufbau",
    "established": "vollstaendig",
}
PEER_GROUPS = {
    "windows_clients",
    "linux_servers",
    "iot",
    "printers",
    "firewalls",
    "network_devices",
    "hypervisors",
    "dmz",
    "management",
    "servers",
    "clients",
    "unknown",
}


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
        "credential_abuse": "initial_access",
        "exploit_attempt": "initial_access",
        "supply_chain": "initial_access",
        "malware": "execution",
        "command_and_control": "command_and_control",
        "lateral_movement": "lateral_movement",
        "exfiltration": "exfiltration",
        "machine_learning": "classification",
        "signature": "signature",
        "anomaly": "host_observation",
        "multi_stage": "multi_stage",
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


def _case_entity_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text or text in {"any", "internal", "external", "auth_services", "host-baseline", "unresolved_internal_host_behind_nat"}:
        return None
    if text.startswith("port:"):
        return None
    return text


def _normalize_mac(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip().lower().replace("-", ":")
    if "." in text and ":" not in text:
        text = text.replace(".", "")
    if ":" not in text and len(text) == 12:
        text = ":".join(text[index:index + 2] for index in range(0, 12, 2))
    parts = [part.zfill(2) for part in text.split(":") if part]
    if len(parts) != 6:
        return None
    if any(len(part) != 2 or not all(char in "0123456789abcdef" for char in part) for part in parts):
        return None
    return ":".join(parts)


def _stable_entity_id(ip: str | None, mac: str | None, hostname: str | None = None) -> str:
    if mac:
        basis = f"pondsec-entity:mac:{mac}"
    elif hostname:
        basis = f"pondsec-entity:hostname:{str(hostname).strip().lower()}"
    else:
        basis = f"pondsec-entity:ip:{ip or 'unknown'}"
    return str(uuid5(NAMESPACE_URL, basis))


def _baseline_version_id(host_ip: str, version: int) -> str:
    return str(uuid5(NAMESPACE_URL, f"pondsec-baseline:{host_ip}:{version}"))


def _safe_json_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _empty_telemetry_counts() -> dict[str, int]:
    return {
        "total": 0,
        "flow": 0,
        "dns": 0,
        "tls": 0,
        "http": 0,
        "fileinfo": 0,
        "authentication": 0,
        "sandbox_verdict": 0,
        "alert_or_drop": 0,
        "incomplete": 0,
    }


def _telemetry_classes(event_type: str, destination_port: int, metadata: dict[str, Any]) -> set[str]:
    classes: set[str] = set()
    normalized = str(event_type or "").lower()
    if normalized in {"flow", "dns", "tls", "http", "fileinfo"}:
        classes.add(normalized)
    if normalized in {"alert", "drop"}:
        classes.add("alert_or_drop")
    if normalized == "authentication" or destination_port in {22, 25, 88, 110, 143, 389, 445, 465, 587, 636, 993, 995, 3389, 5985, 5986}:
        if any(metadata.get(key) for key in ("auth_result", "user", "username")) or normalized in {"http", "flow", "authentication"}:
            classes.add("authentication")
    if any(metadata.get(key) for key in ("sandbox_verdict", "sandbox_status", "sandbox_confidence", "file_verdict", "av_verdict")):
        classes.add("sandbox_verdict")
    return classes


def _incomplete_telemetry_event(event_type: str, source_ip: str | None, destination_ip: str | None, metadata: dict[str, Any]) -> bool:
    if not source_ip and not destination_ip:
        return True
    normalized = str(event_type or "").lower()
    if normalized == "dns":
        return not any(metadata.get(key) for key in ("rrname", "query", "domain"))
    if normalized == "tls":
        return not any(metadata.get(key) for key in ("sni", "tls_sni", "server_name", "hostname"))
    if normalized == "http":
        return not any(metadata.get(key) for key in ("url_path", "url", "hostname", "status", "http_method", "method"))
    if normalized == "fileinfo":
        return not any(metadata.get(key) for key in ("filename", "md5", "sha1", "sha256", "file_verdict", "sandbox_verdict"))
    return False


def _baseline_status(observations: int, minimum_observations: int = BASELINE_MINIMUM_OBSERVATIONS, drift_score: float = 0.0) -> str:
    minimum = max(1, int(minimum_observations or BASELINE_MINIMUM_OBSERVATIONS))
    if observations < max(1, minimum // 2):
        return "building"
    if observations < minimum:
        return "incomplete"
    if drift_score >= 0.7:
        return "uncertain"
    if drift_score >= 0.35:
        return "updated"
    return "complete"


def _baseline_drift(current: dict[str, Any], baseline: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    drift = 0.0
    reasons: list[dict[str, Any]] = []
    for metric in BASELINE_METRICS:
        observed = float(current.get(metric) or 0)
        expected = float(baseline.get(metric) or 0)
        if observed <= 0 or expected <= 0:
            continue
        ratio = observed / max(expected, 1.0)
        distance = abs(observed - expected) / max(observed, expected, 1.0)
        drift = max(drift, min(1.0, distance))
        if ratio >= 3 or ratio <= (1 / 3):
            reasons.append({
                "metric": metric,
                "current": round(observed, 4),
                "baseline": round(expected, 4),
                "ratio": round(ratio, 4),
                "drift": round(min(1.0, distance), 4),
            })
    return drift, reasons


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
        entity_id TEXT,
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
    CREATE TABLE IF NOT EXISTS entities (
        entity_id TEXT PRIMARY KEY,
        primary_ip TEXT,
        mac TEXT,
        hostname TEXT,
        interface TEXT,
        vlan TEXT,
        zone TEXT,
        os_name TEXT,
        confidence REAL NOT NULL DEFAULT 0.2,
        roles_json TEXT NOT NULL DEFAULT '[]',
        peer_group TEXT NOT NULL DEFAULT 'unknown',
        peer_group_source TEXT NOT NULL DEFAULT 'auto',
        peer_group_confidence REAL NOT NULL DEFAULT 0.2,
        criticality TEXT NOT NULL DEFAULT 'normal',
        tags_json TEXT NOT NULL DEFAULT '[]',
        known_services_json TEXT NOT NULL DEFAULT '[]',
        previous_ips_json TEXT NOT NULL DEFAULT '[]',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        history_json TEXT NOT NULL DEFAULT '[]'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS entity_observations (
        observation_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        ip TEXT,
        mac TEXT,
        hostname TEXT,
        interface TEXT,
        vlan TEXT,
        zone TEXT,
        confidence REAL NOT NULL,
        evidence_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS host_baselines (
        host_ip TEXT PRIMARY KEY,
        entity_id TEXT,
        observation_count INTEGER NOT NULL DEFAULT 0,
        first_observation TEXT,
        last_observation TEXT,
        baseline_version INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'building',
        drift_score REAL NOT NULL DEFAULT 0,
        updated_at TEXT,
        baseline_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS baseline_versions (
        version_id TEXT PRIMARY KEY,
        host_ip TEXT NOT NULL,
        entity_id TEXT,
        baseline_version INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        observation_count INTEGER NOT NULL,
        status TEXT NOT NULL,
        drift_score REAL NOT NULL DEFAULT 0,
        reason TEXT NOT NULL,
        baseline_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}'
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
    CREATE TABLE IF NOT EXISTS sinkhole_entries (
        sinkhole_id TEXT PRIMARY KEY,
        incident_id TEXT,
        domain TEXT NOT NULL,
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
    """
    CREATE TABLE IF NOT EXISTS incident_feedback (
        feedback_id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        source_ip TEXT,
        feedback_type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        detail_json TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_entity ON hosts(entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_entities_mac ON entities(mac)",
    "CREATE INDEX IF NOT EXISTS idx_entities_primary_ip ON entities(primary_ip)",
    "CREATE INDEX IF NOT EXISTS idx_entities_peer_group ON entities(peer_group)",
    "CREATE INDEX IF NOT EXISTS idx_entity_observations_entity ON entity_observations(entity_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_entity_observations_ip ON entity_observations(ip, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_host_baselines_status ON host_baselines(status, observation_count)",
    "CREATE INDEX IF NOT EXISTS idx_baseline_versions_host ON baseline_versions(host_ip, baseline_version)",
    "CREATE INDEX IF NOT EXISTS idx_baseline_versions_created ON baseline_versions(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_source ON incidents(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_dedupe ON incidents(status, source_ip, category, destination_ip, validation_tag, last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_incident_feedback_source ON incident_feedback(feedback_type, source_ip, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_sinkhole_domain ON sinkhole_entries(domain, status, expires_at)",
]

INCIDENT_V2_COLUMNS = {
    "first_seen",
    "last_seen",
    "event_count",
    "detection_count",
    "affected_targets_json",
    "attack_stage",
    "validation_tag",
    "suppressed_count",
}
HOST_V3_COLUMNS = {"entity_id"}
HOST_BASELINE_V4_COLUMNS = {"entity_id", "baseline_version", "status", "drift_score", "updated_at"}
ENTITY_V5_COLUMNS = {"peer_group", "peer_group_source", "peer_group_confidence"}


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
            deferred_indexes: list[str] = []
            for statement in SCHEMA:
                if statement.lstrip().upper().startswith("CREATE INDEX"):
                    deferred_indexes.append(statement)
                else:
                    conn.execute(statement)
            current_version = self._schema_version(conn)
            if current_version > SCHEMA_VERSION:
                raise RuntimeError(f"database schema {current_version} is newer than supported schema {SCHEMA_VERSION}")
            if current_version < 2:
                if current_version > 0 or self._schema_needs_v2(conn):
                    self._backup_database(conn, current_version, 2)
                self._migrate_to_v2(conn)
            if current_version < 3:
                if current_version > 0 or self._schema_needs_v3(conn):
                    self._backup_database(conn, max(current_version, 2), 3)
                self._migrate_to_v3(conn)
            if current_version < 4:
                if current_version > 0 or self._schema_needs_v4(conn):
                    self._backup_database(conn, max(current_version, 3), 4)
                self._migrate_to_v4(conn)
            if current_version < 5:
                if current_version > 0 or self._schema_needs_v5(conn):
                    self._backup_database(conn, max(current_version, 4), 5)
                self._migrate_to_v5(conn)
            if current_version < 6:
                if current_version > 0 or self._schema_needs_v6(conn):
                    self._backup_database(conn, max(current_version, 5), 6)
                self._migrate_to_v6(conn)
            for statement in deferred_indexes:
                conn.execute(statement)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, now_iso()),
            )

    def _schema_version(self, conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT max(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0)

    def _schema_needs_v2(self, conn: sqlite3.Connection) -> bool:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        return bool(columns) and not INCIDENT_V2_COLUMNS.issubset(columns)

    def _schema_needs_v3(self, conn: sqlite3.Connection) -> bool:
        host_columns = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()}
        entity_columns = {row["name"] for row in conn.execute("PRAGMA table_info(entities)").fetchall()}
        observation_columns = {row["name"] for row in conn.execute("PRAGMA table_info(entity_observations)").fetchall()}
        return (bool(host_columns) and not HOST_V3_COLUMNS.issubset(host_columns)) or not entity_columns or not observation_columns

    def _schema_needs_v4(self, conn: sqlite3.Connection) -> bool:
        baseline_columns = {row["name"] for row in conn.execute("PRAGMA table_info(host_baselines)").fetchall()}
        version_columns = {row["name"] for row in conn.execute("PRAGMA table_info(baseline_versions)").fetchall()}
        return (bool(baseline_columns) and not HOST_BASELINE_V4_COLUMNS.issubset(baseline_columns)) or not version_columns

    def _schema_needs_v5(self, conn: sqlite3.Connection) -> bool:
        entity_columns = {row["name"] for row in conn.execute("PRAGMA table_info(entities)").fetchall()}
        return bool(entity_columns) and not ENTITY_V5_COLUMNS.issubset(entity_columns)

    def _schema_needs_v6(self, conn: sqlite3.Connection) -> bool:
        entity_columns = {row["name"] for row in conn.execute("PRAGMA table_info(entities)").fetchall()}
        if not ENTITY_V5_COLUMNS.issubset(entity_columns):
            return False
        count = conn.execute("SELECT count(*) FROM entities WHERE peer_group_source = 'auto'").fetchone()[0]
        return int(count or 0) > 0

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

    def _migrate_to_v3(self, conn: sqlite3.Connection) -> None:
        host_columns = {row["name"] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()}
        if "entity_id" not in host_columns:
            conn.execute("ALTER TABLE hosts ADD COLUMN entity_id TEXT")
        rows = conn.execute(
            """
            SELECT ip, hostname, mac, interface, vlan, first_seen, last_seen,
                   known_ports_json
            FROM hosts
            """
        ).fetchall()
        for row in rows:
            entity_id = self._resolve_entity(conn, {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "mac": row["mac"],
                "interface": row["interface"],
                "vlan": row["vlan"],
                "known_services": self._safe_json_list(row["known_ports_json"]),
                "raw_sources": ["migration"],
            }, row["last_seen"] or row["first_seen"] or now_iso())
            conn.execute("UPDATE hosts SET entity_id = ? WHERE ip = ?", (entity_id, row["ip"]))
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (3, now_iso()),
        )

    def _migrate_to_v4(self, conn: sqlite3.Connection) -> None:
        baseline_columns = {row["name"] for row in conn.execute("PRAGMA table_info(host_baselines)").fetchall()}
        additions = {
            "entity_id": "ALTER TABLE host_baselines ADD COLUMN entity_id TEXT",
            "baseline_version": "ALTER TABLE host_baselines ADD COLUMN baseline_version INTEGER NOT NULL DEFAULT 1",
            "status": "ALTER TABLE host_baselines ADD COLUMN status TEXT NOT NULL DEFAULT 'building'",
            "drift_score": "ALTER TABLE host_baselines ADD COLUMN drift_score REAL NOT NULL DEFAULT 0",
            "updated_at": "ALTER TABLE host_baselines ADD COLUMN updated_at TEXT",
        }
        for column, statement in additions.items():
            if column not in baseline_columns:
                conn.execute(statement)
        rows = conn.execute(
            """
            SELECT b.host_ip, b.observation_count, b.first_observation, b.last_observation,
                   b.baseline_json, b.baseline_version, b.status, b.drift_score,
                   b.updated_at, h.entity_id AS host_entity_id
            FROM host_baselines b
            LEFT JOIN hosts h ON h.ip = b.host_ip
            """
        ).fetchall()
        for row in rows:
            observations = int(row["observation_count"] or 0)
            status = row["status"] or _baseline_status(observations)
            if status == "learning":
                status = _baseline_status(observations)
            elif status == "established":
                status = "complete"
            baseline_version = int(row["baseline_version"] or 1)
            observed_at = row["last_observation"] or row["first_observation"] or now_iso()
            entity_id = row["host_entity_id"]
            conn.execute(
                """
                UPDATE host_baselines
                SET entity_id = COALESCE(entity_id, ?),
                    baseline_version = ?,
                    status = ?,
                    drift_score = COALESCE(drift_score, 0),
                    updated_at = COALESCE(updated_at, ?)
                WHERE host_ip = ?
                """,
                (entity_id, baseline_version, status, observed_at, row["host_ip"]),
            )
            self._insert_baseline_version(
                conn,
                row["host_ip"],
                entity_id,
                baseline_version,
                observed_at,
                observations,
                status,
                float(row["drift_score"] or 0),
                row["baseline_json"] or "{}",
                "migration",
                {"source_schema": 3},
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (4, now_iso()),
        )

    def _insert_baseline_version(
        self,
        conn: sqlite3.Connection,
        host_ip: str,
        entity_id: str | None,
        baseline_version: int,
        created_at: str,
        observation_count: int,
        status: str,
        drift_score: float,
        baseline_json: str,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT OR IGNORE INTO baseline_versions(
                version_id, host_ip, entity_id, baseline_version, created_at,
                observation_count, status, drift_score, reason,
                baseline_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _baseline_version_id(host_ip, baseline_version),
                host_ip,
                entity_id,
                baseline_version,
                created_at,
                observation_count,
                status,
                drift_score,
                reason,
                baseline_json,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )

    def _migrate_to_v5(self, conn: sqlite3.Connection) -> None:
        entity_columns = {row["name"] for row in conn.execute("PRAGMA table_info(entities)").fetchall()}
        additions = {
            "peer_group": "ALTER TABLE entities ADD COLUMN peer_group TEXT NOT NULL DEFAULT 'unknown'",
            "peer_group_source": "ALTER TABLE entities ADD COLUMN peer_group_source TEXT NOT NULL DEFAULT 'auto'",
            "peer_group_confidence": "ALTER TABLE entities ADD COLUMN peer_group_confidence REAL NOT NULL DEFAULT 0.2",
        }
        for column, statement in additions.items():
            if column not in entity_columns:
                conn.execute(statement)
        rows = conn.execute(
            """
            SELECT entity_id, hostname, interface, vlan, zone, os_name,
                   roles_json, known_services_json, peer_group,
                   peer_group_source, peer_group_confidence
            FROM entities
            """
        ).fetchall()
        for row in rows:
            if row["peer_group_source"] == "manual" and row["peer_group"] in PEER_GROUPS:
                continue
            roles = set(self._safe_json_list(row["roles_json"]))
            services = [str(item) for item in self._safe_json_list(row["known_services_json"])]
            peer_group, source, confidence = self._infer_peer_group(
                roles=roles,
                os_name=row["os_name"],
                hostname=row["hostname"],
                services=services,
                vlan=row["vlan"],
                zone=row["zone"],
                interface=row["interface"],
                evidence={},
            )
            conn.execute(
                """
                UPDATE entities
                SET peer_group = ?, peer_group_source = ?, peer_group_confidence = ?
                WHERE entity_id = ?
                """,
                (peer_group, source, confidence, row["entity_id"]),
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (5, now_iso()),
        )

    def _migrate_to_v6(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT entity_id, hostname, interface, vlan, zone, os_name,
                   roles_json, known_services_json, peer_group_source
            FROM entities
            WHERE peer_group_source != 'manual'
            """
        ).fetchall()
        for row in rows:
            roles = set(self._safe_json_list(row["roles_json"]))
            services = [str(item) for item in self._safe_json_list(row["known_services_json"])]
            peer_group, source, confidence = self._infer_peer_group(
                roles=roles,
                os_name=row["os_name"],
                hostname=row["hostname"],
                services=services,
                vlan=row["vlan"],
                zone=row["zone"],
                interface=row["interface"],
                evidence={},
            )
            conn.execute(
                """
                UPDATE entities
                SET peer_group = ?, peer_group_source = ?, peer_group_confidence = ?
                WHERE entity_id = ?
                """,
                (peer_group, source, confidence, row["entity_id"]),
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (6, now_iso()),
        )

    def check(self, integrity: str = "full") -> dict[str, Any]:
        mode = str(integrity or "full").lower()
        if mode not in {"full", "quick", "light"}:
            mode = "full"
        with self.connect() as conn:
            if mode == "light":
                result = "not_run"
            else:
                pragma = "quick_check" if mode == "quick" else "integrity_check"
                result = conn.execute(f"PRAGMA {pragma}").fetchone()[0]
            version = conn.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        status = "ok" if result in {"ok", "not_run"} else "corrupt"
        return {
            "status": status,
            "integrity": result,
            "integrity_mode": mode,
            "schema_version": version,
            "size_bytes": size,
        }

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

    def recent_events(self, since: str, limit: int = 5000) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit or 5000), 50000))
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM (
                    SELECT event_id, schema_version, event_type, timestamp,
                           source_ip, source_port, source_interface,
                           destination_ip, destination_port, protocol, direction,
                           metadata_json, raw_source
                    FROM events
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                )
                ORDER BY timestamp ASC
                """,
                (since, limit),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except json.JSONDecodeError:
                metadata = {}
            events.append({
                "event_id": row["event_id"],
                "schema_version": row["schema_version"],
                "event_type": row["event_type"],
                "timestamp": row["timestamp"],
                "source": {
                    "ip": row["source_ip"],
                    "port": row["source_port"],
                    "interface": row["source_interface"],
                },
                "destination": {
                    "ip": row["destination_ip"],
                    "port": row["destination_port"],
                },
                "protocol": row["protocol"],
                "direction": row["direction"],
                "metadata": metadata,
                "raw_source": row["raw_source"],
            })
        return events

    def _upsert_hosts(self, conn: sqlite3.Connection, events: list[dict[str, Any]]) -> None:
        by_host: dict[str, dict[str, Any]] = {}
        for event in events:
            src = event.get("source", {}).get("ip")
            if not src:
                continue
            metadata = event.get("metadata", {})
            item = by_host.setdefault(src, {
                "first": event["timestamp"],
                "last": event["timestamp"],
                "destinations": set(),
                "ports": set(),
                "fingerprints": set(),
                "interface": event.get("source", {}).get("interface"),
                "hostname": metadata.get("hostname") or metadata.get("device_name"),
                "mac": metadata.get("mac") or metadata.get("device_id"),
                "vlan": metadata.get("vlan") or metadata.get("vlan_id"),
                "zone": metadata.get("zone") or event.get("direction"),
                "os_name": metadata.get("os") or metadata.get("os_name") or metadata.get("device_os"),
                "services": set(),
                "sources": set(),
            })
            item["first"] = min(item["first"], event["timestamp"])
            item["last"] = max(item["last"], event["timestamp"])
            dst = event.get("destination", {}).get("ip")
            port = event.get("destination", {}).get("port")
            fingerprint = metadata.get("fingerprint")
            raw_source = event.get("raw_source") or metadata.get("event_source") or "unknown"
            item["sources"].add(str(raw_source))
            if metadata.get("hostname") or metadata.get("device_name"):
                item["hostname"] = metadata.get("hostname") or metadata.get("device_name")
            if metadata.get("mac") or metadata.get("device_id"):
                item["mac"] = metadata.get("mac") or metadata.get("device_id")
            if metadata.get("vlan") or metadata.get("vlan_id"):
                item["vlan"] = metadata.get("vlan") or metadata.get("vlan_id")
            if metadata.get("zone"):
                item["zone"] = metadata.get("zone")
            if metadata.get("os") or metadata.get("os_name") or metadata.get("device_os"):
                item["os_name"] = metadata.get("os") or metadata.get("os_name") or metadata.get("device_os")
            if metadata.get("interface") and not item.get("interface"):
                item["interface"] = metadata.get("interface")
            if dst:
                item["destinations"].add(dst)
            if port is not None:
                item["ports"].add(port)
                item["services"].add(str(port))
            if fingerprint:
                item["fingerprints"].add(_stable_set_value(fingerprint))
        for ip, item in by_host.items():
            entity_id = self._resolve_entity(conn, {
                "ip": ip,
                "mac": item.get("mac"),
                "hostname": item.get("hostname"),
                "interface": item.get("interface"),
                "vlan": item.get("vlan"),
                "zone": item.get("zone"),
                "os_name": item.get("os_name"),
                "known_services": sorted(item["services"]),
                "raw_sources": sorted(item["sources"]),
            }, item["last"])
            row = conn.execute("SELECT known_destinations_json, known_ports_json, known_tls_fingerprints_json, first_seen FROM hosts WHERE ip = ?", (ip,)).fetchone()
            if row:
                destinations = set(json.loads(row["known_destinations_json"])) | item["destinations"]
                ports = set(json.loads(row["known_ports_json"])) | {str(port) for port in item["ports"]}
                fingerprints = set(json.loads(row["known_tls_fingerprints_json"])) | item["fingerprints"]
                first_seen = min(row["first_seen"], item["first"])
                conn.execute(
                    """
                    UPDATE hosts
                    SET entity_id = ?, first_seen = ?, last_seen = ?, interface = COALESCE(?, interface),
                        hostname = COALESCE(?, hostname), mac = COALESCE(?, mac), vlan = COALESCE(?, vlan),
                        known_destinations_json = ?, known_ports_json = ?,
                        known_tls_fingerprints_json = ?
                    WHERE ip = ?
                    """,
                    (
                        entity_id,
                        first_seen,
                        item["last"],
                        item["interface"],
                        item.get("hostname"),
                        _normalize_mac(item.get("mac")) or item.get("mac"),
                        item.get("vlan"),
                        json.dumps(sorted(destinations)),
                        json.dumps(sorted(ports)),
                        json.dumps(sorted(fingerprints)),
                        ip,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO hosts(ip, entity_id, hostname, mac, vlan, interface, first_seen, last_seen, known_destinations_json, known_ports_json, known_tls_fingerprints_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip,
                        entity_id,
                        item.get("hostname"),
                        _normalize_mac(item.get("mac")) or item.get("mac"),
                        item.get("vlan"),
                        item["interface"],
                        item["first"],
                        item["last"],
                        json.dumps(sorted(item["destinations"])),
                        json.dumps(sorted(str(port) for port in item["ports"])),
                        json.dumps(sorted(item["fingerprints"])),
                    ),
                )

    def _resolve_entity(self, conn: sqlite3.Connection, evidence: dict[str, Any], observed_at: str) -> str:
        ip = str(evidence.get("ip") or "") or None
        mac = _normalize_mac(evidence.get("mac") or evidence.get("device_id"))
        hostname = str(evidence.get("hostname") or "").strip() or None
        interface = str(evidence.get("interface") or "").strip() or None
        vlan = str(evidence.get("vlan") or "").strip() or None
        zone = str(evidence.get("zone") or "").strip() or None
        os_name = str(evidence.get("os_name") or evidence.get("os") or "").strip() or None
        raw_sources = self._safe_json_list(evidence.get("raw_sources"))
        known_services = [str(item) for item in self._safe_json_list(evidence.get("known_services")) if str(item)]
        confidence = self._entity_confidence(evidence, mac, hostname)
        row = self._find_entity(conn, ip, mac, hostname)
        entity_id = row["entity_id"] if row else _stable_entity_id(ip, mac, hostname)
        roles = set(self._safe_json_list(row["roles_json"] if row else []))
        roles.update(self._infer_entity_roles(evidence, ip, os_name))
        services = set(self._safe_json_list(row["known_services_json"] if row else []))
        services.update(known_services)
        existing_peer_source = str(row["peer_group_source"]) if row and "peer_group_source" in row.keys() else "auto"
        if existing_peer_source == "manual":
            peer_group = str(row["peer_group"] or "unknown")
            peer_group_source = "manual"
            peer_group_confidence = float(row["peer_group_confidence"] or 0.95)
        else:
            peer_group, peer_group_source, peer_group_confidence = self._infer_peer_group(
                roles=roles,
                os_name=os_name or (row["os_name"] if row else None),
                hostname=hostname or (row["hostname"] if row else None),
                services=sorted(str(item) for item in services),
                vlan=vlan or (row["vlan"] if row else None),
                zone=zone or (row["zone"] if row else None),
                interface=interface or (row["interface"] if row else None),
                evidence=evidence,
            )
        tags = set(self._safe_json_list(row["tags_json"] if row else []))
        tags.update(f"source:{source}" for source in raw_sources if source)
        previous_ips = set(self._safe_json_list(row["previous_ips_json"] if row else []))
        if row and row["primary_ip"] and ip and row["primary_ip"] != ip:
            previous_ips.add(str(row["primary_ip"]))
        if ip:
            previous_ips.add(ip)
        history = self._safe_json_list(row["history_json"] if row else [])
        history.append({
            "observed_at": observed_at,
            "source": raw_sources or [str(evidence.get("source") or "unknown")],
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "interface": interface,
            "vlan": vlan,
            "zone": zone,
            "peer_group": peer_group,
            "confidence": confidence,
        })
        history = history[-50:]
        if row:
            first_seen = min(str(row["first_seen"]), observed_at)
            last_seen = max(str(row["last_seen"]), observed_at)
            conn.execute(
                """
                UPDATE entities
                SET primary_ip = COALESCE(?, primary_ip),
                    mac = COALESCE(?, mac),
                    hostname = COALESCE(?, hostname),
                    interface = COALESCE(?, interface),
                    vlan = COALESCE(?, vlan),
                    zone = COALESCE(?, zone),
                    os_name = COALESCE(?, os_name),
                    confidence = max(confidence, ?),
                    roles_json = ?,
                    peer_group = ?,
                    peer_group_source = ?,
                    peer_group_confidence = max(peer_group_confidence, ?),
                    tags_json = ?,
                    known_services_json = ?,
                    previous_ips_json = ?,
                    first_seen = ?,
                    last_seen = ?,
                    history_json = ?
                WHERE entity_id = ?
                """,
                (
                    ip,
                    mac,
                    hostname,
                    interface,
                    vlan,
                    zone,
                    os_name,
                    confidence,
                    json.dumps(sorted(roles)),
                    peer_group,
                    peer_group_source,
                    peer_group_confidence,
                    json.dumps(sorted(tags)),
                    json.dumps(sorted(services)),
                    json.dumps(sorted(previous_ips)),
                    first_seen,
                    last_seen,
                    json.dumps(history, sort_keys=True),
                    entity_id,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO entities(
                    entity_id, primary_ip, mac, hostname, interface, vlan, zone,
                    os_name, confidence, roles_json, peer_group, peer_group_source,
                    peer_group_confidence, criticality, tags_json,
                    known_services_json, previous_ips_json, first_seen, last_seen,
                    history_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entity_id,
                    ip,
                    mac,
                    hostname,
                    interface,
                    vlan,
                    zone,
                    os_name,
                    confidence,
                    json.dumps(sorted(roles)),
                    peer_group,
                    peer_group_source,
                    peer_group_confidence,
                    "normal",
                    json.dumps(sorted(tags)),
                    json.dumps(sorted(services)),
                    json.dumps(sorted(previous_ips)),
                    observed_at,
                    observed_at,
                    json.dumps(history, sort_keys=True),
                ),
            )
        conn.execute(
            """
            INSERT INTO entity_observations(
                observation_id, entity_id, timestamp, source, ip, mac, hostname,
                interface, vlan, zone, confidence, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                entity_id,
                observed_at,
                ",".join(raw_sources) if raw_sources else str(evidence.get("source") or "unknown"),
                ip,
                mac,
                hostname,
                interface,
                vlan,
                zone,
                confidence,
                json.dumps(evidence, sort_keys=True, default=str),
            ),
        )
        return entity_id

    def _find_entity(self, conn: sqlite3.Connection, ip: str | None, mac: str | None, hostname: str | None) -> sqlite3.Row | None:
        if mac:
            row = conn.execute("SELECT * FROM entities WHERE mac = ? ORDER BY last_seen DESC LIMIT 1", (mac,)).fetchone()
            if row:
                return row
        if hostname:
            row = conn.execute("SELECT * FROM entities WHERE lower(hostname) = lower(?) ORDER BY last_seen DESC LIMIT 1", (hostname,)).fetchone()
            if row:
                return row
        if ip:
            row = conn.execute("SELECT * FROM entities WHERE primary_ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
            if row:
                return row
            rows = conn.execute("SELECT * FROM entities ORDER BY last_seen DESC LIMIT 1000").fetchall()
            for candidate in rows:
                if ip in self._safe_json_list(candidate["previous_ips_json"]):
                    return candidate
        return None

    @staticmethod
    def _entity_confidence(evidence: dict[str, Any], mac: str | None, hostname: str | None) -> float:
        explicit = evidence.get("entity_confidence")
        try:
            if explicit is not None:
                return max(0.0, min(1.0, float(explicit)))
        except (TypeError, ValueError):
            pass
        if mac and hostname:
            return 0.98
        if mac:
            return 0.95
        if hostname:
            return 0.72
        return 0.45

    @staticmethod
    def _infer_entity_roles(evidence: dict[str, Any], ip: str | None, os_name: str | None) -> set[str]:
        roles: set[str] = set()
        sources = {str(item).lower() for item in EventStore._safe_json_list(evidence.get("raw_sources"))}
        if "dnsmasq" in sources or evidence.get("dhcp_action"):
            roles.add("dhcp_client")
        if "zenarmor" in sources:
            roles.add("network_client")
        os_text = str(os_name or "").lower()
        if "windows" in os_text:
            roles.add("windows_client")
        elif "linux" in os_text:
            roles.add("linux_host")
        elif "android" in os_text or "apple" in os_text or "ios" in os_text:
            roles.add("client")
        if ip and _is_private_address(ip):
            roles.add("internal")
        return roles

    @staticmethod
    def _infer_peer_group(
        *,
        roles: set[str],
        os_name: str | None,
        hostname: str | None,
        services: list[str],
        vlan: str | None,
        zone: str | None,
        interface: str | None,
        evidence: dict[str, Any],
    ) -> tuple[str, str, float]:
        explicit = str(evidence.get("peer_group") or "").strip().lower()
        if explicit in PEER_GROUPS:
            return explicit, "metadata", 0.95

        os_text = str(os_name or "").lower()
        host_text = str(hostname or "").lower()
        zone_text = str(zone or "").lower()
        interface_text = str(interface or "").lower()
        vlan_text = str(vlan or "").lower()
        joined = " ".join([os_text, host_text, zone_text, interface_text, vlan_text])

        if "management" in joined or "mgmt" in joined:
            return "management", "auto", 0.82
        if "dmz" in joined:
            return "dmz", "auto", 0.8
        if "firewall" in roles or any(token in joined for token in ("opnsense", "pfsense", "fortigate", "firewall")):
            return "firewalls", "auto", 0.9
        if "hypervisor" in roles or any(token in joined for token in ("esxi", "vmware", "proxmox", "hyper-v", "xcp-ng", "hypervisor")):
            return "hypervisors", "auto", 0.88
        if "network_device" in roles or any(token in joined for token in ("switch", "router", "access-point", "access point", "unifi", "ubnt", "mikrotik", "routeros")):
            return "network_devices", "auto", 0.84
        if "printer" in roles or any(token in joined for token in ("printer", "airprint", "brother", "canon", "epson", "hewlett", "laserjet")):
            return "printers", "auto", 0.86
        if "iot" in roles or any(token in joined for token in ("iot", "camera", "thermostat", "display", "echo", "ring", "tv", "roku", "chromecast")):
            return "iot", "auto", 0.78
        if "windows" in os_text and "server" not in os_text:
            return "windows_clients", "auto", 0.8
        server_name = any(token in host_text for token in ("server", "srv", "nas"))
        if ("linux" in os_text and server_name) or "linux server" in os_text:
            return "linux_servers", "auto", 0.76
        if server_name or "server" in os_text:
            return "servers", "auto", 0.62
        if roles & {"client", "network_client", "dhcp_client", "windows_client"}:
            return "clients", "auto", 0.62
        return "unknown", "auto", 0.2

    @staticmethod
    def _safe_json_list(value: Any) -> list[Any]:
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, set):
            return sorted(value)
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return [value]
            return parsed if isinstance(parsed, list) else [parsed]
        return [value]

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

    def score_features_against_baselines(
        self,
        features: list[dict[str, Any]],
        minimum_observations: int = 50,
        minimum_peer_members: int = 3,
    ) -> list[dict[str, Any]]:
        if not features:
            return features
        minimum_observations = max(1, int(minimum_observations or BASELINE_MINIMUM_OBSERVATIONS))
        minimum_peer_members = max(2, int(minimum_peer_members or 3))
        feature_ips = [item["source_ip"] for item in features]
        with self.connect() as conn:
            source_rows = {
                row["ip"]: dict(row)
                for row in conn.execute(
                    """
                    SELECT h.ip, h.entity_id, e.peer_group, e.peer_group_confidence
                    FROM hosts h
                    LEFT JOIN entities e ON e.entity_id = h.entity_id
                    WHERE h.ip IN ({})
                    """.format(",".join("?" for _ in features)),
                    feature_ips,
                ).fetchall()
            } if features else {}
            baseline_rows = {
                row["host_ip"]: dict(row)
                for row in conn.execute(
                    """
                    SELECT b.host_ip, b.entity_id, b.observation_count,
                           b.baseline_json, b.baseline_version, b.status,
                           b.drift_score, b.updated_at, e.peer_group,
                           e.peer_group_confidence
                    FROM host_baselines b
                    LEFT JOIN hosts h ON h.ip = b.host_ip
                    LEFT JOIN entities e ON e.entity_id = COALESCE(b.entity_id, h.entity_id)
                    WHERE b.host_ip IN ({})
                    """.format(
                        ",".join("?" for _ in features)
                    ),
                    feature_ips,
                ).fetchall()
            } if features else {}
            peer_group_names = sorted({
                str((source_rows.get(ip) or {}).get("peer_group") or (baseline_rows.get(ip) or {}).get("peer_group") or "")
                for ip in feature_ips
            } - {"", "unknown"})
            peer_group_rows = conn.execute(
                """
                SELECT e.peer_group, b.baseline_json
                FROM host_baselines b
                LEFT JOIN hosts h ON h.ip = b.host_ip
                LEFT JOIN entities e ON e.entity_id = COALESCE(b.entity_id, h.entity_id)
                WHERE e.peer_group IN ({})
                  AND b.observation_count >= ?
                  AND b.status IN ('complete', 'updated', 'uncertain', 'established')
                """.format(",".join("?" for _ in peer_group_names)),
                [*peer_group_names, minimum_observations],
            ).fetchall() if peer_group_names else []
        peer_baselines: dict[str, dict[str, Any]] = {}
        grouped_peer_rows: dict[str, list[dict[str, Any]]] = {}
        for row in peer_group_rows:
            grouped_peer_rows.setdefault(str(row["peer_group"]), []).append(_safe_json_dict(row["baseline_json"]))
        for peer_group, baselines in grouped_peer_rows.items():
            if len(baselines) < minimum_peer_members:
                continue
            averaged: dict[str, float] = {}
            for metric in BASELINE_METRICS:
                values = [float(item.get(metric) or 0) for item in baselines if float(item.get(metric) or 0) > 0]
                averaged[metric] = sum(values) / len(values) if values else 0.0
            peer_baselines[peer_group] = {"count": len(baselines), "baseline": averaged}
        scored = []
        for item in features:
            enriched = dict(item)
            row = baseline_rows.get(item["source_ip"])
            source_row = source_rows.get(item["source_ip"])
            peer_group = str((source_row or {}).get("peer_group") or (row or {}).get("peer_group") or "unknown")
            peer_confidence = float((source_row or {}).get("peer_group_confidence") or (row or {}).get("peer_group_confidence") or 0.0)
            reasons: list[dict[str, Any]] = []
            score = float(enriched.get("baseline_deviation") or 0)
            enriched["peer_group"] = peer_group
            enriched["peer_group_confidence"] = round(peer_confidence, 4)
            if row and int(row["observation_count"]) >= minimum_observations:
                baseline = _safe_json_dict(row["baseline_json"])
                for metric in BASELINE_METRICS:
                    current = float(enriched.get(metric) or 0)
                    expected = float(baseline.get(metric) or 0)
                    if current <= 0 or expected <= 0:
                        continue
                    ratio = current / max(expected, 1.0)
                    if ratio >= 3:
                        metric_score = min(1.0, (ratio - 1) / 10)
                        score = max(score, metric_score)
                        reasons.append({"metric": metric, "current": round(current, 4), "baseline": round(expected, 4), "ratio": round(ratio, 4)})
                computed_drift, drift_reasons = _baseline_drift(enriched, baseline)
                drift_score = max(float(row["drift_score"] or 0), computed_drift, score if reasons else 0.0)
                status = _baseline_status(int(row["observation_count"]), minimum_observations, drift_score)
                enriched["baseline_status"] = status
                enriched["baseline_status_label"] = BASELINE_STATUS_LABELS.get(status, status)
                enriched["baseline_legacy_status"] = "established"
                enriched["baseline_observations"] = int(row["observation_count"])
                enriched["baseline_version"] = int(row["baseline_version"] or 1)
                enriched["baseline_entity_id"] = row["entity_id"]
                enriched["baseline_drift_score"] = round(min(1.0, drift_score), 4)
                enriched["baseline_updated_at"] = row["updated_at"]
                enriched["baseline_anomaly_reasons"] = (reasons + drift_reasons)[:6]
            else:
                observations = int(row["observation_count"]) if row else 0
                status = _baseline_status(observations, minimum_observations)
                enriched["baseline_status"] = status
                enriched["baseline_status_label"] = BASELINE_STATUS_LABELS.get(status, status)
                enriched["baseline_legacy_status"] = "learning"
                enriched["baseline_observations"] = int(row["observation_count"]) if row else 0
                enriched["baseline_version"] = int(row["baseline_version"] or 0) if row else 0
                enriched["baseline_entity_id"] = row["entity_id"] if row else None
                enriched["baseline_drift_score"] = round(float(row["drift_score"] or 0), 4) if row else 0.0
                enriched["baseline_updated_at"] = row["updated_at"] if row else None
                enriched["baseline_anomaly_reasons"] = []
            peer_info = peer_baselines.get(peer_group)
            if peer_group == "unknown":
                enriched["peer_group_status"] = "unknown"
                enriched["peer_group_size"] = 0
                enriched["peer_group_deviation"] = 0.0
                enriched["peer_group_anomaly_reasons"] = []
            elif not peer_info:
                observed_count = len(grouped_peer_rows.get(peer_group, []))
                enriched["peer_group_status"] = "insufficient_peers" if observed_count < minimum_peer_members else "no_peer_baseline"
                enriched["peer_group_size"] = observed_count
                enriched["peer_group_deviation"] = 0.0
                enriched["peer_group_anomaly_reasons"] = []
            else:
                peer_score, peer_reasons = _baseline_drift(enriched, peer_info["baseline"])
                enriched["peer_group_status"] = "ready"
                enriched["peer_group_size"] = int(peer_info["count"])
                enriched["peer_group_deviation"] = round(min(1.0, peer_score), 4)
                enriched["peer_group_anomaly_reasons"] = peer_reasons[:6]
            enriched["baseline_deviation"] = round(min(1.0, score), 4)
            scored.append(enriched)
        return scored

    def update_host_baselines(
        self,
        features: list[dict[str, Any]],
        skip_sources: set[str] | None = None,
        minimum_observations: int = BASELINE_MINIMUM_OBSERVATIONS,
    ) -> int:
        if not features:
            return 0
        skip_sources = skip_sources or set()
        minimum_observations = max(1, int(minimum_observations or BASELINE_MINIMUM_OBSERVATIONS))
        updated = 0
        with self.connect() as conn:
            for item in features:
                source_ip = item["source_ip"]
                if source_ip in skip_sources:
                    continue
                now = now_iso()
                row = conn.execute(
                    """
                    SELECT host_ip, entity_id, observation_count, first_observation,
                           baseline_json, baseline_version, status, drift_score
                    FROM host_baselines
                    WHERE host_ip = ?
                    """,
                    (source_ip,),
                ).fetchone()
                host_row = conn.execute("SELECT entity_id FROM hosts WHERE ip = ?", (source_ip,)).fetchone()
                entity_id = (host_row["entity_id"] if host_row else None) or (row["entity_id"] if row else None)
                if row:
                    count = int(row["observation_count"])
                    baseline = _safe_json_dict(row["baseline_json"])
                    next_count = count + 1
                    previous_drift = float(row["drift_score"] or 0)
                    drift_score, drift_reasons = _baseline_drift(item, baseline)
                    if count < minimum_observations:
                        alpha = 1.0 / next_count
                    else:
                        alpha = 0.02 if drift_score >= 0.5 else 0.05
                    for metric in BASELINE_METRICS:
                        current = float(item.get(metric) or 0)
                        previous = float(baseline.get(metric) or 0)
                        if count < minimum_observations:
                            baseline[metric] = ((previous * count) + current) / next_count
                        else:
                            baseline[metric] = (previous * (1 - alpha)) + (current * alpha)
                    previous_status = row["status"] or _baseline_status(count, minimum_observations, previous_drift)
                    if previous_status == "learning":
                        previous_status = _baseline_status(count, minimum_observations, previous_drift)
                    elif previous_status == "established":
                        previous_status = "complete"
                    status = _baseline_status(next_count, minimum_observations, drift_score)
                    current_version = int(row["baseline_version"] or 1)
                    crossed_drift = drift_score >= 0.35 and previous_drift < 0.35
                    crossed_minimum = count < minimum_observations <= next_count
                    status_changed = status != previous_status
                    periodic_snapshot = next_count >= minimum_observations and next_count % 250 == 0
                    snapshot_reason = ""
                    if crossed_minimum:
                        snapshot_reason = "minimum_observations_reached"
                    elif crossed_drift:
                        snapshot_reason = "drift_threshold_crossed"
                    elif status_changed:
                        snapshot_reason = "status_changed"
                    elif periodic_snapshot:
                        snapshot_reason = "periodic_refresh"
                    next_version = current_version + 1 if snapshot_reason else current_version
                    baseline_json = json.dumps(baseline, sort_keys=True)
                    conn.execute(
                        """
                        UPDATE host_baselines
                        SET entity_id = COALESCE(?, entity_id),
                            observation_count = ?,
                            last_observation = ?,
                            baseline_version = ?,
                            status = ?,
                            drift_score = ?,
                            updated_at = ?,
                            baseline_json = ?
                        WHERE host_ip = ?
                        """,
                        (entity_id, next_count, now, next_version, status, drift_score, now, baseline_json, source_ip),
                    )
                    if snapshot_reason:
                        self._insert_baseline_version(
                            conn,
                            source_ip,
                            entity_id,
                            next_version,
                            now,
                            next_count,
                            status,
                            drift_score,
                            baseline_json,
                            snapshot_reason,
                            {
                                "adaptation_alpha": alpha,
                                "previous_status": previous_status,
                                "previous_version": current_version,
                                "drift_reasons": drift_reasons[:6],
                            },
                        )
                else:
                    baseline = {metric: float(item.get(metric) or 0) for metric in BASELINE_METRICS}
                    status = _baseline_status(1, minimum_observations)
                    baseline_json = json.dumps(baseline, sort_keys=True)
                    conn.execute(
                        """
                        INSERT INTO host_baselines(
                            host_ip, entity_id, observation_count, first_observation,
                            last_observation, baseline_version, status, drift_score,
                            updated_at, baseline_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (source_ip, entity_id, 1, now, now, 1, status, 0.0, now, baseline_json),
                    )
                    self._insert_baseline_version(
                        conn,
                        source_ip,
                        entity_id,
                        1,
                        now,
                        1,
                        status,
                        0.0,
                        baseline_json,
                        "initial",
                        {"adaptation_alpha": 1.0},
                    )
                conn.execute(
                    "UPDATE hosts SET learning_status = ?, baseline_deviation = ? WHERE ip = ?",
                    (
                        "established" if int((row["observation_count"] if row else 0)) + 1 >= minimum_observations else "learning",
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
                existing = self._find_incident_by_id(conn, prepared["incident_id"])
                if existing and existing["status"] in OPEN_INCIDENT_STATUSES:
                    self._merge_incident(conn, existing, prepared)
                elif existing:
                    incident["incident_id"] = existing["incident_id"]
                    prepared["incident_id"] = existing["incident_id"]
                else:
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

    @staticmethod
    def _find_incident_by_id(conn: sqlite3.Connection, incident_id: str) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()

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
        for target in incident.get("affected_targets") or []:
            if target:
                targets.add(str(target))
        if incident.get("destination_ip"):
            targets.add(str(incident["destination_ip"]))
        roles = evidence.get("entity_roles", {}) if isinstance(evidence, dict) else {}
        if isinstance(roles, dict):
            for key in ("victim", "affected_host", "pivot_host", "destination"):
                if roles.get(key):
                    targets.add(str(roles[key]))
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
              AND COALESCE(validation_tag, '') = COALESCE(?, '')
              AND COALESCE(last_seen, updated_at) >= ?
            ORDER BY COALESCE(last_seen, updated_at) DESC
            LIMIT 50
            """,
            (incident.get("validation_tag"), cutoff),
        ).fetchall()
        for row in rows:
            if self._incident_related(row, incident):
                return row
        return None

    @staticmethod
    def _incident_related(row: sqlite3.Row, incident: dict[str, Any]) -> bool:
        existing_source = _case_entity_value(row["source_ip"])
        incoming_source = _case_entity_value(incident.get("source_ip"))
        if existing_source and incoming_source and existing_source == incoming_source:
            return EventStore._incident_target_matches(row, incident)
        try:
            existing_evidence = json.loads(row["evidence_json"] or "{}")
        except json.JSONDecodeError:
            existing_evidence = {}
        existing_roles = existing_evidence.get("entity_roles", {}) if isinstance(existing_evidence, dict) else {}
        incoming_roles = (incident.get("evidence") or {}).get("entity_roles", {}) if isinstance(incident.get("evidence"), dict) else {}
        if EventStore._requires_pre_nat_mapping(existing_evidence) != EventStore._requires_pre_nat_mapping(incident.get("evidence") or {}):
            return False
        if (
            existing_source
            and incoming_source
            and existing_source != incoming_source
            and _is_private_address(existing_source)
            and _is_private_address(incoming_source)
            and not EventStore._internal_sources_explicitly_related(row, existing_roles, incident, incoming_roles)
        ):
            return False
        existing_entities = EventStore._role_entities(row, existing_roles)
        incoming_entities = EventStore._role_entities_dict(incident, incoming_roles)
        if incoming_source and incoming_source in existing_entities:
            return True
        if existing_source and existing_source in incoming_entities:
            return True
        shared = existing_entities & incoming_entities
        if shared:
            return True
        return False

    @staticmethod
    def _requires_pre_nat_mapping(evidence: dict[str, Any]) -> bool:
        if not isinstance(evidence, dict):
            return False
        detections = evidence.get("detections", [])
        if not isinstance(detections, list):
            return False
        for detection in detections:
            if not isinstance(detection, dict):
                continue
            detection_evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
            if (
                detection_evidence.get("nat_mapping_required")
                or detection_evidence.get("response_target_confidence") == "low_without_pre_nat_session_context"
            ):
                return True
        return False

    @staticmethod
    def _internal_sources_explicitly_related(
        row: sqlite3.Row,
        existing_roles: dict[str, Any],
        incident: dict[str, Any],
        incoming_roles: dict[str, Any],
    ) -> bool:
        existing_source = _case_entity_value(row["source_ip"])
        incoming_source = _case_entity_value(incident.get("source_ip"))
        existing_destination = _case_entity_value(row["destination_ip"])
        incoming_destination = _case_entity_value(incident.get("destination_ip"))
        if existing_source and incoming_destination == existing_source:
            return True
        if incoming_source and existing_destination == incoming_source:
            return True
        if isinstance(existing_roles, dict):
            for key in ("victim", "affected_host", "pivot_host", "destination"):
                if _case_entity_value(existing_roles.get(key)) == incoming_source:
                    return True
        if isinstance(incoming_roles, dict):
            for key in ("victim", "affected_host", "pivot_host", "destination"):
                if _case_entity_value(incoming_roles.get(key)) == existing_source:
                    return True
        return False

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
    def _role_entities(row: sqlite3.Row, roles: dict[str, Any]) -> set[str]:
        entities = {value for key in ("source_ip", "destination_ip") if (value := _case_entity_value(row[key]))}
        try:
            entities.update(
                value for target in json.loads(row["affected_targets_json"] or "[]")
                if (value := _case_entity_value(target))
            )
        except json.JSONDecodeError:
            pass
        if isinstance(roles, dict):
            entities.update(value for role_value in roles.values() if (value := _case_entity_value(role_value)))
        return entities

    @staticmethod
    def _role_entities_dict(incident: dict[str, Any], roles: dict[str, Any]) -> set[str]:
        entities = {
            value for key in ("source_ip", "destination_ip")
            if (value := _case_entity_value(incident.get(key)))
        }
        entities.update(value for target in incident.get("affected_targets", []) if (value := _case_entity_value(target)))
        if isinstance(roles, dict):
            entities.update(value for role_value in roles.values() if (value := _case_entity_value(role_value)))
        return entities

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
            "dedupe_rule": "related source, entity role, target or target network, validation tag, and time window",
            "category_equality_required": False,
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

    @staticmethod
    def _detection_ids_from_evidence(evidence: dict[str, Any]) -> set[str]:
        detections = evidence.get("detections", []) if isinstance(evidence, dict) else []
        if not isinstance(detections, list):
            return set()
        return {
            str(item["detection_id"])
            for item in detections
            if isinstance(item, dict) and item.get("detection_id")
        }

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
        existing_detection_ids = self._detection_ids_from_evidence(existing_evidence)
        incoming_detection_ids = set(incoming["detection_ids"]) | self._detection_ids_from_evidence(incoming["evidence"])
        new_detection_ids = incoming_detection_ids - existing_detection_ids
        merged_detection_count = (
            existing_detection_count
            if not new_detection_ids
            else existing_detection_count + len(new_detection_ids)
        )
        merged_event_count = (
            existing_event_count
            if not new_detection_ids
            else existing_event_count + incoming["event_count"]
        )
        existing_suppressed = int(existing["suppressed_count"] or 0)
        merged_category = existing["category"]
        if incoming.get("category") and incoming.get("category") != existing["category"]:
            merged_category = "multi_stage"
        merged_attack_stage = existing["attack_stage"]
        if incoming.get("attack_stage") and incoming.get("attack_stage") != existing["attack_stage"]:
            merged_attack_stage = "multi_stage"
        merged_title = existing["title"]
        if merged_category == "multi_stage":
            source = existing["source_ip"] or incoming.get("source_ip") or "unknown source"
            target = existing["destination_ip"] or incoming.get("destination_ip") or (targets[0] if targets else "unknown target")
            if target == source and targets:
                target = next((item for item in targets if item != source), target)
            suffix = "detection" if merged_detection_count == 1 else "detections"
            merged_title = f"Multi-stage activity from {source} to {target} ({merged_detection_count} {suffix})"
        conn.execute(
            """
            UPDATE incidents
            SET title = ?,
                risk_score = max(risk_score, ?),
                severity = max(severity, ?),
                confidence = max(confidence, ?),
                destination_ip = COALESCE(destination_ip, ?),
                category = ?,
                updated_at = ?,
                first_seen = ?,
                last_seen = ?,
                event_count = ?,
                detection_count = ?,
                affected_targets_json = ?,
                attack_stage = ?,
                validation_tag = COALESCE(validation_tag, ?),
                suppressed_count = ?,
                evidence_json = ?,
                risk_factors_json = ?
            WHERE incident_id = ?
            """,
            (
                merged_title,
                incoming["risk_score"],
                incoming["severity"],
                incoming["confidence"],
                incoming.get("destination_ip"),
                merged_category,
                max(str(existing["updated_at"]), incoming["updated_at"]),
                first_seen,
                last_seen,
                merged_event_count,
                merged_detection_count,
                json.dumps(targets, sort_keys=True),
                merged_attack_stage,
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
                if status == "false_positive":
                    self._record_incident_feedback(
                        conn,
                        incident_id,
                        source["source_ip"],
                        "false_positive",
                        actor,
                        {
                            "scope": "host_local_baseline",
                            "effect": "future baseline updates for this host may include similar observations",
                            "global_rule_change": False,
                        },
                    )
            return changed > 0

    def delete_incident(self, incident_id: str, actor: str = "system") -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT incident_id, title, source_ip FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return {"status": "not_found", "incident_id": incident_id}
            active_blocks = conn.execute(
                """
                SELECT block_id, status, source_ip
                FROM block_entries
                WHERE incident_id = ?
                  AND status IN ('proposed', 'active')
                  AND expires_at > ?
                ORDER BY created_at DESC
                """,
                (incident_id, now_iso()),
            ).fetchall()
            if active_blocks:
                return {
                    "status": "denied",
                    "incident_id": incident_id,
                    "message": "release active case response before deleting this incident",
                    "active_blocks": [dict(item) for item in active_blocks],
                }
            source_ip = row["source_ip"]
            conn.execute("DELETE FROM incident_detections WHERE incident_id = ?", (incident_id,))
            conn.execute("DELETE FROM responses WHERE incident_id = ?", (incident_id,))
            conn.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
            if source_ip:
                conn.execute(
                    "UPDATE hosts SET open_incidents = (SELECT count(*) FROM incidents WHERE status = 'open' AND source_ip = ?) WHERE ip = ?",
                    (source_ip, source_ip),
                )
            self._audit(conn, actor, "incident.delete", incident_id, {"title": row["title"], "source_ip": source_ip})
            return {"status": "ok", "incident_id": incident_id}

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

    def update_block_entry(self, block_id: str, reason: str, expires_at: str, actor: str = "system") -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM block_entries WHERE block_id = ?", (block_id,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE block_entries SET reason = ?, expires_at = ? WHERE block_id = ?",
                (reason, expires_at, block_id),
            )
            if row["status"] in {"proposed", "active"}:
                host_status = self._current_host_block_status(conn, row["source_ip"])
                conn.execute("UPDATE hosts SET block_status = ? WHERE ip = ?", (host_status, row["source_ip"]))
            self._audit(conn, actor, "block.updated", block_id, {"reason": reason, "expires_at": expires_at})
            updated = conn.execute("SELECT * FROM block_entries WHERE block_id = ?", (block_id,)).fetchone()
        return dict(updated) if updated else None

    def existing_response_block(self, incident_id: str | None, source_ip: str | None) -> dict[str, Any] | None:
        if not incident_id and not source_ip:
            return None
        now = now_iso()
        clauses = ["status IN ('proposed', 'active')", "expires_at > ?"]
        values: list[Any] = [now]
        if incident_id:
            clauses.append("incident_id = ?")
            values.append(incident_id)
        if source_ip:
            clauses.append("source_ip = ?")
            values.append(source_ip)
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT * FROM block_entries WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 1",
                values,
            ).fetchone()
        return dict(row) if row else None

    def active_response_blocks_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM block_entries
                WHERE incident_id = ?
                  AND status IN ('proposed', 'active')
                  AND expires_at > ?
                ORDER BY created_at DESC
                """,
                (incident_id, now),
            ).fetchall()
        return [dict(row) for row in rows]

    def blocklist_view(self, limit: int = 100) -> dict[str, Any]:
        rows = self.list_rows("block_entries", limit=limit)
        now = now_iso()
        current_keys: set[tuple[str, str | None]] = set()
        visible = []
        history = []
        for row in rows:
            key = (str(row.get("source_ip")), row.get("incident_id"))
            is_current = row.get("status") in {"proposed", "active"} and str(row.get("expires_at") or "") > now
            if is_current:
                current_keys.add(key)
                item = dict(row)
                item["current"] = True
                visible.append(item)
        for row in rows:
            key = (str(row.get("source_ip")), row.get("incident_id"))
            if row.get("status") in {"proposed", "active"} and str(row.get("expires_at") or "") > now:
                continue
            item = dict(row)
            item["current"] = False
            item["superseded_by_current"] = key in current_keys
            history.append(item)
        return {
            "items": visible,
            "history": history,
            "summary": {
                "current": len(current_keys),
                "history": len(history),
                "hidden_historical_duplicates": sum(1 for item in history if item.get("superseded_by_current")),
            },
        }

    def active_block_count(self) -> int:
        now = now_iso()
        with self.connect() as conn:
            return int(conn.execute("SELECT count(*) FROM block_entries WHERE status = 'active' AND expires_at > ?", (now,)).fetchone()[0])

    def recent_automatic_internal_block_count(self, since_seconds: int = 3600) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=since_seconds)).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT source_ip
                FROM block_entries
                WHERE automatic = 1
                  AND created_at >= ?
                  AND status IN ('active', 'removed', 'expired')
                """,
                (cutoff,),
            ).fetchall()
        return sum(1 for row in rows if _is_private_address(row["source_ip"]))

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
                host_status = self._current_host_block_status(conn, row["source_ip"])
                conn.execute("UPDATE hosts SET block_status = ? WHERE ip = ?", (host_status, row["source_ip"]))
            self._audit(conn, actor, f"block.{status}", block_id, {"removal_reason": removal_reason})
            return changed > 0

    @staticmethod
    def _current_host_block_status(conn: sqlite3.Connection, source_ip: str) -> str:
        row = conn.execute(
            """
            SELECT status
            FROM block_entries
            WHERE source_ip = ?
              AND status IN ('active', 'proposed')
              AND expires_at > ?
            ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END, created_at DESC
            LIMIT 1
            """,
            (source_ip, now_iso()),
        ).fetchone()
        return row["status"] if row else "none"

    def expire_block_entries(self, actor: str = "system") -> int:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute("SELECT block_id, source_ip FROM block_entries WHERE status IN ('proposed', 'active') AND expires_at <= ?", (now,)).fetchall()
            for row in rows:
                conn.execute("UPDATE block_entries SET status = 'expired', removal_reason = 'expired' WHERE block_id = ?", (row["block_id"],))
                conn.execute("UPDATE hosts SET block_status = ? WHERE ip = ?", (self._current_host_block_status(conn, row["source_ip"]), row["source_ip"]))
                self._audit(conn, actor, "block.expired", row["block_id"], {})
            return len(rows)

    def add_sinkhole_entry(self, entry: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        sinkhole_id = entry.get("sinkhole_id") or str(uuid4())
        created_at = entry.get("created_at") or now_iso()
        record = {
            "sinkhole_id": sinkhole_id,
            "incident_id": entry.get("incident_id"),
            "domain": str(entry["domain"]).lower(),
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
                INSERT INTO sinkhole_entries(
                    sinkhole_id, incident_id, domain, reason, risk_score, confidence,
                    policy_id, created_at, expires_at, created_by, automatic,
                    status, removal_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["sinkhole_id"], record["incident_id"], record["domain"], record["reason"],
                    record["risk_score"], record["confidence"], record["policy_id"], record["created_at"],
                    record["expires_at"], record["created_by"], record["automatic"], record["status"],
                    record["removal_reason"],
                ),
            )
            self._audit(conn, actor, f"sinkhole.{record['status']}", record["domain"], record)
        return record

    def get_sinkhole_entry(self, sinkhole_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM sinkhole_entries WHERE sinkhole_id = ?", (sinkhole_id,)).fetchone()
        return dict(row) if row else None

    def existing_sinkhole_entry(self, incident_id: str | None, domain: str | None) -> dict[str, Any] | None:
        if not incident_id and not domain:
            return None
        now = now_iso()
        clauses = ["status IN ('proposed', 'active')", "expires_at > ?"]
        values: list[Any] = [now]
        if incident_id:
            clauses.append("incident_id = ?")
            values.append(incident_id)
        if domain:
            clauses.append("domain = ?")
            values.append(str(domain).lower())
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT * FROM sinkhole_entries WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 1",
                values,
            ).fetchone()
        return dict(row) if row else None

    def update_sinkhole_entry(self, sinkhole_id: str, reason: str, expires_at: str, actor: str = "system") -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM sinkhole_entries WHERE sinkhole_id = ?", (sinkhole_id,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE sinkhole_entries SET reason = ?, expires_at = ? WHERE sinkhole_id = ?",
                (reason, expires_at, sinkhole_id),
            )
            self._audit(conn, actor, "sinkhole.updated", sinkhole_id, {"reason": reason, "expires_at": expires_at})
            updated = conn.execute("SELECT * FROM sinkhole_entries WHERE sinkhole_id = ?", (sinkhole_id,)).fetchone()
        return dict(updated) if updated else None

    def update_sinkhole_status(self, sinkhole_id: str, status: str, removal_reason: str | None = None, actor: str = "system") -> bool:
        if status not in {"proposed", "active", "removed", "expired", "rejected"}:
            raise ValueError("invalid sinkhole status")
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute(
                "UPDATE sinkhole_entries SET status = ?, removal_reason = COALESCE(?, removal_reason) WHERE sinkhole_id = ?",
                (status, removal_reason, sinkhole_id),
            )
            changed = conn.total_changes - before
            self._audit(conn, actor, f"sinkhole.{status}", sinkhole_id, {"removal_reason": removal_reason})
            return changed > 0

    def sinkhole_view(self, limit: int = 100) -> dict[str, Any]:
        rows = self.list_rows("sinkhole_entries", limit=limit)
        now = now_iso()
        current_domains: set[str] = set()
        visible = []
        history = []
        for row in rows:
            is_current = row.get("status") in {"proposed", "active"} and str(row.get("expires_at") or "") > now
            if is_current:
                current_domains.add(str(row.get("domain")))
                item = dict(row)
                item["current"] = True
                visible.append(item)
        for row in rows:
            if row.get("status") in {"proposed", "active"} and str(row.get("expires_at") or "") > now:
                continue
            item = dict(row)
            item["current"] = False
            item["superseded_by_current"] = str(row.get("domain")) in current_domains
            history.append(item)
        return {
            "items": visible,
            "history": history,
            "summary": {
                "current": len(current_domains),
                "history": len(history),
                "hidden_historical_duplicates": sum(1 for item in history if item.get("superseded_by_current")),
            },
        }

    def active_sinkhole_domains(self) -> list[str]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT domain FROM sinkhole_entries WHERE status = 'active' AND expires_at > ?",
                (now,),
            ).fetchall()
        return [row["domain"] for row in rows]

    def expired_active_sinkhole_domains(self) -> list[str]:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT domain FROM sinkhole_entries WHERE status = 'active' AND expires_at <= ?",
                (now,),
            ).fetchall()
        return [row["domain"] for row in rows]

    def expire_sinkhole_entries(self, actor: str = "system") -> int:
        now = now_iso()
        with self.connect() as conn:
            rows = conn.execute("SELECT sinkhole_id FROM sinkhole_entries WHERE status IN ('proposed', 'active') AND expires_at <= ?", (now,)).fetchall()
            for row in rows:
                conn.execute("UPDATE sinkhole_entries SET status = 'expired', removal_reason = 'expired' WHERE sinkhole_id = ?", (row["sinkhole_id"],))
                self._audit(conn, actor, "sinkhole.expired", row["sinkhole_id"], {})
            return len(rows)

    def reset_runtime_state(self, actor: str = "system") -> dict[str, Any]:
        """Clear runtime telemetry while keeping configuration, models, policies, and allowlists."""
        runtime_tables = [
            "incident_detections",
            "responses",
            "block_entries",
            "sinkhole_entries",
            "incidents",
            "detections",
            "features",
            "flows",
            "events",
            "host_baselines",
            "hosts",
            "service_health",
            "collector_offsets",
            "incident_feedback",
            "audit_log",
        ]
        deleted: dict[str, int] = {}
        with self.connect() as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            before = conn.total_changes
            for table in runtime_tables:
                table_before = conn.total_changes
                conn.execute(f"DELETE FROM {table}")
                deleted[table] = conn.total_changes - table_before
            self._audit(conn, actor, "database.reset_runtime_state", None, {"deleted": deleted})
            total = conn.total_changes - before
        with self.connect() as conn:
            conn.execute("VACUUM")
        return {"status": "ok", "deleted": deleted, "total_deleted": total}

    def audit_case_action(self, action: str, incident_id: str, detail: dict[str, Any], actor: str = "system") -> None:
        with self.connect() as conn:
            self._audit(conn, actor, f"case.{action}", incident_id, detail)

    def audit_response_decision(self, incident_id: str | None, action: str, detail: dict[str, Any], actor: str = "system") -> None:
        with self.connect() as conn:
            self._audit(conn, actor, f"response.{action}", incident_id, detail)

    def response_decisions_for_incident(self, incident_id: str | None, limit: int = 10) -> list[dict[str, Any]]:
        if not incident_id:
            return []
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, actor, action, detail_json
                FROM audit_log
                WHERE target = ?
                  AND action LIKE 'response.%'
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (incident_id, max(1, int(limit))),
            ).fetchall()
        decisions = []
        for row in rows:
            try:
                detail = json.loads(row["detail_json"] or "{}")
            except json.JSONDecodeError:
                detail = {}
            decisions.append({
                "timestamp": row["timestamp"],
                "actor": row["actor"],
                "action": row["action"],
                "detail": detail,
            })
        return decisions

    def false_positive_feedback_sources(self, since_days: int = 14) -> set[str]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, int(since_days)))).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT source_ip
                FROM incident_feedback
                WHERE feedback_type = 'false_positive'
                  AND source_ip IS NOT NULL
                  AND created_at >= ?
                """,
                (cutoff,),
            ).fetchall()
        return {str(row["source_ip"]) for row in rows if row["source_ip"]}

    def merge_incidents(self, primary_id: str, secondary_id: str, actor: str = "system") -> dict[str, Any]:
        if primary_id == secondary_id:
            return {"status": "error", "message": "cannot merge an incident into itself"}
        with self.connect() as conn:
            primary = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (primary_id,)).fetchone()
            secondary = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (secondary_id,)).fetchone()
            if not primary or not secondary:
                return {"status": "not_found", "primary_id": primary_id, "secondary_id": secondary_id}
            incoming = self._row_to_prepared_incident(secondary)
            self._merge_incident(conn, primary, incoming)
            detection_rows = conn.execute("SELECT detection_id FROM incident_detections WHERE incident_id = ?", (secondary_id,)).fetchall()
            for row in detection_rows:
                conn.execute("INSERT OR IGNORE INTO incident_detections(incident_id, detection_id) VALUES (?, ?)", (primary_id, row["detection_id"]))
            conn.execute("UPDATE incidents SET status = 'archived', updated_at = ? WHERE incident_id = ?", (now_iso(), secondary_id))
            self._audit(conn, actor, "case.merge", primary_id, {"merged_incident_id": secondary_id})
            return {"status": "ok", "primary_id": primary_id, "merged_incident_id": secondary_id}

    def _row_to_prepared_incident(self, row: sqlite3.Row) -> dict[str, Any]:
        evidence = json.loads(row["evidence_json"] or "{}")
        risk_factors = json.loads(row["risk_factors_json"] or "[]")
        affected_targets = json.loads(row["affected_targets_json"] or "[]")
        detection_ids = []
        detections = evidence.get("detections", []) if isinstance(evidence, dict) else []
        if isinstance(detections, list):
            detection_ids = [str(item["detection_id"]) for item in detections if isinstance(item, dict) and item.get("detection_id")]
        return {
            "incident_id": row["incident_id"],
            "title": row["title"],
            "status": row["status"],
            "risk_score": int(row["risk_score"]),
            "severity": int(row["severity"]),
            "confidence": float(row["confidence"]),
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "category": row["category"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "first_seen": row["first_seen"] or row["created_at"],
            "last_seen": row["last_seen"] or row["updated_at"],
            "event_count": int(row["event_count"] or 0),
            "detection_count": int(row["detection_count"] or 0),
            "affected_targets": affected_targets,
            "attack_stage": row["attack_stage"],
            "validation_tag": row["validation_tag"],
            "suppressed_count": int(row["suppressed_count"] or 0),
            "evidence": evidence,
            "risk_factors": risk_factors,
            "detection_ids": detection_ids,
            "target_key": _target_network_key(row["destination_ip"], row["category"]),
        }

    def _audit(self, conn: sqlite3.Connection, actor: str, action: str, target: str | None, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO audit_log(audit_id, timestamp, actor, action, target, detail_json) VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid4()), now_iso(), actor, action, target, json.dumps(detail, sort_keys=True)),
        )

    def _record_incident_feedback(
        self,
        conn: sqlite3.Connection,
        incident_id: str,
        source_ip: str | None,
        feedback_type: str,
        actor: str,
        detail: dict[str, Any],
    ) -> None:
        conn.execute(
            """
            INSERT INTO incident_feedback(
                feedback_id, incident_id, source_ip, feedback_type, created_at, actor, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid4()), incident_id, source_ip, feedback_type, now_iso(), actor, json.dumps(detail, sort_keys=True)),
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

    def learning_started_at_candidate(self) -> str | None:
        queries = [
            "SELECT min(timestamp) AS value FROM events",
            "SELECT min(timestamp) AS value FROM features",
            "SELECT min(timestamp) AS value FROM detections",
            "SELECT min(first_observation) AS value FROM host_baselines",
            "SELECT min(created_at) AS value FROM incidents",
        ]
        values: list[str] = []
        with self.connect() as conn:
            for query in queries:
                row = conn.execute(query).fetchone()
                if row and row["value"]:
                    values.append(str(row["value"]))
        parsed = sorted((_parse_time(value).isoformat() for value in values if value))
        return parsed[0] if parsed else None

    def list_rows(self, table: str, limit: int = 100) -> list[dict[str, Any]]:
        allowed = {
            "events", "detections", "incidents", "hosts", "entities",
            "entity_observations", "block_entries", "sinkhole_entries",
            "allowlist_entries", "policies", "models", "audit_log",
            "incident_feedback",
        }
        if table not in allowed:
            raise ValueError(f"unsupported table: {table}")
        order = "timestamp" if table in {"events", "detections", "audit_log"} else "rowid"
        if table == "incidents":
            order = "updated_at"
        if table == "hosts":
            order = "last_seen"
        if table == "entities":
            order = "last_seen"
        if table == "entity_observations":
            order = "timestamp"
        with self.connect() as conn:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY {order} DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def host_inventory(self, limit: int = 100) -> dict[str, Any]:
        with self.connect() as conn:
            total_entities = int(conn.execute("SELECT count(*) FROM entities").fetchone()[0])
            peer_group_rows = conn.execute(
                "SELECT peer_group, count(*) AS count FROM entities GROUP BY peer_group"
            ).fetchall()
            entities = conn.execute(
                """
                SELECT *
                FROM entities
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
            host_rows = conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC").fetchall()
        hosts_by_entity: dict[str, list[dict[str, Any]]] = {}
        unassigned: list[dict[str, Any]] = []
        peer_groups = {row["peer_group"] or "unknown": int(row["count"]) for row in peer_group_rows}
        for row in host_rows:
            item = dict(row)
            entity_id = item.get("entity_id")
            if entity_id:
                hosts_by_entity.setdefault(str(entity_id), []).append(item)
            else:
                unassigned.append(item)
        items: list[dict[str, Any]] = []
        for row in entities:
            entity = dict(row)
            entity_hosts = [self._compact_host_record(host) for host in hosts_by_entity.get(entity["entity_id"], [])]
            current_ips = sorted({host["ip"] for host in entity_hosts if host.get("ip")})
            roles = self._safe_json_list(entity.pop("roles_json", "[]"))
            tags = self._safe_json_list(entity.pop("tags_json", "[]"))
            known_services = self._safe_json_list(entity.pop("known_services_json", "[]"))
            previous_ips = set(self._safe_json_list(entity.pop("previous_ips_json", "[]")))
            history = self._safe_json_list(entity.pop("history_json", "[]"))
            previous_ips.update(ip for ip in current_ips if ip != entity.get("primary_ip"))
            item = {
                **entity,
                "ip": entity.get("primary_ip"),
                "current_ips": current_ips,
                "previous_ips": sorted(previous_ips),
                "roles": roles,
                "tags": tags,
                "known_services": known_services,
                "history": history,
                "host_records": entity_hosts,
            }
            items.append(item)
        for host in unassigned[:max(0, int(limit) - len(items))]:
            compact_host = self._compact_host_record(host)
            items.append({
                "entity_id": host.get("entity_id"),
                "ip": host.get("ip"),
                "primary_ip": host.get("ip"),
                "current_ips": [host.get("ip")] if host.get("ip") else [],
                "previous_ips": [],
                "hostname": host.get("hostname"),
                "mac": host.get("mac"),
                "interface": host.get("interface"),
                "vlan": host.get("vlan"),
                "confidence": 0.2,
                "roles": [],
                "peer_group": "unknown",
                "peer_group_source": "fallback",
                "peer_group_confidence": 0.2,
                "criticality": "normal",
                "tags": [],
                "known_services": json.loads(host.get("known_ports_json") or "[]"),
                "first_seen": host.get("first_seen"),
                "last_seen": host.get("last_seen"),
                "history": [],
                "host_records": [compact_host],
            })
        return {
            "items": items,
            "summary": {
                "entities": total_entities,
                "returned_entities": len(items),
                "host_records": len(host_rows),
                "resolved_host_records": sum(len(value) for value in hosts_by_entity.values()),
                "unassigned_host_records": len(unassigned),
                "peer_groups": peer_groups,
            },
        }

    def host_detail(self, host_id: str, limit: int = 10000) -> dict[str, Any]:
        target = str(host_id or "").strip().lower()
        if not target:
            return {"status": "not_found", "host_id": host_id}
        inventory = self.host_inventory(limit=limit)
        for item in inventory.get("items", []):
            values = {
                item.get("entity_id"),
                item.get("ip"),
                item.get("primary_ip"),
                item.get("mac"),
                item.get("hostname"),
            }
            values.update(item.get("current_ips") or [])
            values.update(item.get("previous_ips") or [])
            for host in item.get("host_records") or []:
                values.update({host.get("ip"), host.get("entity_id"), host.get("mac"), host.get("hostname")})
            if target in {str(value).strip().lower() for value in values if value}:
                return {"status": "ok", "item": item, "summary": inventory.get("summary", {})}
        return {"status": "not_found", "host_id": host_id}

    @staticmethod
    def _compact_host_record(host: dict[str, Any]) -> dict[str, Any]:
        return {
            "ip": host.get("ip"),
            "entity_id": host.get("entity_id"),
            "hostname": host.get("hostname"),
            "mac": host.get("mac"),
            "interface": host.get("interface"),
            "vlan": host.get("vlan"),
            "first_seen": host.get("first_seen"),
            "last_seen": host.get("last_seen"),
            "risk_score": host.get("risk_score"),
            "open_incidents": host.get("open_incidents"),
            "learning_status": host.get("learning_status"),
            "baseline_deviation": host.get("baseline_deviation"),
            "block_status": host.get("block_status"),
            "allowlist_status": host.get("allowlist_status"),
        }

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
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))).isoformat()
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

    def telemetry_provider_matrix(self, hours: int = 24) -> dict[str, Any]:
        window = max(24, int(hours))
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=window)).isoformat()
        window_cutoffs = {
            "1h": now - timedelta(hours=1),
            "6h": now - timedelta(hours=6),
            "24h": now - timedelta(hours=24),
        }
        matrix: dict[str, dict[str, Any]] = {}
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT raw_source, event_type, timestamp, source_ip, destination_ip,
                       destination_port, metadata_json
                FROM events
                WHERE timestamp >= ?
                """,
                (cutoff,),
            ).fetchall()
        for row in rows:
            source = str(row["raw_source"] or "unknown")
            event_type = str(row["event_type"] or "unknown")
            entry = matrix.setdefault(source, {
                "last_event_at": None,
                "windows": {name: _empty_telemetry_counts() for name in window_cutoffs},
            })
            timestamp = _parse_time(row["timestamp"])
            if entry["last_event_at"] is None or timestamp.isoformat() > entry["last_event_at"]:
                entry["last_event_at"] = timestamp.isoformat()
            metadata = _safe_json_dict(row["metadata_json"])
            classes = _telemetry_classes(event_type, int(row["destination_port"] or 0), metadata)
            incomplete = _incomplete_telemetry_event(
                event_type,
                row["source_ip"],
                row["destination_ip"],
                metadata,
            )
            for name, cutoff_time in window_cutoffs.items():
                if timestamp < cutoff_time:
                    continue
                counts = entry["windows"][name]
                counts["total"] += 1
                for item in classes:
                    counts[item] += 1
                if incomplete:
                    counts["incomplete"] += 1
        coverage = _empty_telemetry_counts()
        for entry in matrix.values():
            for key, value in entry["windows"]["24h"].items():
                coverage[key] += int(value)
        return {
            "hours": window,
            "windows": [1, 6, 24],
            "by_provider": matrix,
            "coverage": coverage,
            "email_url_file_ready": {
                "dns_metadata": coverage["dns"] > 0,
                "tls_metadata": coverage["tls"] > 0,
                "http_metadata": coverage["http"] > 0,
                "file_metadata": coverage["fileinfo"] > 0,
                "signature_or_drop_metadata": coverage["alert_or_drop"] > 0,
                "sandbox_verdict_metadata": coverage["sandbox_verdict"] > 0,
            },
        }

    def baseline_summary(self) -> dict[str, Any]:
        with self.connect() as conn:
            total = int(conn.execute("SELECT count(*) FROM host_baselines").fetchone()[0])
            status_rows = conn.execute(
                "SELECT status, count(*) AS count FROM host_baselines GROUP BY status"
            ).fetchall()
            status_counts = {row["status"] or "building": int(row["count"]) for row in status_rows}
            established = int(conn.execute(
                """
                SELECT count(*) FROM host_baselines
                WHERE observation_count >= ? OR status IN ('complete', 'updated', 'uncertain', 'established')
                """,
                (BASELINE_MINIMUM_OBSERVATIONS,),
            ).fetchone()[0])
            learning = max(0, total - established)
            max_observations = int(conn.execute("SELECT COALESCE(max(observation_count), 0) FROM host_baselines").fetchone()[0])
            version_count = int(conn.execute("SELECT count(*) FROM baseline_versions").fetchone()[0])
            drifted = int(conn.execute(
                "SELECT count(*) FROM host_baselines WHERE drift_score >= 0.35 OR status IN ('updated', 'uncertain')"
            ).fetchone()[0])
            uncertain = int(conn.execute(
                "SELECT count(*) FROM host_baselines WHERE drift_score >= 0.7 OR status = 'uncertain'"
            ).fetchone()[0])
        return {
            "total_hosts": total,
            "established_hosts": established,
            "learning_hosts": learning,
            "max_observations": max_observations,
            "status_counts": status_counts,
            "baseline_versions": version_count,
            "drifted_hosts": drifted,
            "uncertain_hosts": uncertain,
        }

    def host_baseline_observations(self, host_ip: str | None) -> int:
        if not host_ip:
            return 0
        with self.connect() as conn:
            row = conn.execute("SELECT observation_count FROM host_baselines WHERE host_ip = ?", (host_ip,)).fetchone()
        return int(row["observation_count"]) if row else 0

    def dashboard_summary(self) -> dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            events_24h = conn.execute("SELECT count(*) FROM events WHERE timestamp >= ?", (cutoff,)).fetchone()[0]
            open_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open'").fetchone()[0]
            active_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND COALESCE(last_seen, updated_at) >= ?", (cutoff,)).fetchone()[0]
            high_risk_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 70").fetchone()[0]
            critical_incidents = conn.execute("SELECT count(*) FROM incidents WHERE status = 'open' AND risk_score >= 90").fetchone()[0]
            block_rows = conn.execute("SELECT DISTINCT source_ip FROM block_entries WHERE status = 'active' AND expires_at > ?", (now_iso(),)).fetchall()
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
        return self.purge_before(cutoff, include_open_incidents=False)

    def purge_before(self, cutoff: str, include_open_incidents: bool = False) -> int:
        with self.connect() as conn:
            before = conn.total_changes
            conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM features WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM detections WHERE timestamp < ?", (cutoff,))
            incident_clause = "COALESCE(updated_at, created_at) < ?"
            values: list[Any] = [cutoff]
            if not include_open_incidents:
                incident_clause += " AND status != 'open'"
            old_incidents = [
                row["incident_id"]
                for row in conn.execute(f"SELECT incident_id FROM incidents WHERE {incident_clause}", values).fetchall()
            ]
            if old_incidents:
                placeholders = ",".join("?" for _ in old_incidents)
                conn.execute(f"DELETE FROM incident_detections WHERE incident_id IN ({placeholders})", old_incidents)
                conn.execute(f"DELETE FROM incidents WHERE incident_id IN ({placeholders})", old_incidents)
                conn.execute(f"DELETE FROM responses WHERE incident_id IN ({placeholders})", old_incidents)
            return conn.total_changes - before
