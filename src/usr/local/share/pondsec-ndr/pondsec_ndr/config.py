"""Configuration loading and validation for PondSec NDR."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


CONFIG_PATH = Path(os.environ.get("PONDSEC_NDR_CONFIG", "/usr/local/etc/pondsec-ndr/pondsec-ndr.json"))
DATA_DIR = Path(os.environ.get("PONDSEC_NDR_DATA_DIR", "/var/db/pondsec-ndr"))
LOG_DIR = Path(os.environ.get("PONDSEC_NDR_LOG_DIR", "/var/log/pondsec-ndr"))
RUN_DIR = Path(os.environ.get("PONDSEC_NDR_RUN_DIR", "/var/run/pondsec-ndr"))

MODES = {"monitor", "alert", "interactive", "prevent"}
RESPONSE_MODES = {"observe", "recommend", "enforce"}
DIRECTIONS = {"ingress", "egress", "both"}
ZEEK_MODES = {"external", "local"}
ZEEK_PARSERS = {"tsv"}


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def _csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_learning_started_marker(data_dir: Path) -> str:
    marker = data_dir / "learning_started_at"
    try:
        value = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return value if _parse_datetime(value) else ""


@dataclass(slots=True)
class InterfaceConfig:
    monitored: list[str] = field(default_factory=list)
    monitored_devices: list[str] = field(default_factory=list)
    direction: str = "both"
    internal: list[str] = field(default_factory=list)
    internal_devices: list[str] = field(default_factory=list)
    wan: list[str] = field(default_factory=list)
    wan_devices: list[str] = field(default_factory=list)
    management: list[str] = field(default_factory=list)
    management_devices: list[str] = field(default_factory=list)
    excluded_interfaces: list[str] = field(default_factory=list)
    excluded_devices: list[str] = field(default_factory=list)
    excluded_networks: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DetectionConfig:
    suricata_events: bool = True
    dns_analysis: bool = True
    tls_analysis: bool = True
    http_metadata: bool = True
    portscan: bool = True
    lateral_movement: bool = True
    beaconing: bool = True
    dns_tunneling: bool = True
    exfiltration: bool = True
    unusual_destinations: bool = True
    unusual_services: bool = True
    unusual_internal: bool = True
    machine_learning: bool = True
    learning_mode: bool = True
    learning_started_at: str = ""
    learning_days: int = 14
    early_ai_activation_override: bool = False
    learning_phase_observations: int = 1000
    minimum_observations: int = 50
    minimum_incident_confidence: int = 75
    correlation_window_minutes: int = 30
    false_positive_feedback_days: int = 14

    def learning_status(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        started = _parse_datetime(self.learning_started_at)
        elapsed_days = 0
        remaining_days = self.learning_days
        if started is not None:
            elapsed_days = int(max(0.0, (now - started).total_seconds()) // 86400)
            remaining_days = max(0, self.learning_days - elapsed_days)
        if not self.machine_learning:
            status = "disabled"
            active = False
            reason = "machine_learning_disabled"
            warning = ""
        elif self.learning_mode and self.early_ai_activation_override:
            status = "override"
            active = False
            reason = "admin_early_ai_activation_override"
            warning = (
                "AI detections are active before the recommended learning phase is complete. "
                "False positives are likely until enough baseline history exists."
            )
        elif self.learning_mode and (started is None or elapsed_days < self.learning_days):
            status = "learning"
            active = True
            reason = "learning_phase_active"
            warning = "AI and baseline anomaly alarms are suppressed until learning completes or an administrator overrides it."
        else:
            status = "armed"
            active = False
            reason = "learning_phase_complete_or_disabled"
            warning = ""
        return {
            "status": status,
            "active": active,
            "reason": reason,
            "warning": warning,
            "started_at": started.isoformat() if started else None,
            "required_days": self.learning_days,
            "elapsed_days": elapsed_days,
            "remaining_days": remaining_days,
            "minimum_observations": self.minimum_observations,
            "learning_phase_observations": self.learning_phase_observations,
            "early_ai_activation_override": self.early_ai_activation_override,
        }


@dataclass(slots=True)
class ThreatIntelConfig:
    cve_enrichment: bool = True
    external_lookup: bool = False
    cache_ttl_hours: int = 24
    api_timeout_seconds: int = 5


@dataclass(slots=True)
class ZeekConfig:
    enabled: bool = False
    mode: str = "external"
    parser: str = "tsv"
    sensor_name: str = ""
    interface: str = ""
    remote_target: str = ""
    log_dir: str = "/var/log/zeek/current"
    start_at_end: bool = True
    conn_log: str = "conn.log"
    dns_log: str = "dns.log"
    ssl_log: str = "ssl.log"
    x509_log: str = "x509.log"
    http_log: str = "http.log"
    files_log: str = "files.log"
    notice_log: str = "notice.log"
    weird_log: str = "weird.log"

    def log_paths(self) -> dict[str, Path]:
        root = Path(self.log_dir)
        configured = {
            "conn": self.conn_log,
            "dns": self.dns_log,
            "ssl": self.ssl_log,
            "x509": self.x509_log,
            "http": self.http_log,
            "files": self.files_log,
            "notice": self.notice_log,
            "weird": self.weird_log,
        }
        paths: dict[str, Path] = {}
        for log_type, value in configured.items():
            if not value:
                continue
            path = Path(value)
            paths[log_type] = path if path.is_absolute() else root / path
        return paths


@dataclass(slots=True)
class ResponseConfig:
    mode: str = "observe"
    ai_full_decision_mode: bool = False
    kill_switch: bool = False
    maintenance_mode: bool = False
    automatic_blocking: bool = False
    minimum_confidence: int = 95
    minimum_risk_score: int = 95
    minimum_severity: int = 9
    min_internal_event_count: int = 3
    min_internal_detection_count: int = 3
    min_internal_categories: int = 3
    min_supporting_indicators: int = 2
    min_independent_engines: int = 2
    baseline_stable_observations: int = 50
    default_block_seconds: int = 3600
    auto_isolation_seconds: int = 900
    max_block_seconds: int = 86400
    max_concurrent_blocks: int = 100
    internal_isolation_cooldown_seconds: int = 900
    max_internal_isolations_per_hour: int = 1
    max_auto_isolation_candidates_per_run: int = 3
    block_external: bool = False
    isolate_internal: bool = False
    manual_confirmation: bool = True
    protect_management_networks: bool = True
    forbid_block_on_service_error: bool = True
    enforce_allowlist: bool = True
    protected_networks: list[str] = field(default_factory=list)
    protected_hosts: list[str] = field(default_factory=list)
    break_glass_values: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PondSecConfig:
    enabled: bool = False
    mode: str = "monitor"
    risk_threshold: int = 70
    max_event_rate: int = 5000
    max_queue_length: int = 10000
    retention_days: int = 30
    max_database_mb: int = 1024
    incident_rate_limit_per_minute: int = 60
    pf_action_rate_limit_per_minute: int = 20
    memory_warning_mb: int = 512
    cpu_warning_percent: int = 85
    privacy_mode: bool = True
    anonymize_storage: bool = False
    debug_logging: bool = False
    fail_open: bool = True
    timezone: str = "UTC"
    language: str = "en"
    suricata_eve_path: str = "/var/log/suricata/eve.json"
    interfaces: InterfaceConfig = field(default_factory=InterfaceConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    zeek: ZeekConfig = field(default_factory=ZeekConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    data_dir: Path = DATA_DIR
    log_dir: Path = LOG_DIR
    run_dir: Path = RUN_DIR

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.mode not in MODES:
            errors.append(f"invalid mode: {self.mode}")
        if self.response.mode not in RESPONSE_MODES:
            errors.append(f"invalid response mode: {self.response.mode}")
        if self.interfaces.direction not in DIRECTIONS:
            errors.append(f"invalid direction: {self.interfaces.direction}")
        if not self.fail_open:
            errors.append("fail_open must remain enabled in the foundation release")
        if self.mode == "prevent" and not self.response.manual_confirmation and self.response.minimum_confidence < 75:
            errors.append("prevent mode without manual confirmation requires at least 75 percent confidence")
        if self.response.mode == "enforce" and not self.response.automatic_blocking:
            errors.append("response enforce mode requires automatic blocking to be enabled")
        if self.retention_days < 1:
            errors.append("retention_days must be positive")
        if self.max_database_mb < 64:
            errors.append("max_database_mb must be at least 64")
        if self.max_queue_length < 1:
            errors.append("max_queue_length must be positive")
        if self.incident_rate_limit_per_minute < 1:
            errors.append("incident_rate_limit_per_minute must be positive")
        if self.pf_action_rate_limit_per_minute < 1:
            errors.append("pf_action_rate_limit_per_minute must be positive")
        if self.detection.correlation_window_minutes < 1:
            errors.append("correlation_window_minutes must be positive")
        if self.detection.false_positive_feedback_days < 1:
            errors.append("false_positive_feedback_days must be positive")
        if self.threat_intel.cache_ttl_hours < 1:
            errors.append("threat_intel cache_ttl_hours must be positive")
        if self.threat_intel.api_timeout_seconds < 1:
            errors.append("threat_intel api_timeout_seconds must be positive")
        if self.zeek.mode not in ZEEK_MODES:
            errors.append(f"invalid Zeek mode: {self.zeek.mode}")
        if self.zeek.parser not in ZEEK_PARSERS:
            errors.append(f"invalid Zeek parser: {self.zeek.parser}")
        if self.zeek.enabled and not self.zeek.log_paths():
            errors.append("Zeek provider requires at least one configured log path")
        if self.response.max_internal_isolations_per_hour < 0:
            errors.append("max_internal_isolations_per_hour must not be negative")
        if self.response.internal_isolation_cooldown_seconds < 0:
            errors.append("internal_isolation_cooldown_seconds must not be negative")
        return errors


def load_config(path: Path | None = None) -> PondSecConfig:
    config_path = path or Path(os.environ.get("PONDSEC_NDR_CONFIG", str(CONFIG_PATH)))
    data_dir = Path(os.environ.get("PONDSEC_NDR_DATA_DIR", str(DATA_DIR)))
    log_dir = Path(os.environ.get("PONDSEC_NDR_LOG_DIR", str(LOG_DIR)))
    run_dir = Path(os.environ.get("PONDSEC_NDR_RUN_DIR", str(RUN_DIR)))
    raw: dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
            if isinstance(loaded, dict):
                raw = loaded

    interfaces = raw.get("interfaces") or {}
    detection = raw.get("detection") or {}
    threat_intel = raw.get("threat_intel") or {}
    zeek = raw.get("zeek") or {}
    zeek_logs = zeek.get("logs") or {}
    response = raw.get("response") or {}
    mode = str(raw.get("mode", "monitor")).strip().lower()
    if mode not in MODES:
        mode = "monitor"
    zeek_mode = str(zeek.get("mode") or "external").strip().lower()
    if zeek_mode not in ZEEK_MODES:
        zeek_mode = "external"
    zeek_parser = str(zeek.get("parser") or "tsv").strip().lower()
    if zeek_parser not in ZEEK_PARSERS:
        zeek_parser = "tsv"

    return PondSecConfig(
        enabled=_bool(raw.get("enabled"), False),
        mode=mode,
        risk_threshold=_int(raw.get("risk_threshold"), 70, 1, 100),
        max_event_rate=_int(raw.get("max_event_rate"), 5000, 1, 100000),
        max_queue_length=_int(raw.get("max_queue_length"), 10000, 1, 1000000),
        retention_days=_int(raw.get("retention_days"), 30, 1, 3650),
        max_database_mb=_int(raw.get("max_database_mb"), 1024, 64, 1048576),
        incident_rate_limit_per_minute=_int(raw.get("incident_rate_limit_per_minute"), 60, 1, 100000),
        pf_action_rate_limit_per_minute=_int(raw.get("pf_action_rate_limit_per_minute"), 20, 1, 100000),
        memory_warning_mb=_int(raw.get("memory_warning_mb"), 512, 32, 1048576),
        cpu_warning_percent=_int(raw.get("cpu_warning_percent"), 85, 1, 100),
        privacy_mode=_bool(raw.get("privacy_mode"), True),
        anonymize_storage=_bool(raw.get("anonymize_storage"), False),
        debug_logging=_bool(raw.get("debug_logging"), False),
        fail_open=_bool(raw.get("fail_open"), True),
        timezone=str(raw.get("timezone", "UTC")),
        language=str(raw.get("language", "en")),
        suricata_eve_path=str(raw.get("suricata_eve_path", "/var/log/suricata/eve.json")),
        interfaces=InterfaceConfig(
            monitored=_csv(interfaces.get("monitored")),
            monitored_devices=_csv(interfaces.get("monitored_devices")),
            direction=str(interfaces.get("direction", "both")).strip().lower(),
            internal=_csv(interfaces.get("internal")),
            internal_devices=_csv(interfaces.get("internal_devices")),
            wan=_csv(interfaces.get("wan")),
            wan_devices=_csv(interfaces.get("wan_devices")),
            management=_csv(interfaces.get("management")),
            management_devices=_csv(interfaces.get("management_devices")),
            excluded_interfaces=_csv(interfaces.get("excluded_interfaces")),
            excluded_devices=_csv(interfaces.get("excluded_devices")),
            excluded_networks=_csv(interfaces.get("excluded_networks")),
            excluded_hosts=_csv(interfaces.get("excluded_hosts")),
        ),
        detection=DetectionConfig(
            suricata_events=_bool(detection.get("suricata_events"), True),
            dns_analysis=_bool(detection.get("dns_analysis"), True),
            tls_analysis=_bool(detection.get("tls_analysis"), True),
            http_metadata=_bool(detection.get("http_metadata"), True),
            portscan=_bool(detection.get("portscan"), True),
            lateral_movement=_bool(detection.get("lateral_movement"), True),
            beaconing=_bool(detection.get("beaconing"), True),
            dns_tunneling=_bool(detection.get("dns_tunneling"), True),
            exfiltration=_bool(detection.get("exfiltration"), True),
            unusual_destinations=_bool(detection.get("unusual_destinations"), True),
            unusual_services=_bool(detection.get("unusual_services"), True),
            unusual_internal=_bool(detection.get("unusual_internal"), True),
            machine_learning=_bool(detection.get("machine_learning"), True),
            learning_mode=_bool(detection.get("learning_mode"), True),
            learning_started_at=str(detection.get("learning_started_at") or _read_learning_started_marker(data_dir) or ""),
            learning_days=_int(detection.get("learning_days"), 14, 1, 90),
            early_ai_activation_override=_bool(detection.get("early_ai_activation_override"), False),
            learning_phase_observations=_int(detection.get("learning_phase_observations"), 1000, 10, 10000000),
            minimum_observations=_int(detection.get("minimum_observations"), 50, 1, 1000000),
            minimum_incident_confidence=_int(detection.get("minimum_incident_confidence"), 75, 1, 100),
            correlation_window_minutes=_int(detection.get("correlation_window_minutes"), 30, 1, 1440),
            false_positive_feedback_days=_int(detection.get("false_positive_feedback_days"), 14, 1, 365),
        ),
        threat_intel=ThreatIntelConfig(
            cve_enrichment=_bool(threat_intel.get("cve_enrichment"), True),
            external_lookup=_bool(threat_intel.get("external_lookup"), False),
            cache_ttl_hours=_int(threat_intel.get("cache_ttl_hours"), 24, 1, 168),
            api_timeout_seconds=_int(threat_intel.get("api_timeout_seconds"), 5, 1, 30),
        ),
        zeek=ZeekConfig(
            enabled=_bool(zeek.get("enabled"), False),
            mode=zeek_mode,
            parser=zeek_parser,
            sensor_name=str(zeek.get("sensor_name") or ""),
            interface=str(zeek.get("interface") or ""),
            remote_target=str(zeek.get("remote_target") or ""),
            log_dir=str(zeek.get("log_dir") or "/var/log/zeek/current"),
            start_at_end=_bool(zeek.get("start_at_end"), True),
            conn_log=str(zeek_logs.get("conn") or zeek.get("conn_log") or "conn.log"),
            dns_log=str(zeek_logs.get("dns") or zeek.get("dns_log") or "dns.log"),
            ssl_log=str(zeek_logs.get("ssl") or zeek.get("ssl_log") or "ssl.log"),
            x509_log=str(zeek_logs.get("x509") or zeek.get("x509_log") or "x509.log"),
            http_log=str(zeek_logs.get("http") or zeek.get("http_log") or "http.log"),
            files_log=str(zeek_logs.get("files") or zeek.get("files_log") or "files.log"),
            notice_log=str(zeek_logs.get("notice") or zeek.get("notice_log") or "notice.log"),
            weird_log=str(zeek_logs.get("weird") or zeek.get("weird_log") or "weird.log"),
        ),
        response=ResponseConfig(
            mode=str(response.get("mode") or "observe").strip().lower() if str(response.get("mode") or "observe").strip().lower() in RESPONSE_MODES else "observe",
            ai_full_decision_mode=_bool(response.get("ai_full_decision_mode"), False),
            kill_switch=_bool(response.get("kill_switch"), False),
            maintenance_mode=_bool(response.get("maintenance_mode"), False),
            automatic_blocking=_bool(response.get("automatic_blocking"), False),
            minimum_confidence=_int(response.get("minimum_confidence"), 95, 1, 100),
            minimum_risk_score=_int(response.get("minimum_risk_score"), 95, 1, 100),
            minimum_severity=_int(response.get("minimum_severity"), 9, 1, 10),
            min_internal_event_count=_int(response.get("min_internal_event_count"), 3, 1, 100000),
            min_internal_detection_count=_int(response.get("min_internal_detection_count"), 3, 1, 100000),
            min_internal_categories=_int(response.get("min_internal_categories"), 3, 1, 100),
            min_supporting_indicators=_int(response.get("min_supporting_indicators"), 2, 0, 100),
            min_independent_engines=_int(response.get("min_independent_engines"), 2, 1, 100),
            baseline_stable_observations=_int(response.get("baseline_stable_observations"), 50, 1, 10000000),
            default_block_seconds=_int(response.get("default_block_seconds"), 3600, 60, 604800),
            auto_isolation_seconds=_int(response.get("auto_isolation_seconds"), 900, 60, 604800),
            max_block_seconds=_int(response.get("max_block_seconds"), 86400, 60, 2592000),
            max_concurrent_blocks=_int(response.get("max_concurrent_blocks"), 100, 0, 100000),
            internal_isolation_cooldown_seconds=_int(response.get("internal_isolation_cooldown_seconds"), 900, 0, 86400),
            max_internal_isolations_per_hour=_int(response.get("max_internal_isolations_per_hour"), 1, 0, 100000),
            max_auto_isolation_candidates_per_run=_int(response.get("max_auto_isolation_candidates_per_run"), 3, 1, 100000),
            block_external=_bool(response.get("block_external"), False),
            isolate_internal=_bool(response.get("isolate_internal"), False),
            manual_confirmation=_bool(response.get("manual_confirmation"), True),
            protect_management_networks=_bool(response.get("protect_management_networks"), True),
            forbid_block_on_service_error=_bool(response.get("forbid_block_on_service_error"), True),
            enforce_allowlist=_bool(response.get("enforce_allowlist"), True),
            protected_networks=_csv(response.get("protected_networks")),
            protected_hosts=_csv(response.get("protected_hosts")),
            break_glass_values=_csv(response.get("break_glass_values")),
        ),
        data_dir=data_dir,
        log_dir=log_dir,
        run_dir=run_dir,
    )


def ensure_directories(config: PondSecConfig) -> None:
    for directory in (config.data_dir, config.log_dir, config.run_dir):
        directory.mkdir(parents=True, exist_ok=True)
