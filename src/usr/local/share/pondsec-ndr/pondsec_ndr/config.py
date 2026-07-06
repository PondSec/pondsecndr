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
DIRECTIONS = {"ingress", "egress", "both"}


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
class ResponseConfig:
    automatic_blocking: bool = False
    minimum_confidence: int = 95
    minimum_risk_score: int = 90
    default_block_seconds: int = 3600
    max_block_seconds: int = 86400
    max_concurrent_blocks: int = 100
    block_external: bool = False
    isolate_internal: bool = False
    manual_confirmation: bool = True
    protect_management_networks: bool = True
    forbid_block_on_service_error: bool = True
    enforce_allowlist: bool = True


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
    response: ResponseConfig = field(default_factory=ResponseConfig)
    data_dir: Path = DATA_DIR
    log_dir: Path = LOG_DIR
    run_dir: Path = RUN_DIR

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.mode not in MODES:
            errors.append(f"invalid mode: {self.mode}")
        if self.interfaces.direction not in DIRECTIONS:
            errors.append(f"invalid direction: {self.interfaces.direction}")
        if not self.fail_open:
            errors.append("fail_open must remain enabled in the foundation release")
        if self.mode == "prevent" and not self.response.manual_confirmation and self.response.minimum_confidence < 75:
            errors.append("prevent mode without manual confirmation requires at least 75 percent confidence")
        if self.response.automatic_blocking and self.mode not in {"interactive", "prevent"}:
            errors.append("automatic blocking can only be enabled in interactive or prevent mode")
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
    response = raw.get("response") or {}
    mode = str(raw.get("mode", "monitor")).strip().lower()
    if mode not in MODES:
        mode = "monitor"

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
            learning_started_at=str(detection.get("learning_started_at") or ""),
            learning_days=_int(detection.get("learning_days"), 14, 1, 90),
            early_ai_activation_override=_bool(detection.get("early_ai_activation_override"), False),
            learning_phase_observations=_int(detection.get("learning_phase_observations"), 1000, 10, 10000000),
            minimum_observations=_int(detection.get("minimum_observations"), 50, 1, 1000000),
            minimum_incident_confidence=_int(detection.get("minimum_incident_confidence"), 75, 1, 100),
        ),
        response=ResponseConfig(
            automatic_blocking=_bool(response.get("automatic_blocking"), False),
            minimum_confidence=_int(response.get("minimum_confidence"), 95, 1, 100),
            minimum_risk_score=_int(response.get("minimum_risk_score"), 90, 1, 100),
            default_block_seconds=_int(response.get("default_block_seconds"), 3600, 60, 604800),
            max_block_seconds=_int(response.get("max_block_seconds"), 86400, 60, 2592000),
            max_concurrent_blocks=_int(response.get("max_concurrent_blocks"), 100, 0, 100000),
            block_external=_bool(response.get("block_external"), False),
            isolate_internal=_bool(response.get("isolate_internal"), False),
            manual_confirmation=_bool(response.get("manual_confirmation"), True),
            protect_management_networks=_bool(response.get("protect_management_networks"), True),
            forbid_block_on_service_error=_bool(response.get("forbid_block_on_service_error"), True),
            enforce_allowlist=_bool(response.get("enforce_allowlist"), True),
        ),
        data_dir=data_dir,
        log_dir=log_dir,
        run_dir=run_dir,
    )


def ensure_directories(config: PondSecConfig) -> None:
    for directory in (config.data_dir, config.log_dir, config.run_dir):
        directory.mkdir(parents=True, exist_ok=True)
