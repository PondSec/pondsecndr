"""Data source provider registry."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from pondsec_ndr.config import PondSecConfig


@dataclass(slots=True)
class DataSourceProvider:
    provider_id: str
    display_name: str
    description: str
    version: str
    enabled: bool
    health_status: str
    input_type: str
    event_types: list[str]
    configuration: dict[str, Any]
    statistics: dict[str, Any]
    last_successful_processing: str | None = None
    last_error: str | None = None
    safe_disable: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def provider_inventory(config: PondSecConfig, health: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    health = health or {}
    detail = health.get("detail", {}) if isinstance(health.get("detail"), dict) else {}
    sources = detail.get("collector_sources", {}) if isinstance(detail.get("collector_sources"), dict) else {}
    updated_at = health.get("updated_at")
    providers = [
        _suricata_provider(config, sources.get("suricata_eve") or {}, updated_at),
        _filterlog_provider(config, sources.get("opnsense_filterlog") or {}, updated_at),
        _dnsmasq_provider(config, sources.get("dnsmasq") or {}, updated_at),
        _zeek_provider(config, sources.get("zeek") or {}, updated_at),
        _netflow_provider(config, sources.get("netflow") or {}, updated_at),
        _zenarmor_provider(config, sources.get("zenarmor") or {}, updated_at),
    ]
    providers.extend(_planned_providers())
    return [provider.as_dict() for provider in providers]


def _suricata_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    enabled = bool(config.detection.suricata_events)
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="suricata_eve",
        display_name="Suricata EVE JSON",
        description="Reads normalized Suricata alert, flow, DNS, TLS, HTTP, file and anomaly telemetry.",
        version="1",
        enabled=enabled,
        health_status=_health(enabled, last_error, stats),
        input_type="file",
        event_types=["alert", "drop", "flow", "dns", "tls", "http", "file", "anomaly"],
        configuration={
            "path": config.suricata_eve_path,
            "max_event_rate": config.max_event_rate,
            "queue_limit": min(config.max_event_rate, 100000),
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if enabled and not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _filterlog_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="opnsense_filterlog",
        display_name="OPNsense Firewall Logs",
        description="Reads local PF filterlog block events for firewall-enforced traffic visibility.",
        version="1",
        enabled=True,
        health_status=_health(True, last_error, stats, optional=True),
        input_type="file",
        event_types=["firewall", "flow", "response"],
        configuration={
            "path": "/var/log/filter/latest.log",
            "max_event_rate": config.max_event_rate,
            "optional": True,
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _dnsmasq_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    enabled = bool(config.dnsmasq.enabled)
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="dnsmasq_dns_dhcp",
        display_name="dnsmasq DNS and DHCP",
        description="Reads dnsmasq DNS query, DHCP event and lease telemetry without changing resolver or DHCP settings.",
        version="1",
        enabled=enabled,
        health_status=_health(enabled, last_error, stats, optional=True),
        input_type="file",
        event_types=["dns", "dhcp", "asset"],
        configuration={
            "dns_log_path": config.dnsmasq.dns_log_path,
            "dhcp_log_path": config.dnsmasq.dhcp_log_path,
            "lease_path": config.dnsmasq.lease_path,
            "sensor_name": config.dnsmasq.sensor_name,
            "start_at_end": config.dnsmasq.start_at_end,
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if enabled and not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _zeek_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    enabled = bool(config.zeek.enabled)
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="zeek_logs",
        display_name="Zeek Logs",
        description="Reads configured Zeek TSV logs from a local or external sensor export path.",
        version="1",
        enabled=enabled,
        health_status=_health(enabled, last_error, stats, optional=True),
        input_type="file",
        event_types=["flow", "dns", "tls", "http", "file", "notice", "anomaly"],
        configuration={
            "mode": config.zeek.mode,
            "parser": config.zeek.parser,
            "sensor_name": config.zeek.sensor_name,
            "interface": config.zeek.interface,
            "remote_target": config.zeek.remote_target,
            "log_dir": config.zeek.log_dir,
            "start_at_end": config.zeek.start_at_end,
            "logs": {name: str(path) for name, path in config.zeek.log_paths().items()},
            "health": {
                "rotation": "tracked_per_log",
                "offset_recovery": "inode_and_size_checked",
                "monitoring": "provider_inventory_and_service_health",
            },
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if enabled and not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _netflow_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    enabled = bool(config.netflow.enabled)
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="netflow",
        display_name="NetFlow / IPFIX",
        description="Receives NetFlow v5, NetFlow v9 template health and IPFIX-ready UDP flow telemetry.",
        version="1",
        enabled=enabled,
        health_status=_health(enabled, last_error, stats, optional=True),
        input_type="udp",
        event_types=["flow"],
        configuration={
            "listen_address": config.netflow.listen_address,
            "port": config.netflow.port,
            "allowed_exporters": config.netflow.allowed_exporters,
            "sampling_rate": config.netflow.sampling_rate,
            "template_ttl_seconds": config.netflow.template_ttl_seconds,
            "retention_days": config.netflow.retention_days,
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if enabled and not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _zenarmor_provider(config: PondSecConfig, stats: dict[str, Any], updated_at: str | None) -> DataSourceProvider:
    enabled = bool(config.zenarmor.enabled)
    last_error = stats.get("last_error")
    return DataSourceProvider(
        provider_id="zenarmor",
        display_name="Zenarmor Reporting",
        description="Reads documented Zenarmor reporting, official-log and API metadata for application, TLS, device, policy and security context.",
        version="1",
        enabled=enabled,
        health_status=_health(enabled, last_error, stats, optional=True),
        input_type="file",
        event_types=["flow", "tls", "http", "dns", "application", "security"],
        configuration={
            "source": config.zenarmor.source,
            "format": config.zenarmor.format,
            "sensor_name": config.zenarmor.sensor_name,
            "remote_target": config.zenarmor.remote_target,
            "syslog_path": config.zenarmor.syslog_path,
            "start_at_end": config.zenarmor.start_at_end,
            "api_enabled": config.zenarmor.api_enabled,
            "api_base_url": config.zenarmor.api_base_url,
            "api_key_ref": config.zenarmor.api_key_ref,
            "api_timeout_seconds": config.zenarmor.api_timeout_seconds,
            "api_verify_tls": config.zenarmor.api_verify_tls,
            "imports": {
                "applications": config.zenarmor.import_applications,
                "categories": config.zenarmor.import_categories,
                "tls_metadata": config.zenarmor.import_tls_metadata,
                "session_context": config.zenarmor.import_session_context,
                "policy_actions": config.zenarmor.import_policy_actions,
                "device_context": config.zenarmor.import_device_context,
                "security_events": config.zenarmor.import_security_events,
            },
        },
        statistics=_stats(stats),
        last_successful_processing=updated_at if enabled and not last_error and _accepted(stats) else None,
        last_error=last_error,
    )


def _planned_providers() -> list[DataSourceProvider]:
    planned = [
        ("ipfix", "IPFIX", "udp", ["flow"]),
        ("sflow", "sFlow", "udp", ["flow"]),
        ("unbound_dns", "Unbound DNS Logs", "file", ["dns"]),
        ("isc_dhcp_leases", "ISC DHCP Lease Events", "file", ["dhcp", "asset"]),
        ("arp_neighbor", "ARP / Neighbor Tables", "system", ["asset"]),
        ("crowdsec", "CrowdSec Decisions", "local_api", ["threat_intelligence", "response"]),
        ("syslog", "Syslog", "udp", ["system", "authentication", "firewall"]),
        ("rest_ingest", "REST API Ingest", "api", ["generic_json"]),
        ("file_import", "File Import", "file", ["generic_json"]),
        ("pcap_import", "PCAP Import", "file", ["flow"]),
    ]
    return [
        DataSourceProvider(
            provider_id=provider_id,
            display_name=display_name,
            description="Provider interface reserved; enable once configured by the administrator.",
            version="0",
            enabled=False,
            health_status="not_configured",
            input_type=input_type,
            event_types=event_types,
            configuration={"requires_configuration": True},
            statistics={"accepted_events": 0, "parser_errors": 0, "queue_drops": 0},
            safe_disable=True,
        )
        for provider_id, display_name, input_type, event_types in planned
    ]


def _health(enabled: bool, last_error: str | None, stats: dict[str, Any], optional: bool = False) -> str:
    if not enabled:
        return "not_configured" if optional else "disabled"
    if last_error:
        return "warning" if optional else "degraded"
    if stats:
        return "healthy"
    return "waiting"


def _accepted(stats: dict[str, Any]) -> bool:
    return int(stats.get("accepted_events") or 0) > 0 or int(stats.get("read_lines") or 0) > 0


def _stats(stats: dict[str, Any]) -> dict[str, Any]:
    return {
        "read_lines": int(stats.get("read_lines") or 0),
        "accepted_events": int(stats.get("accepted_events") or 0),
        "parser_errors": int(stats.get("parser_errors") or 0),
        "normalization_errors": int(stats.get("normalization_errors") or 0),
        "queue_drops": int(stats.get("queue_drops") or 0),
        "duplicates": int(stats.get("duplicates") or 0),
        "rotation_detected": bool(stats.get("rotation_detected")),
    }
