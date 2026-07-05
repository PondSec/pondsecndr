"""Safe response proposal engine for PondSec NDR."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.storage.database import EventStore


PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("0.0.0.0/32"),
]


class ResponseDenied(ValueError):
    """Raised when a response action is not safe."""


def validate_ip_or_network(value: str) -> str:
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ResponseDenied(f"invalid IP or network: {value}") from exc


def is_protected_target(value: str, config: PondSecConfig) -> bool:
    target = validate_ip_or_network(value)
    networks = list(PROTECTED_NETWORKS)
    for configured in config.interfaces.management + config.interfaces.excluded_networks:
        try:
            networks.append(ipaddress.ip_network(configured, strict=False))
        except ValueError:
            continue
    addresses = [ipaddress.ip_network(target, strict=False)] if "/" in target else [ipaddress.ip_network(f"{target}/32", strict=False)]
    for candidate in addresses:
        if any((candidate.version == network.version) and (candidate.subnet_of(network) or candidate.overlaps(network)) for network in networks):
            return True
    return target in config.interfaces.excluded_hosts


def is_allowlisted(value: str, allowlist_values: list[str]) -> bool:
    target = ipaddress.ip_network(validate_ip_or_network(value), strict=False)
    for allowed in allowlist_values:
        try:
            allowed_network = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            continue
        if target.subnet_of(allowed_network) or target.overlaps(allowed_network):
            return True
    return False


def propose_block_for_incident(
    store: EventStore,
    config: PondSecConfig,
    incident_id: str,
    actor: str = "system",
    duration_seconds: int | None = None,
) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise ResponseDenied("incident not found")
    source_ip = incident.get("source_ip")
    if not source_ip:
        raise ResponseDenied("incident has no source IP")
    if is_protected_target(source_ip, config):
        raise ResponseDenied("source IP is protected")
    if config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values()):
        raise ResponseDenied("source IP is allowlisted")
    if incident["risk_score"] < config.response.minimum_risk_score:
        raise ResponseDenied("incident risk score is below response threshold")
    if float(incident["confidence"]) * 100 < config.response.minimum_confidence:
        raise ResponseDenied("incident confidence is below response threshold")

    duration = duration_seconds or config.response.default_block_seconds
    duration = min(duration, config.response.max_block_seconds)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
    return store.add_block_entry({
        "incident_id": incident_id,
        "source_ip": source_ip,
        "destination": incident.get("destination_ip"),
        "reason": f"Response proposal for incident {incident_id}",
        "risk_score": incident["risk_score"],
        "confidence": incident["confidence"],
        "policy_id": None,
        "expires_at": expires_at,
        "created_by": actor,
        "automatic": False,
        "status": "proposed",
    }, actor=actor)
