"""Safe response proposal engine for PondSec NDR."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.response.policy import evaluate_automatic_response_policy
from pondsec_ndr.response.pf import PFTableEnforcer
from pondsec_ndr.schema import is_private_ip
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

INTERNAL_ISOLATION_CATEGORIES = {
    "anomaly",
    "machine_learning",
    "lateral_movement",
    "command_and_control",
    "exfiltration",
}
PERMANENT_BLOCK_EXPIRES_AT = "9999-12-31T23:59:59+00:00"


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
    for configured in config.interfaces.management + config.interfaces.excluded_networks + config.response.protected_networks + config.response.break_glass_values:
        try:
            networks.append(ipaddress.ip_network(configured, strict=False))
        except ValueError:
            continue
    addresses = [ipaddress.ip_network(target, strict=False)] if "/" in target else [ipaddress.ip_network(f"{target}/32", strict=False)]
    for candidate in addresses:
        if any((candidate.version == network.version) and (candidate.subnet_of(network) or candidate.overlaps(network)) for network in networks):
            return True
    protected_hosts = set(config.interfaces.excluded_hosts + config.response.protected_hosts + config.response.break_glass_values)
    return target in protected_hosts


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


def normalize_block_expires_at(value: str | None) -> str:
    text = str(value or "").strip()
    if not text or text.lower() in {"never", "permanent", "unlimited", "infinite"}:
        return PERMANENT_BLOCK_EXPIRES_AT
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResponseDenied("invalid expiration timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if parsed <= datetime.now(timezone.utc):
        raise ResponseDenied("expiration timestamp must be in the future")
    return parsed.isoformat()


def propose_block_for_incident(
    store: EventStore,
    config: PondSecConfig,
    incident_id: str,
    actor: str = "system",
    duration_seconds: int | None = None,
    automatic: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise ResponseDenied("incident not found")
    source_ip = _response_target_for_incident(incident)
    if not source_ip:
        raise ResponseDenied("incident has no response target")
    protected = is_protected_target(source_ip, config)
    allowlisted = config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values() + config.response.break_glass_values)
    decision: dict[str, Any] | None = None
    if automatic:
        decision = evaluate_automatic_response_policy(store, config, incident, source_ip, protected, allowlisted)
        store.audit_response_decision(incident_id, "policy_decision", decision, actor=actor)
        if not decision["proposal_allowed"]:
            raise ResponseDenied("response policy denied: " + "; ".join(decision["reasons"]))
    if protected:
        raise ResponseDenied("source IP is protected")
    if allowlisted:
        raise ResponseDenied("source IP is allowlisted")
    if automatic and is_private_ip(source_ip) and not config.response.isolate_internal:
        raise ResponseDenied("automatic internal isolation is disabled")
    if automatic and not is_private_ip(source_ip) and not config.response.block_external:
        raise ResponseDenied("automatic external blocking is disabled")
    if incident["risk_score"] < config.response.minimum_risk_score:
        raise ResponseDenied("incident risk score is below response threshold")
    if float(incident["confidence"]) * 100 < config.response.minimum_confidence:
        raise ResponseDenied("incident confidence is below response threshold")
    existing = store.existing_response_block(incident_id, source_ip)
    if existing:
        result = dict(existing)
        if decision is not None:
            result["policy_decision"] = decision
        return result
    existing_for_source = store.existing_response_block(None, source_ip)
    if existing_for_source:
        result = dict(existing_for_source)
        if decision is not None:
            result["policy_decision"] = decision
        return result

    duration = duration_seconds or (config.response.auto_isolation_seconds if automatic else config.response.default_block_seconds)
    duration = min(duration, config.response.max_block_seconds)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
    if dry_run:
        result = {
            "block_id": None,
            "incident_id": incident_id,
            "source_ip": source_ip,
            "destination": incident.get("destination_ip"),
            "reason": _response_reason(incident, source_ip),
            "risk_score": incident["risk_score"],
            "confidence": incident["confidence"],
            "expires_at": expires_at,
            "created_by": actor,
            "automatic": automatic,
            "status": "would_execute",
            "dry_run": True,
        }
        if decision is not None:
            result["policy_decision"] = decision
        return result
    result = store.add_block_entry({
        "incident_id": incident_id,
        "source_ip": source_ip,
        "destination": incident.get("destination_ip"),
        "reason": _response_reason(incident, source_ip),
        "risk_score": incident["risk_score"],
        "confidence": incident["confidence"],
        "policy_id": None,
        "expires_at": expires_at,
        "created_by": actor,
        "automatic": automatic,
        "status": "proposed",
    }, actor=actor)
    if decision is not None:
        result["policy_decision"] = decision
    return result


def _response_target_for_incident(incident: dict[str, Any]) -> str | None:
    evidence = incident.get("evidence") if isinstance(incident.get("evidence"), dict) else {}
    if _requires_pre_nat_mapping(evidence):
        return None
    roles = evidence.get("entity_roles") if isinstance(evidence.get("entity_roles"), dict) else {}
    source_ip = incident.get("source_ip")
    if source_ip and is_private_ip(str(source_ip)):
        return str(source_ip)
    internal_actor = _internal_behavior_actor(evidence)
    if internal_actor:
        return internal_actor
    response_target = roles.get("response_target") if isinstance(roles, dict) else None
    if response_target and is_private_ip(str(response_target)):
        return str(response_target)
    return str(source_ip) if source_ip else None


def _requires_pre_nat_mapping(evidence: dict[str, Any]) -> bool:
    detections = evidence.get("detections") if isinstance(evidence.get("detections"), list) else []
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


def _internal_behavior_actor(evidence: dict[str, Any]) -> str | None:
    detections = evidence.get("detections") if isinstance(evidence.get("detections"), list) else []
    by_source: dict[str, set[str]] = {}
    confidence_by_source: dict[str, float] = {}
    max_score: dict[str, int] = {}
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        source = detection.get("source_ip")
        if not source or not is_private_ip(str(source)):
            continue
        category = str(detection.get("category") or "").lower()
        if category not in INTERNAL_ISOLATION_CATEGORIES:
            continue
        by_source.setdefault(str(source), set()).add(category)
        confidence_by_source[str(source)] = max(confidence_by_source.get(str(source), 0.0), float(detection.get("confidence") or 0))
        max_score[str(source)] = max(max_score.get(str(source), 0), int(detection.get("severity") or 0))
    candidates = []
    for source, categories in by_source.items():
        if (
            len(categories) >= 2
            and categories & {"command_and_control", "exfiltration", "lateral_movement"}
            and max_score.get(source, 0) >= 9
            and confidence_by_source.get(source, 0.0) >= 0.95
        ):
            candidates.append((source, len(categories), max_score.get(source, 0)))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[1], item[2]), reverse=True)
    return candidates[0][0]


def _response_reason(incident: dict[str, Any], target: str) -> str:
    if target != incident.get("source_ip") and is_private_ip(target):
        return f"Isolation proposal for internal host {target} from incident {incident.get('incident_id')}"
    return f"Response proposal for incident {incident.get('incident_id')}"


def propose_manual_block(
    store: EventStore,
    config: PondSecConfig,
    target: str,
    reason: str | None = None,
    actor: str = "system",
    duration_seconds: int | None = None,
) -> dict[str, Any]:
    source_ip = validate_ip_or_network(target)
    if is_protected_target(source_ip, config):
        raise ResponseDenied("source IP is protected")
    if config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values()):
        raise ResponseDenied("source IP is allowlisted")
    existing_for_source = store.existing_response_block(None, source_ip)
    if existing_for_source:
        return existing_for_source

    duration = duration_seconds or config.response.default_block_seconds
    duration = min(duration, config.response.max_block_seconds)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
    return store.add_block_entry({
        "incident_id": None,
        "source_ip": source_ip,
        "destination": None,
        "reason": reason or "Manual blocklist entry",
        "risk_score": config.response.minimum_risk_score,
        "confidence": 1.0,
        "policy_id": "manual",
        "expires_at": expires_at,
        "created_by": actor,
        "automatic": False,
        "status": "proposed",
    }, actor=actor)


def propose_manual_block_for_incident(
    store: EventStore,
    config: PondSecConfig,
    incident_id: str,
    actor: str = "system",
    duration_seconds: int | None = None,
) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise ResponseDenied("incident not found")
    source_ip = _response_target_for_incident(incident)
    if not source_ip:
        raise ResponseDenied("incident has no response target")
    source_ip = validate_ip_or_network(source_ip)
    if is_protected_target(source_ip, config):
        raise ResponseDenied("source IP is protected")
    if config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values() + config.response.break_glass_values):
        raise ResponseDenied("source IP is allowlisted")
    existing = store.existing_response_block(incident_id, source_ip) or store.existing_response_block(None, source_ip)
    if existing:
        return dict(existing)

    duration = duration_seconds or config.response.default_block_seconds
    duration = min(duration, config.response.max_block_seconds)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration)).isoformat()
    return store.add_block_entry({
        "incident_id": incident_id,
        "source_ip": source_ip,
        "destination": incident.get("destination_ip"),
        "reason": f"Manual block for incident {incident_id}",
        "risk_score": int(incident.get("risk_score") or 0),
        "confidence": float(incident.get("confidence") or 0),
        "policy_id": "manual-incident",
        "expires_at": expires_at,
        "created_by": actor,
        "automatic": False,
        "status": "proposed",
    }, actor=actor)


def edit_block_entry(
    store: EventStore,
    config: PondSecConfig,
    block_id: str,
    reason: str | None = None,
    expires_at: str | None = None,
    actor: str = "system",
) -> dict[str, Any]:
    block = store.get_block_entry(block_id)
    if block is None:
        raise ResponseDenied("block entry not found")
    if block.get("status") not in {"proposed", "active"}:
        raise ResponseDenied("block entry is not editable")
    source_ip = validate_ip_or_network(str(block["source_ip"]))
    if is_protected_target(source_ip, config):
        raise ResponseDenied("source IP is protected")
    if config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values() + config.response.break_glass_values):
        raise ResponseDenied("source IP is allowlisted")
    updated = store.update_block_entry(
        block_id,
        reason=str(reason or "").strip() or block.get("reason") or "Manual blocklist entry",
        expires_at=str(block.get("expires_at")) if expires_at is None else normalize_block_expires_at(expires_at),
        actor=actor,
    )
    if updated is None:
        raise ResponseDenied("block entry not found")
    return updated


def activate_block(
    store: EventStore,
    config: PondSecConfig,
    block_id: str,
    actor: str = "system",
    enforcer: PFTableEnforcer | None = None,
) -> dict[str, Any]:
    block = store.get_block_entry(block_id)
    if block is None:
        raise ResponseDenied("block entry not found")
    source_ip = validate_ip_or_network(block["source_ip"])
    if is_protected_target(source_ip, config):
        raise ResponseDenied("source IP is protected")
    if config.response.enforce_allowlist and is_allowlisted(source_ip, store.allowlist_values()):
        raise ResponseDenied("source IP is allowlisted")
    if store.active_block_count() >= config.response.max_concurrent_blocks:
        raise ResponseDenied("maximum concurrent blocks reached")
    pf = enforcer or PFTableEnforcer()
    result = pf.add(source_ip)
    if not result.ok:
        raise ResponseDenied(f"PF table add failed: {result.stderr or result.stdout or result.returncode}")
    changed = store.update_block_status(block_id, "active", actor=actor)
    verified = pf.test(source_ip)
    return {
        "status": "ok" if changed and verified.ok else "failed",
        "block_id": block_id,
        "source_ip": source_ip,
        "pf_table": pf.table,
        "pf_add": result.as_dict(),
        "pf_verify": verified.as_dict(),
        "pf_rule_present": pf.rule_present(),
    }


def remove_block(
    store: EventStore,
    block_id: str,
    reason: str = "manual removal",
    actor: str = "system",
    enforcer: PFTableEnforcer | None = None,
) -> dict[str, Any]:
    block = store.get_block_entry(block_id)
    if block is None:
        raise ResponseDenied("block entry not found")
    source_ip = validate_ip_or_network(block["source_ip"])
    changed = store.update_block_status(block_id, "removed", reason, actor=actor)
    still_active = source_ip in store.active_block_sources()
    pf = enforcer or PFTableEnforcer()
    result = None if still_active else pf.delete(source_ip)
    return {
        "status": "ok" if changed else "not_found",
        "block_id": block_id,
        "source_ip": source_ip,
        "pf_table": pf.table,
        "pf_removed": result.as_dict() if result else None,
        "pf_kept_for_other_active_blocks": still_active,
    }


def release_incident_response(
    store: EventStore,
    incident_id: str,
    reason: str = "case release",
    actor: str = "system",
    enforcer: PFTableEnforcer | None = None,
) -> dict[str, Any]:
    blocks = store.active_response_blocks_for_incident(incident_id)
    if not blocks:
        return {"status": "not_found", "incident_id": incident_id, "released": []}
    pf = enforcer or PFTableEnforcer()
    released = []
    for block in blocks:
        released.append(remove_block(store, block["block_id"], reason=reason, actor=actor, enforcer=pf))
    return {
        "status": "ok" if all(item.get("status") == "ok" for item in released) else "partial",
        "incident_id": incident_id,
        "released": released,
    }
