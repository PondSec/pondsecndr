"""Automatic response policy evaluation for PondSec NDR."""

from __future__ import annotations

from typing import Any

from pondsec_ndr.config import PondSecConfig
from pondsec_ndr.schema import is_private_ip
from pondsec_ndr.storage.database import EventStore


STRONG_INTERNAL_CATEGORIES = {
    "command_and_control",
    "lateral_movement",
    "exfiltration",
    "credential_abuse",
    "malware",
}

NOISY_SINGLE_SIGNAL_CATEGORIES = {
    "reconnaissance",
    "signature",
    "reputation",
}


def evaluate_automatic_response_policy(
    store: EventStore,
    config: PondSecConfig,
    incident: dict[str, Any],
    target_ip: str,
    protected: bool,
    allowlisted: bool,
) -> dict[str, Any]:
    """Evaluate whether an automatic response may be proposed or enforced."""
    summary = _evidence_summary(incident, config)
    reasons: list[str] = []
    activation_reasons: list[str] = []
    mode = config.response.mode
    target_is_internal = is_private_ip(target_ip)
    learning_status = config.detection.learning_status()

    if config.response.kill_switch:
        reasons.append("global response kill switch is active")
    if config.response.maintenance_mode:
        reasons.append("maintenance mode is active")
    if protected:
        reasons.append("target is protected")
    if allowlisted:
        reasons.append("target is allowlisted or break-glass protected")
    if learning_status.get("active"):
        reasons.append("learning phase is active")
    elif target_is_internal and not _learning_complete_for_response(learning_status):
        reasons.append("learning phase is not complete for internal auto-isolation")
    if int(incident.get("risk_score") or 0) < config.response.minimum_risk_score:
        reasons.append("incident risk score is below response threshold")
    if int(incident.get("severity") or 0) < config.response.minimum_severity:
        reasons.append("incident severity is below response threshold")
    if float(incident.get("confidence") or 0.0) * 100 < config.response.minimum_confidence:
        reasons.append("incident confidence is below response threshold")

    if target_is_internal:
        reasons.extend(_internal_isolation_reasons(store, config, incident, target_ip, summary))
        if not config.response.ai_full_decision_mode:
            activation_reasons.append("AI full decision mode is not enabled for internal auto-isolation")
    elif not config.response.block_external:
        reasons.append("automatic external blocking is disabled")

    if mode == "observe":
        policy_status = "observe"
        reasons.append("response policy is in observe mode")
    elif mode == "recommend":
        policy_status = "recommend" if not reasons else "denied"
    elif mode == "enforce":
        if reasons:
            policy_status = "denied"
        elif activation_reasons:
            policy_status = "recommend"
        else:
            policy_status = "enforce"
    elif mode == "shadow_enforce":
        if reasons:
            policy_status = "denied"
        elif activation_reasons:
            policy_status = "recommend"
        else:
            policy_status = "shadow_enforce"
    else:
        policy_status = "denied"
        reasons.append(f"invalid response policy mode: {mode}")

    all_reasons = reasons + activation_reasons
    decision_layers = _decision_layers(
        config,
        incident,
        target_ip,
        target_is_internal,
        summary,
        learning_status,
        reasons,
        activation_reasons,
        policy_status,
    )
    return {
        "status": policy_status,
        "target_ip": target_ip,
        "target_internal": target_is_internal,
        "proposal_allowed": policy_status in {"recommend", "enforce", "shadow_enforce"},
        "activation_allowed": policy_status == "enforce",
        "would_execute": policy_status == "shadow_enforce",
        "reasons": all_reasons,
        "blocking_reasons": reasons,
        "activation_reasons": activation_reasons,
        "learning_status": learning_status,
        "evidence": summary,
        "decision_layers": decision_layers,
        "thresholds": {
            "minimum_risk_score": config.response.minimum_risk_score,
            "minimum_severity": config.response.minimum_severity,
            "minimum_confidence": config.response.minimum_confidence,
            "min_internal_event_count": config.response.min_internal_event_count,
            "min_internal_detection_count": config.response.min_internal_detection_count,
            "min_internal_categories": config.response.min_internal_categories,
            "min_supporting_indicators": config.response.min_supporting_indicators,
            "min_independent_engines": config.response.min_independent_engines,
            "baseline_stable_observations": config.response.baseline_stable_observations,
            "internal_isolation_cooldown_seconds": config.response.internal_isolation_cooldown_seconds,
            "max_internal_isolations_per_hour": config.response.max_internal_isolations_per_hour,
        },
    }


def _learning_complete_for_response(learning_status: dict[str, Any]) -> bool:
    return (
        learning_status.get("status") == "armed"
        and bool(learning_status.get("started_at"))
        and int(learning_status.get("remaining_days") or 0) == 0
    )


def _decision_layers(
    config: PondSecConfig,
    incident: dict[str, Any],
    target_ip: str,
    target_is_internal: bool,
    summary: dict[str, Any],
    learning_status: dict[str, Any],
    blocking_reasons: list[str],
    activation_reasons: list[str],
    policy_status: str,
) -> dict[str, Any]:
    risk_score = int(incident.get("risk_score") or 0)
    severity = int(incident.get("severity") or 0)
    confidence_percent = float(incident.get("confidence") or 0.0) * 100
    event_count = int(incident.get("event_count") or 0)
    detection_count = int(incident.get("detection_count") or summary["detections_considered"] or 0)
    threshold_passes = {
        "risk_score": risk_score >= config.response.minimum_risk_score,
        "severity": severity >= config.response.minimum_severity,
        "confidence": confidence_percent >= config.response.minimum_confidence,
    }
    evidence_passes = {
        "event_count": event_count >= config.response.min_internal_event_count,
        "detection_count": detection_count >= config.response.min_internal_detection_count,
        "category_count": len(summary["categories"]) >= config.response.min_internal_categories,
        "supporting_indicator_count": len(summary["supporting_indicators"]) >= config.response.min_supporting_indicators,
        "independent_engine_count": len(summary["independent_engines"]) >= config.response.min_independent_engines,
        "strong_attack_category": bool(set(summary["categories"]) & STRONG_INTERNAL_CATEGORIES),
        "not_ml_only": not summary["ml_only"],
        "not_noisy_single_signal": not set(summary["categories"]).issubset(NOISY_SINGLE_SIGNAL_CATEGORIES),
        "not_prevented_only": not summary["all_prevented_or_blocked"],
    }
    compromise_ready = target_is_internal and all(threshold_passes.values()) and all(evidence_passes.values())
    containment_allowed = policy_status in {"recommend", "enforce", "shadow_enforce"}
    execution_allowed = policy_status == "enforce"
    shadow_execution = policy_status == "shadow_enforce"
    return {
        "detection": {
            "status": "observed" if detection_count > 0 else "insufficient_evidence",
            "event_count": event_count,
            "detection_count": detection_count,
            "categories": summary["categories"],
            "detector_ids": summary["detector_ids"],
            "engines": summary["independent_engines"],
            "data_sources": summary["data_sources"],
        },
        "compromise_assessment": {
            "status": "likely_compromised" if compromise_ready else "unconfirmed",
            "target": target_ip,
            "target_internal": target_is_internal,
            "threshold_passes": threshold_passes,
            "evidence_passes": evidence_passes,
            "learning_status": learning_status.get("status"),
            "statement": (
                "Internal compromise is likely based on independent corroborated evidence."
                if compromise_ready
                else "Compromise is not confirmed by the required independent evidence."
            ),
        },
        "containment_decision": {
            "status": "eligible" if containment_allowed else "denied",
            "mode": config.response.mode,
            "blocking_reasons": blocking_reasons,
        },
        "execution": {
            "status": "allowed" if execution_allowed else ("would_execute" if shadow_execution else "not_allowed"),
            "activation_reasons": activation_reasons,
            "automatic_blocking": config.response.automatic_blocking,
            "ai_full_decision_mode": config.response.ai_full_decision_mode,
            "kill_switch": config.response.kill_switch,
            "maintenance_mode": config.response.maintenance_mode,
        },
    }


def _internal_isolation_reasons(
    store: EventStore,
    config: PondSecConfig,
    incident: dict[str, Any],
    target_ip: str,
    summary: dict[str, Any],
) -> list[str]:
    reasons = []
    if not config.response.isolate_internal:
        reasons.append("automatic internal isolation is disabled")
    if int(incident.get("event_count") or 0) < config.response.min_internal_event_count:
        reasons.append("not enough correlated events for internal isolation")
    if int(incident.get("detection_count") or 0) < config.response.min_internal_detection_count:
        reasons.append("not enough correlated detections for internal isolation")
    if len(summary["categories"]) < config.response.min_internal_categories:
        reasons.append("not enough independent detection categories for internal isolation")
    if not (set(summary["categories"]) & STRONG_INTERNAL_CATEGORIES):
        reasons.append("no strong internal compromise category is present")
    if len(summary["supporting_indicators"]) < config.response.min_supporting_indicators:
        reasons.append("not enough supporting indicators for internal isolation")
    if len(summary["independent_engines"]) < config.response.min_independent_engines:
        reasons.append("not enough independent engines for internal isolation")
    if summary["ml_only"]:
        reasons.append("machine-learning evidence cannot isolate a client by itself")
    if set(summary["categories"]).issubset(NOISY_SINGLE_SIGNAL_CATEGORIES):
        reasons.append("single-signal scan, signature, or reputation evidence cannot isolate an internal client")
    if summary["all_prevented_or_blocked"]:
        reasons.append("prevented or blocked events alone cannot justify internal isolation")
    baseline_observations = store.host_baseline_observations(target_ip)
    if baseline_observations < config.response.baseline_stable_observations:
        reasons.append("host baseline is not stable enough for automatic isolation")
    if (
        config.response.internal_isolation_cooldown_seconds > 0
        and store.recent_automatic_internal_block_count(config.response.internal_isolation_cooldown_seconds) >= 1
    ):
        reasons.append("internal auto-isolation cooldown is active")
    if store.recent_automatic_internal_block_count(3600) >= config.response.max_internal_isolations_per_hour:
        reasons.append("internal auto-isolation hourly rate limit reached")
    return reasons


def _evidence_summary(incident: dict[str, Any], config: PondSecConfig) -> dict[str, Any]:
    evidence = incident.get("evidence") if isinstance(incident.get("evidence"), dict) else {}
    detections = evidence.get("detections") if isinstance(evidence.get("detections"), list) else []
    detections = [item for item in detections if isinstance(item, dict)]
    categories = sorted({str(item.get("category") or "unknown") for item in detections})
    detector_ids = sorted({str(item.get("detector_id") or "unknown") for item in detections})
    engines = sorted({_engine_for_detection(item) for item in detections})
    sources = sorted({source for item in detections for source in _sources_for_detection(item)})
    supporting = sorted({indicator for item in detections for indicator in _supporting_indicators(item, config)})
    prevented_flags = [_is_prevented_or_blocked(item) for item in detections]
    ml_ids = {"pondsec.pretrained_ids_model"}
    return {
        "categories": categories,
        "detector_ids": detector_ids,
        "independent_engines": engines,
        "data_sources": sources,
        "supporting_indicators": supporting,
        "ml_only": bool(detections) and all(str(item.get("detector_id")) in ml_ids or str(item.get("category")) == "machine_learning" for item in detections),
        "all_prevented_or_blocked": bool(prevented_flags) and all(prevented_flags),
        "detections_considered": len(detections),
    }


def _engine_for_detection(detection: dict[str, Any]) -> str:
    detector_id = str(detection.get("detector_id") or "")
    category = str(detection.get("category") or "")
    if detector_id.startswith("pondsec.suricata") or _evidence(detection).get("signature_id"):
        return "suricata"
    if detector_id == "pondsec.pretrained_ids_model" or category == "machine_learning":
        return "machine_learning"
    if detector_id == "pondsec.dns_tunneling":
        return "dns"
    if detector_id == "pondsec.unusual_tls_fingerprint":
        return "tls"
    if "intel" in detector_id or category == "threat_intelligence":
        return "threat_intel"
    return "behavior"


def _sources_for_detection(detection: dict[str, Any]) -> set[str]:
    evidence = _evidence(detection)
    values = set()
    for key in ("provider_id", "event_source", "raw_source", "source"):
        value = evidence.get(key)
        if isinstance(value, str) and value:
            values.add(value)
    for key in ("providers", "event_sources", "raw_sources"):
        value = evidence.get(key)
        if isinstance(value, list):
            values.update(str(item) for item in value if item)
    if not values:
        values.add("suricata_eve")
    return values


def _supporting_indicators(detection: dict[str, Any], config: PondSecConfig) -> set[str]:
    detector_id = str(detection.get("detector_id") or "")
    category = str(detection.get("category") or "")
    evidence = _evidence(detection)
    indicators = set()
    if detector_id == "pondsec.beaconing" or "periodicity" in evidence:
        indicators.add("beaconing")
    if detector_id == "pondsec.dns_tunneling":
        indicators.add("dns_anomaly")
    if detector_id == "pondsec.host_baseline_anomaly":
        indicators.add("baseline_deviation")
    if detector_id == "pondsec.lateral_movement" or category == "lateral_movement":
        indicators.add("unusual_internal_access")
    if detector_id == "pondsec.data_exfiltration" or category == "exfiltration":
        indicators.add("data_transfer")
    if detector_id == "pondsec.unusual_tls_fingerprint":
        indicators.add("tls_fingerprint")
    if "intel" in detector_id or category == "threat_intelligence":
        indicators.add("threat_intel")
    if config.response.ai_full_decision_mode and (detector_id == "pondsec.pretrained_ids_model" or category == "machine_learning"):
        indicators.add("ml_assessment")
    return indicators


def _is_prevented_or_blocked(detection: dict[str, Any]) -> bool:
    detector_id = str(detection.get("detector_id") or "")
    evidence = _evidence(detection)
    action = str(evidence.get("suricata_action") or evidence.get("action") or "").lower()
    return detector_id == "pondsec.suricata_drop" or action in {"blocked", "block", "drop", "dropped", "reject"}


def _evidence(detection: dict[str, Any]) -> dict[str, Any]:
    evidence = detection.get("evidence")
    return evidence if isinstance(evidence, dict) else {}
