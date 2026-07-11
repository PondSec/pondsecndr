"""Detection correlation into incident cases."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pondsec_ndr.risk import score_detection_group, severity_from_risk


DEFAULT_CORRELATION_WINDOW_SECONDS = 1800
PROMOTION_THRESHOLD = 70
INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
STRONG_INCIDENT_DETECTORS = {
    "pondsec.credential_bruteforce",
    "pondsec.data_exfiltration",
    "pondsec.dns_tunneling",
    "pondsec.exploit_attempt",
    "pondsec.exploit_blocked",
    "pondsec.lateral_movement",
    "pondsec.malware_callback",
    "pondsec.suricata_drop",
}
WEB_FANOUT_PORTS = {80, 443, 853}


def correlate_detections(detections: list[dict[str, Any]], window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS) -> list[dict[str, Any]]:
    """Build incident cases from related detections.

    Category equality is intentionally not a requirement. A realistic attack
    often starts as reconnaissance, then produces a signature alert, then host
    anomaly or beaconing detections. These belong in one case when the entities
    and timeline make that relation plausible.
    """

    window_seconds = max(60, int(window_seconds or DEFAULT_CORRELATION_WINDOW_SECONDS))
    cases: list[dict[str, Any]] = []
    for detection in sorted((item for item in detections if isinstance(item, dict)), key=_detection_sort_key):
        related = _find_related_case(cases, detection, window_seconds)
        if related is None:
            related = _new_case(detection)
            cases.append(related)
        else:
            related["detections"].append(detection)
            related["first_seen"] = min(related["first_seen"], _detection_time(detection))
            related["last_seen"] = max(related["last_seen"], _detection_time(detection))
            _update_case_indexes(related, detection)

    incidents: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for case in cases:
        items = case["detections"]
        risk_score, factors = score_detection_group(items)
        if risk_score < 35:
            promotion = _suppression_decision(items, categories=[], reason="risk_score_below_incident_floor", score=risk_score)
            _annotate_detection_promotion(items, promotion, "suppressed")
            continue
        roles = _entity_roles(items)
        categories = sorted({str(item.get("category") or "unknown") for item in items})
        category = "multi_stage" if len(categories) > 1 else categories[0]
        promotable, promotion = _incident_promotion(items, categories, risk_score, roles)
        if not promotable:
            _annotate_detection_promotion(items, promotion, "suppressed")
            continue
        _annotate_detection_promotion(items, promotion, "promoted")
        first_seen = min(str(item.get("timestamp") or now) for item in items)
        last_seen = max(str(item.get("timestamp") or now) for item in items)
        source_ip = roles.get("threat_source") or _most_common([item.get("source_ip") for item in items])
        destination_ip = roles.get("victim") or roles.get("destination") or _common_destination(items)
        detection_ids = [str(item["detection_id"]) for item in items if item.get("detection_id")]
        basis = "|".join([
            str(source_ip or "unknown-source"),
            str(roles.get("victim") or destination_ip or "unknown-target"),
            category,
            ",".join(sorted(detection_ids)),
        ])
        stages = sorted({_stage_for_category(str(item.get("category") or "")) for item in items})
        incident = {
            "incident_id": str(uuid5(NAMESPACE_URL, basis)),
            "title": _title(category, source_ip, roles, len(items), categories),
            "status": "open",
            "risk_score": risk_score,
            "severity": severity_from_risk(risk_score),
            "confidence": round(max(float(item["confidence"]) for item in items), 4),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "category": category,
            "created_at": now,
            "updated_at": now,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "event_count": max(1, sum(_evidence_event_count(item) for item in items)),
            "detection_count": len(items),
            "affected_targets": _affected_targets(items, roles),
            "attack_stage": "multi_stage" if len(stages) > 1 else stages[0],
            "evidence": {
                "detections": items,
                "entity_roles": roles,
                "attack_sequence": _attack_sequence(items),
                "correlation": {
                    "rule": "cross-category entity and timeline correlation",
                    "correlation_window_seconds": window_seconds,
                    "detection_count": len(items),
                    "categories": categories,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "risk_factors": factors,
                    "category_equality_required": False,
                    "promotion": promotion,
                    "certainty_note": "This case links related detections; it does not confirm successful compromise without explicit success evidence.",
                },
            },
            "risk_factors": factors,
            "detection_ids": detection_ids,
        }
        incidents.append(incident)
    return incidents


def _incident_promotion(
    detections: list[dict[str, Any]],
    categories: list[str],
    risk_score: int,
    roles: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    score, positive, negative = _promotion_score(detections, categories, risk_score, roles)
    detector_ids = {str(item.get("detector_id") or "") for item in detections}
    base = {
        "promotion_score": score,
        "promotion_threshold": PROMOTION_THRESHOLD,
        "positive_evidence": positive,
        "negative_evidence": negative,
        "categories": categories,
        "detectors": sorted(detector_ids),
        "attack_stages": sorted({_stage_for_category(category) for category in categories}),
        "entity_consistency": _entity_consistency(detections),
        "roles": roles,
    }
    if score >= PROMOTION_THRESHOLD:
        decision = dict(base)
        decision.update({
            "decision": "promoted",
            "reason": _promotion_reason(positive),
        })
        return True, decision

    decision = dict(base)
    decision.update({
        "decision": "suppressed",
        "reason": _suppression_reason(negative),
    })
    return False, decision


def _promotion_score(
    detections: list[dict[str, Any]],
    categories: list[str],
    risk_score: int,
    roles: dict[str, Any],
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    positive: list[dict[str, Any]] = []
    negative: list[dict[str, Any]] = []
    detector_ids = {str(item.get("detector_id") or "") for item in detections}
    stages = {_stage_for_category(category) for category in categories}
    avg_confidence = sum(float(item.get("confidence") or 0) for item in detections) / max(1, len(detections))
    max_severity = max((int(item.get("severity") or 0) for item in detections), default=0)

    score = 0
    score += _add_factor(positive, "detection_confidence", int(avg_confidence * 20), {"average_confidence": round(avg_confidence, 4)})
    score += _add_factor(positive, "severity", min(36, max_severity * 4), {"max_severity": max_severity})
    score += _add_factor(positive, "independent_detectors", min(15, len(detector_ids) * 6), {"count": len(detector_ids)})
    score += _add_factor(positive, "attack_stage_coverage", min(16, len(stages) * 8), {"stages": sorted(stages)})
    score += _add_factor(positive, "risk_score_context", min(10, max(0, risk_score // 10)), {"risk_score": risk_score})

    strong_detectors = sorted(detector_ids & STRONG_INCIDENT_DETECTORS)
    marker_supply_chain = _has_marker_supply_chain(detections)
    high_confidence_signature = _has_high_confidence_signature(detections)
    high_confidence_ml = _has_high_confidence_ml(detections)
    actionable_reconnaissance = _has_actionable_reconnaissance(detections, roles)
    if strong_detectors:
        score += _add_factor(positive, "strong_detector", 35, {"detectors": strong_detectors})
    if marker_supply_chain:
        score += _add_factor(positive, "supply_chain_marker", 30, {})
    if high_confidence_signature:
        score += _add_factor(positive, "high_confidence_signature", 25, {})
    if high_confidence_ml:
        score += _add_factor(positive, "high_confidence_model", 25, {})
    if actionable_reconnaissance:
        score += _add_factor(positive, "actionable_reconnaissance", 25, {})
    if _entity_consistency(detections):
        score += _add_factor(positive, "entity_consistency", 6, {})
    if roles.get("external_actor") and roles.get("victim"):
        score += _add_factor(positive, "clear_direction", 6, {"direction": "external_to_internal"})
    if _provider_quality(detections) == "high":
        score += _add_factor(positive, "provider_data_quality", 6, {"quality": "high"})

    has_strong_context = bool(
        strong_detectors
        or marker_supply_chain
        or high_confidence_signature
        or high_confidence_ml
        or actionable_reconnaissance
    )
    if len(detector_ids) == 1 and not has_strong_context:
        score -= _add_factor(negative, "single_weak_detector", 25, {"detectors": sorted(detector_ids)})
    if _is_web_fanout_only(detections):
        score -= _add_factor(negative, "normal_https_fanout", 40, {})
    if _is_heuristic_supply_chain_only(detections):
        score -= _add_factor(negative, "supply_chain_without_marker", 35, {})
    if _is_beacon_only(detections):
        score -= _add_factor(negative, "periodicity_without_corroboration", 30, {})
    if _has_immature_baseline(detections):
        score -= _add_factor(negative, "immature_baseline", 25, {})
    if _has_many_external_destinations_without_failures(detections):
        score -= _add_factor(negative, "external_fanout_without_scan_failures", 20, {})
    benign_context = _benign_application_context(detections)
    if benign_context and not (marker_supply_chain or high_confidence_signature or strong_detectors):
        score -= _add_factor(negative, "known_benign_application_context", 25, {"context": benign_context})
    if not _has_reputation_or_signature_context(detections) and not actionable_reconnaissance:
        score -= _add_factor(negative, "missing_reputation_or_signature_context", 5, {})

    return max(0, min(100, score)), positive, negative


def _add_factor(target: list[dict[str, Any]], name: str, value: int, detail: dict[str, Any]) -> int:
    value = int(max(0, value))
    if value:
        target.append({"name": name, "value": value, **detail})
    return value


def _promotion_reason(positive: list[dict[str, Any]]) -> str:
    names = {item["name"] for item in positive}
    for name in (
        "strong_detector",
        "supply_chain_marker",
        "high_confidence_signature",
        "high_confidence_model",
        "actionable_reconnaissance",
    ):
        if name in names:
            return name
    if "attack_stage_coverage" in names and "independent_detectors" in names:
        return "corroborated_multi_signal"
    return "promotion_score_threshold"


def _suppression_reason(negative: list[dict[str, Any]]) -> str:
    if not negative:
        return "promotion_score_below_threshold"
    return str(max(negative, key=lambda item: int(item.get("value") or 0)).get("name") or "promotion_score_below_threshold")


def _suppression_decision(
    detections: list[dict[str, Any]],
    categories: list[str],
    reason: str,
    score: int = 0,
) -> dict[str, Any]:
    detector_ids = {str(item.get("detector_id") or "") for item in detections}
    return {
        "decision": "suppressed",
        "reason": reason,
        "promotion_score": score,
        "promotion_threshold": PROMOTION_THRESHOLD,
        "positive_evidence": [],
        "negative_evidence": [{"name": reason, "value": PROMOTION_THRESHOLD}],
        "categories": categories,
        "detectors": sorted(detector_ids),
    }


def _annotate_detection_promotion(detections: list[dict[str, Any]], promotion: dict[str, Any], state: str) -> None:
    for detection in detections:
        evidence = detection.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
            detection["evidence"] = evidence
        evidence["detection_state"] = state
        evidence["promotion"] = promotion


def _entity_consistency(detections: list[dict[str, Any]]) -> bool:
    sources = {_text_or_none(item.get("source_ip")) for item in detections}
    sources.discard(None)
    if len(sources) == 1:
        return True
    destinations = {_text_or_none(item.get("destination_ip")) for item in detections}
    destinations.discard(None)
    return bool(sources & destinations)


def _provider_quality(detections: list[dict[str, Any]]) -> str:
    signals = 0
    for detection in detections:
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        if evidence.get("signature_id") or evidence.get("suricata_action") or evidence.get("event_source"):
            signals += 1
        if evidence.get("raw_sources") or evidence.get("providers") or evidence.get("source"):
            signals += 1
        if evidence.get("application") or evidence.get("sni") or evidence.get("domain"):
            signals += 1
    return "high" if signals >= 2 else "low"


def _is_web_fanout_only(detections: list[dict[str, Any]]) -> bool:
    if not detections:
        return False
    for detection in detections:
        if detection.get("detector_id") != "pondsec.horizontal_scan":
            return False
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        port = _safe_int(evidence.get("port"))
        source = _text_or_none(detection.get("source_ip"))
        if port not in WEB_FANOUT_PORTS or not source or not _is_internal_address(source):
            return False
    return True


def _is_heuristic_supply_chain_only(detections: list[dict[str, Any]]) -> bool:
    return bool(detections) and all(
        detection.get("detector_id") == "pondsec.supply_chain_callback"
        and isinstance(detection.get("evidence"), dict)
        and detection["evidence"].get("signature_required") is False
        for detection in detections
    )


def _is_beacon_only(detections: list[dict[str, Any]]) -> bool:
    return bool(detections) and all(detection.get("detector_id") == "pondsec.beaconing" for detection in detections)


def _has_immature_baseline(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        status = str(evidence.get("baseline_status") or "")
        observations = int(evidence.get("baseline_observations") or 0)
        if status in {"building", "incomplete", "learning"} or (status and observations < 50):
            return True
    return False


def _has_many_external_destinations_without_failures(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        destinations = int(evidence.get("destination_count") or evidence.get("unique_destinations") or 0)
        external = int(evidence.get("external_connections") or 0)
        failures = int(evidence.get("failed_connections") or 0)
        if (destinations >= 35 or external >= 35) and failures < 5:
            return True
    return False


def _benign_application_context(detections: list[dict[str, Any]]) -> list[str]:
    terms = {
        "apple",
        "microsoft",
        "google",
        "cloudflare",
        "akamai",
        "cdn",
        "update",
        "telemetry",
        "push",
        "ntp",
        "backup",
        "zoom",
        "teams",
    }
    matches: set[str] = set()
    for detection in detections:
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        haystack = " ".join(str(value).lower() for value in evidence.values() if isinstance(value, (str, int, float)))
        for term in terms:
            if term in haystack:
                matches.add(term)
    return sorted(matches)


def _has_reputation_or_signature_context(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        if evidence.get("signature_id") or evidence.get("signature") or evidence.get("reputation") or evidence.get("threat_intel_confidence"):
            return True
    return False


def _has_marker_supply_chain(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        if detection.get("detector_id") != "pondsec.supply_chain_callback":
            continue
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        if evidence.get("signature_required") is False:
            continue
        if evidence.get("signature") or evidence.get("signature_id") or evidence.get("suricata_category"):
            return True
    return False


def _has_high_confidence_signature(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        if detection.get("category") != "signature":
            continue
        if detection.get("detector_id") == "pondsec.suricata_drop":
            return True
        if int(detection.get("severity") or 0) >= 8 and float(detection.get("confidence") or 0) >= 0.9:
            return True
    return False


def _has_high_confidence_ml(detections: list[dict[str, Any]]) -> bool:
    for detection in detections:
        if detection.get("detector_id") != "pondsec.pretrained_ids_model":
            continue
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        if float(evidence.get("attack_probability") or 0) >= 0.9 and float(detection.get("confidence") or 0) >= 0.9:
            return True
    return False


def _has_actionable_reconnaissance(detections: list[dict[str, Any]], roles: dict[str, Any]) -> bool:
    for detection in detections:
        if detection.get("category") != "reconnaissance":
            continue
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        detector_id = str(detection.get("detector_id") or "")
        if detector_id == "pondsec.portscan":
            unique_ports = int(evidence.get("unique_ports") or 0)
            failed = int(evidence.get("failed_connections") or 0)
            if unique_ports >= 12 and failed >= 8:
                return True
        if detector_id == "pondsec.horizontal_scan":
            port = _safe_int(evidence.get("port"))
            destinations = int(evidence.get("destination_count") or 0)
            source = _text_or_none(detection.get("source_ip"))
            destination = _text_or_none(detection.get("destination_ip"))
            if port in WEB_FANOUT_PORTS and source and _is_internal_address(source):
                continue
            if port not in WEB_FANOUT_PORTS and destinations >= 20:
                return True
            if destination and not str(destination).startswith("port:") and _is_internal_address(destination):
                return True
        if detector_id == "pondsec.vertical_scan":
            unique_ports = int(evidence.get("unique_ports") or 0)
            source = _text_or_none(detection.get("source_ip"))
            destination = _text_or_none(detection.get("destination_ip"))
            if unique_ports >= 20 and destination and _is_internal_address(destination):
                if not source or not _is_internal_address(source):
                    return True
        external_actor = roles.get("external_actor")
        victim = roles.get("victim")
        if external_actor and victim and int(detection.get("severity") or 0) >= 8:
            return True
    return False


def _new_case(detection: dict[str, Any]) -> dict[str, Any]:
    case = {
        "detections": [detection],
        "first_seen": _detection_time(detection),
        "last_seen": _detection_time(detection),
        "source_ips": set(),
        "destination_ips": set(),
        "pairs": set(),
        "internal_hosts": set(),
        "external_sources": set(),
    }
    _update_case_indexes(case, detection)
    return case


def _update_case_indexes(case: dict[str, Any], detection: dict[str, Any]) -> None:
    src = _text_or_none(detection.get("source_ip"))
    dst = _text_or_none(detection.get("destination_ip"))
    if src:
        case["source_ips"].add(src)
        if _is_internal_address(src):
            case["internal_hosts"].add(src)
        else:
            case["external_sources"].add(src)
    if dst:
        case["destination_ips"].add(dst)
        if _is_internal_address(dst):
            case["internal_hosts"].add(dst)
    if src and dst:
        case["pairs"].add((src, dst))


def _find_related_case(cases: list[dict[str, Any]], detection: dict[str, Any], window_seconds: int) -> dict[str, Any] | None:
    for case in reversed(cases):
        if not _within_window(case, detection, window_seconds):
            continue
        if _is_related(case, detection):
            return case
    return None


def _within_window(case: dict[str, Any], detection: dict[str, Any], window_seconds: int) -> bool:
    timestamp = _detection_time(detection)
    return abs((timestamp - case["last_seen"]).total_seconds()) <= window_seconds


def _is_related(case: dict[str, Any], detection: dict[str, Any]) -> bool:
    src = _text_or_none(detection.get("source_ip"))
    dst = _text_or_none(detection.get("destination_ip"))
    if src and src in case["source_ips"]:
        return True
    if src and src in case["internal_hosts"]:
        return True
    if dst and dst in case["source_ips"]:
        return True
    if src and dst and (src, dst) in case["pairs"]:
        return True
    if src and dst and src in case["external_sources"] and dst in case["internal_hosts"]:
        return True
    return False


def _entity_roles(detections: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(detections, key=_detection_sort_key)
    sources = [_text_or_none(item.get("source_ip")) for item in ordered]
    destinations = [_text_or_none(item.get("destination_ip")) for item in ordered]
    inbound = [
        item for item in ordered
        if _text_or_none(item.get("source_ip"))
        and _text_or_none(item.get("destination_ip"))
        and not _is_internal_address(str(item.get("source_ip")))
        and _is_internal_address(str(item.get("destination_ip")))
    ]
    external_actor = _text_or_none(inbound[0].get("source_ip")) if inbound else next((src for src in sources if src and not _is_internal_address(src)), None)
    victim = _text_or_none(inbound[0].get("destination_ip")) if inbound else next((dst for dst in destinations if dst and _is_internal_address(dst)), None)
    affected_host = victim or next((src for src in sources if src and _is_internal_address(src)), None) or sources[0]

    pivot_host = None
    if victim:
        for item in ordered:
            src = _text_or_none(item.get("source_ip"))
            dst = _text_or_none(item.get("destination_ip"))
            if src == victim and dst and dst != victim:
                pivot_host = src
                break
            if src and src != victim and _is_internal_address(src):
                pivot_host = src
                break

    destination = _most_common([dst for dst in destinations if dst]) or victim
    response_target = external_actor if external_actor else affected_host
    roles = {
        "external_actor": external_actor,
        "threat_source": external_actor or sources[0],
        "affected_host": affected_host,
        "victim": victim,
        "pivot_host": pivot_host,
        "destination": destination,
        "response_target": response_target,
    }
    return {key: value for key, value in roles.items() if value}


def _attack_sequence(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sequence = []
    for detection in sorted(detections, key=_detection_sort_key):
        sequence.append({
            "timestamp": detection.get("timestamp"),
            "detection_id": detection.get("detection_id"),
            "detector_id": detection.get("detector_id"),
            "category": detection.get("category"),
            "stage": _stage_for_category(str(detection.get("category") or "")),
            "source_ip": detection.get("source_ip"),
            "destination_ip": detection.get("destination_ip"),
        })
    return sequence


def _affected_targets(detections: list[dict[str, Any]], roles: dict[str, Any]) -> list[str]:
    targets = []
    for key in ("victim", "affected_host", "destination", "pivot_host"):
        value = roles.get(key)
        if value and value not in targets:
            targets.append(str(value))
    for detection in detections:
        value = detection.get("destination_ip")
        if value and str(value) not in targets:
            targets.append(str(value))
    return targets


def _title(category: str, source_ip: str | None, roles: dict[str, Any], count: int, categories: list[str]) -> str:
    if category == "multi_stage":
        source = roles.get("external_actor") or source_ip or "unknown source"
        target = roles.get("victim") or roles.get("affected_host") or roles.get("destination") or "unknown target"
        return f"Multi-stage activity from {source} to {target} ({count} detections)"
    label = category.replace("_", " ").title()
    if source_ip:
        return f"{label} from {source_ip} ({count} detection{'s' if count != 1 else ''})"
    return f"{label} ({count} detection{'s' if count != 1 else ''})"


def _common_destination(detections: list[dict[str, Any]]) -> str | None:
    values = {item.get("destination_ip") for item in detections if item.get("destination_ip")}
    if len(values) == 1:
        return next(iter(values))
    return None


def _most_common(values: list[Any]) -> str | None:
    filtered = [str(value) for value in values if value]
    if not filtered:
        return None
    return Counter(filtered).most_common(1)[0][0]


def _evidence_event_count(detection: dict[str, Any]) -> int:
    evidence = detection.get("evidence", {})
    if not isinstance(evidence, dict):
        return 1
    for key in ("event_count", "connections", "destination_count", "unique_destinations", "unique_ports", "failed_connections"):
        value = evidence.get(key)
        if isinstance(value, int) and value > 0:
            return value
    return 1


def _stage_for_category(category: str) -> str:
    return {
        "reconnaissance": "reconnaissance",
        "signature": "reconnaissance",
        "credential_abuse": "initial_access",
        "exploit_attempt": "initial_access",
        "supply_chain": "initial_access",
        "malware": "execution",
        "machine_learning": "execution",
        "anomaly": "execution",
        "lateral_movement": "lateral_movement",
        "command_and_control": "command_and_control",
        "exfiltration": "exfiltration",
    }.get(category, "execution")


def _detection_sort_key(detection: dict[str, Any]) -> str:
    return str(detection.get("timestamp") or "")


def _detection_time(detection: dict[str, Any]) -> datetime:
    value = detection.get("timestamp")
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _text_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_internal_address(value: str | None) -> bool:
    if not value or "/" in str(value) or str(value).startswith("port:"):
        return False
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in INTERNAL_NETWORKS) or address.is_loopback
