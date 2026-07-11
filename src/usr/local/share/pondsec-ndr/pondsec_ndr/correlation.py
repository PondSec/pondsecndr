"""Detection correlation into incident cases."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pondsec_ndr.risk import score_detection_group, severity_from_risk


DEFAULT_CORRELATION_WINDOW_SECONDS = 1800
INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


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
            continue
        roles = _entity_roles(items)
        categories = sorted({str(item.get("category") or "unknown") for item in items})
        category = "multi_stage" if len(categories) > 1 else categories[0]
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
                    "certainty_note": "This case links related detections; it does not confirm successful compromise without explicit success evidence.",
                },
            },
            "risk_factors": factors,
            "detection_ids": detection_ids,
        }
        incidents.append(incident)
    return incidents


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


def _is_internal_address(value: str | None) -> bool:
    if not value or "/" in str(value) or str(value).startswith("port:"):
        return False
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in INTERNAL_NETWORKS) or address.is_loopback
