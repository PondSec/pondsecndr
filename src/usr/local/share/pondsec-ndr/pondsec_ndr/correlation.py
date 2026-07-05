"""Detection correlation into incidents."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pondsec_ndr.risk import score_detection_group, severity_from_risk


def correlate_detections(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str | None, str], list[dict[str, Any]]] = defaultdict(list)
    for detection in detections:
        grouped[(detection.get("source_ip"), detection.get("category"))].append(detection)

    incidents: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()
    for (source_ip, category), items in grouped.items():
        risk_score, factors = score_detection_group(items)
        if risk_score < 35:
            continue
        title = _title(category, source_ip, len(items))
        basis = f"{source_ip}:{category}:{','.join(sorted(item['detection_id'] for item in items))}"
        incidents.append({
            "incident_id": str(uuid5(NAMESPACE_URL, basis)),
            "title": title,
            "status": "open",
            "risk_score": risk_score,
            "severity": severity_from_risk(risk_score),
            "confidence": round(max(float(item["confidence"]) for item in items), 4),
            "source_ip": source_ip,
            "destination_ip": _common_destination(items),
            "category": category,
            "created_at": now,
            "updated_at": now,
            "evidence": {"detections": items},
            "risk_factors": factors,
            "detection_ids": [item["detection_id"] for item in items],
        })
    return incidents


def _title(category: str, source_ip: str | None, count: int) -> str:
    label = category.replace("_", " ").title()
    if source_ip:
        return f"{label} from {source_ip} ({count} detection{'s' if count != 1 else ''})"
    return f"{label} ({count} detection{'s' if count != 1 else ''})"


def _common_destination(detections: list[dict[str, Any]]) -> str | None:
    values = {item.get("destination_ip") for item in detections if item.get("destination_ip")}
    if len(values) == 1:
        return next(iter(values))
    return None
