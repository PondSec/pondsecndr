"""Explainable risk scoring."""

from __future__ import annotations

from typing import Any


def score_detection_group(detections: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
    if not detections:
        return 0, []
    max_severity = max(int(item["severity"]) for item in detections)
    avg_confidence = sum(float(item["confidence"]) for item in detections) / len(detections)
    max_anomaly = max(float(item.get("anomaly_score") or 0) for item in detections)
    detector_count = len({item["detector_id"] for item in detections})
    event_factor = min(15, len(detections) * 3)
    factors = [
        {"name": "severity", "value": max_severity * 5},
        {"name": "confidence", "value": int(avg_confidence * 20)},
        {"name": "anomaly_score", "value": int(max_anomaly * 15)},
        {"name": "number_of_detectors", "value": min(15, detector_count * 5)},
        {"name": "number_of_events", "value": event_factor},
    ]
    if any(item["category"] == "lateral_movement" for item in detections):
        factors.append({"name": "lateral_movement", "value": 15})
    if any(item["category"] == "signature" for item in detections):
        factors.append({"name": "suricata_alert", "value": 12})
    if any(item["category"] == "exfiltration" for item in detections):
        factors.append({"name": "data_volume", "value": 15})
    score = max(1, min(100, sum(item["value"] for item in factors)))
    return score, factors


def severity_from_risk(risk_score: int) -> int:
    if risk_score >= 90:
        return 10
    if risk_score >= 75:
        return 8
    if risk_score >= 50:
        return 6
    return 4
