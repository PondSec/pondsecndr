"""Detector primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pondsec_ndr.schema import FEATURE_SCHEMA_VERSION


def make_detection(
    detector_id: str,
    category: str,
    title: str,
    description: str,
    source_ip: str | None,
    destination_ip: str | None,
    severity: int,
    confidence: float,
    anomaly_score: float,
    evidence: dict[str, Any],
    recommended_action: str = "investigate",
    model_version: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    basis = f"{detector_id}:{source_ip}:{destination_ip}:{title}:{sorted(evidence.items(), key=lambda item: item[0])}"
    detection_id = str(uuid5(NAMESPACE_URL, basis))
    return {
        "detection_id": detection_id,
        "detector_id": detector_id,
        "detector_version": "1.0.0",
        "category": category,
        "title": title,
        "description": description,
        "timestamp": now,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "severity": int(max(1, min(10, severity))),
        "confidence": round(max(0.0, min(1.0, confidence)), 4),
        "anomaly_score": round(max(0.0, min(1.0, anomaly_score)), 4),
        "evidence": evidence,
        "recommended_action": recommended_action,
        "model_version": model_version,
        "feature_version": FEATURE_SCHEMA_VERSION,
    }


class Detector:
    detector_id = "pondsec.detector"
    enabled = True

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise NotImplementedError
