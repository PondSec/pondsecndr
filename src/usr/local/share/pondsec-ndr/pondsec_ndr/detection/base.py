"""Detector primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from pondsec_ndr.schema import FEATURE_SCHEMA_VERSION


def _notable_features(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    features = []
    ignored = {"thresholds", "validation", "explainability", "feature_values"}
    for key, value in evidence.items():
        if key in ignored:
            continue
        if isinstance(value, (int, float, str, bool)) or value:
            features.append({"name": key, "value": value})
    return features[:12]


def _default_admin_guidance(category: str, recommended_action: str) -> list[str]:
    guidance = {
        "reconnaissance": [
            "Confirm whether the source is an approved scanner or administrator workstation.",
            "Review firewall and Suricata logs for failed connection bursts from the same source.",
            "Check whether the destination services should be reachable from this network segment.",
        ],
        "command_and_control": [
            "Inspect DNS and TLS metadata for repeated or high-entropy destinations.",
            "Check endpoint telemetry on the source host for unknown processes or scheduled tasks.",
            "Block or isolate the source if the destination is not business-approved.",
        ],
        "lateral_movement": [
            "Validate whether administrative protocols were expected for this source host.",
            "Review authentication logs on contacted internal hosts.",
            "Check segmentation rules between the involved VLANs.",
        ],
        "credential_abuse": [
            "Review authentication logs for failed logons, lockouts, or password spraying from this source.",
            "Confirm whether the target service should accept connections from this network segment.",
            "Temporarily rate-limit or block the source if the activity is not an approved test.",
        ],
        "exploit_attempt": [
            "Open the referenced signature or marker and verify the attempted service, CVE, and target exposure.",
            "Patch or shield the targeted service if the traffic reached a vulnerable application path.",
            "Treat this as attempted exploitation; do not assume successful compromise without host evidence.",
        ],
        "supply_chain": [
            "Check whether the source host recently ran package, update, CI/CD, or installer activity.",
            "Review DNS, TLS, proxy, and endpoint telemetry for unexpected callback destinations.",
            "Quarantine only after corroborating the callback with endpoint or policy evidence.",
        ],
        "exfiltration": [
            "Identify the destination and confirm whether large outbound transfer is expected.",
            "Review proxy, DNS, TLS, and application logs for the same transfer window.",
            "Consider temporary isolation while validating data sensitivity.",
        ],
        "machine_learning": [
            "Review the model score together with deterministic detections for the same host.",
            "Inspect the feature values that drove the pretrained model decision.",
            "Treat this as supporting evidence until correlated with real traffic context.",
        ],
        "anomaly": [
            "Compare the host's current behavior with its normal role and recent changes.",
            "Look for new destinations, new ports, or volume changes that explain the deviation.",
            "Avoid automatic isolation unless this correlates with stronger attack evidence.",
        ],
        "signature": [
            "Open the referenced Suricata alert and verify source, destination, signature, and action.",
            "Check whether the traffic was dropped upstream or still reached the target.",
            "Update or suppress the signature only after validating false-positive context.",
        ],
    }.get(category, ["Review the source host, destination, and surrounding traffic window."])
    if recommended_action == "block":
        return guidance + ["If confirmed malicious, apply the matching PondSec response policy."]
    return guidance


def _build_explainability(
    category: str,
    description: str,
    evidence: dict[str, Any],
    recommended_action: str,
) -> dict[str, Any]:
    thresholds = evidence.get("thresholds")
    if not isinstance(thresholds, list):
        thresholds = [
            {"feature": item["name"], "observed": item["value"], "threshold": "detector-defined"}
            for item in _notable_features(evidence)
            if isinstance(item["value"], (int, float))
        ]
    return {
        "why": description,
        "combined_events": evidence.get("combined_events", "aggregated Suricata/flow feature window"),
        "thresholds_exceeded": thresholds,
        "notable_features": _notable_features(evidence),
        "policy_response": {
            "recommended_action": recommended_action,
            "category": category,
            "automatic_response_eligible": recommended_action == "block",
        },
        "administrator_guidance": _default_admin_guidance(category, recommended_action),
    }


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
    evidence = dict(evidence)
    explainability = _build_explainability(category, description, evidence, recommended_action)
    evidence.setdefault("explainability", explainability)
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
        "explainability": explainability,
        "recommended_action": recommended_action,
        "model_version": model_version,
        "feature_version": FEATURE_SCHEMA_VERSION,
    }


class Detector:
    detector_id = "pondsec.detector"
    enabled = True

    def detect(self, events: list[dict[str, Any]], features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        raise NotImplementedError
