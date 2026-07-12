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
    event_factor = min(10, len(detections) * 2)
    factors = [
        {"name": "severity", "value": max_severity * 4},
        {"name": "confidence", "value": int(avg_confidence * 18)},
        {"name": "anomaly_score", "value": int(max_anomaly * 10)},
        {"name": "number_of_detectors", "value": min(12, detector_count * 4)},
        {"name": "number_of_events", "value": event_factor},
    ]
    hard_evidence = _has_hard_evidence(detections)
    if any(item["category"] == "lateral_movement" for item in detections):
        factors.append({"name": "lateral_movement", "value": 10})
    if any(item["category"] == "signature" for item in detections):
        factors.append({"name": "signature_context", "value": 14})
    if any(_provider_prevented(item) for item in detections):
        factors.append({"name": "provider_prevented", "value": 12})
    if any(_sandbox_malicious(item) for item in detections):
        factors.append({"name": "sandbox_malicious", "value": 18})
    if any(_threat_intel_match(item) for item in detections):
        factors.append({"name": "threat_intel_match", "value": 15})
    if any(_explicit_exploit_or_malware(item) for item in detections):
        factors.append({"name": "exploit_or_malware_context", "value": 12})
    if any(item["category"] == "exfiltration" and _has_exfiltration_volume(item) for item in detections):
        factors.append({"name": "verified_external_data_volume", "value": 10})

    score = sum(item["value"] for item in factors)
    caps: list[dict[str, Any]] = []
    if any(_metadata_limited_dns(item) for item in detections) and not hard_evidence:
        caps.append({"name": "metadata_limited_dns_cap", "value": 60})
        factors.append({"name": "metadata_limited_dns", "value": -18})
    if any(_heuristic_only(item) for item in detections) and not hard_evidence:
        caps.append({"name": "heuristic_only_cap", "value": 65})
        factors.append({"name": "heuristic_only", "value": -10})
    if detector_count == 1 and not hard_evidence:
        caps.append({"name": "single_detector_without_hard_evidence_cap", "value": 68})
        factors.append({"name": "single_detector_without_hard_evidence", "value": -8})
    if not hard_evidence and not _has_confirmed_target(detections):
        caps.append({"name": "unconfirmed_target_cap", "value": 72})
    score = sum(item["value"] for item in factors)
    if caps:
        score = min(score, min(int(item["value"]) for item in caps))
        factors.extend(caps)
    score = max(1, min(100, score))
    return score, factors


def severity_from_risk(risk_score: int) -> int:
    if risk_score >= 90:
        return 10
    if risk_score >= 75:
        return 8
    if risk_score >= 50:
        return 6
    return 4


def _evidence(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _has_hard_evidence(detections: list[dict[str, Any]]) -> bool:
    return any(
        item.get("category") == "signature"
        or str(item.get("detector_id") or "") in {
            "pondsec.suricata_alert",
            "pondsec.suricata_drop",
            "pondsec.exploit_attempt",
            "pondsec.exploit_blocked",
            "pondsec.file_sandbox_verdict",
            "pondsec.email_threat",
            "pondsec.threat_intel_indicator",
            "pondsec.dns_sinkhole_hit",
        }
        or _provider_prevented(item)
        or _sandbox_malicious(item)
        or _threat_intel_match(item)
        for item in detections
    )


def _provider_prevented(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    return bool(evidence.get("provider_prevented") or str(evidence.get("suricata_action") or "").lower() in {"blocked", "drop", "dropped"})


def _sandbox_malicious(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    verdict = str(evidence.get("sandbox_verdict") or evidence.get("file_verdict") or evidence.get("av_verdict") or "").lower()
    return verdict in {"malicious", "malware", "infected", "blocked", "quarantine", "quarantined", "denied", "high"}


def _threat_intel_match(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    reputation = str(evidence.get("reputation") or "").lower()
    return bool(
        evidence.get("threat_intel_confidence")
        or evidence.get("threat_intel_source")
        or evidence.get("ioc_type")
        or reputation in {"malicious", "known_bad", "bad", "high", "block", "blocked"}
    )


def _explicit_exploit_or_malware(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    return bool(
        evidence.get("signature_id")
        or evidence.get("signature")
        or evidence.get("threat_name")
        or evidence.get("security_category")
    ) and str(item.get("category") or "") in {"exploit_attempt", "malware", "command_and_control"}


def _has_exfiltration_volume(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    return (
        int(evidence.get("external_non_dns_bytes_out") or 0) >= 50_000_000
        and int(evidence.get("external_destination_count") or 0) >= 1
        and float(evidence.get("upload_download_ratio") or 0) >= 8
    )


def _metadata_limited_dns(item: dict[str, Any]) -> bool:
    return str(item.get("detector_id") or "") == "pondsec.dns_tunneling" and bool(_evidence(item).get("metadata_limited"))


def _heuristic_only(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    return bool(evidence.get("signature_required") is False or evidence.get("explicit_auth_evidence") is False)


def _has_confirmed_target(detections: list[dict[str, Any]]) -> bool:
    for item in detections:
        destination = item.get("destination_ip")
        if destination and str(destination) not in {"dns_resolver", "auth_services", "internal", "external"} and not str(destination).startswith("port:"):
            return True
    return False
