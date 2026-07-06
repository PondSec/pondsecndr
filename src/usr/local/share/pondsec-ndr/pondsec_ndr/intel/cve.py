"""Local CVE/KEV/EPSS enrichment for cases.

The service never needs an internet connection to enrich a case. Administrators
can refresh the cache out-of-band; case analysis reads only local cache files.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

SOURCE_URLS = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "first_epss": "https://api.first.org/data/v1/epss",
    "mitre_attack": "https://attack.mitre.org/",
    "suricata_local_metadata": "local Suricata rule metadata",
}

EVIDENCE_RANK = {
    "referenced": 1,
    "possible": 2,
    "product_matched": 3,
    "version_matched": 4,
    "exploitation_attempt_observed": 5,
    "exploitation_success_unconfirmed": 6,
}


@dataclass(slots=True)
class CveEnrichmentOptions:
    cache_ttl_hours: int = 24
    external_lookup: bool = False


def enrich_case_cves(
    detections: list[dict[str, Any]],
    data_dir: Path,
    options: CveEnrichmentOptions | None = None,
) -> dict[str, Any]:
    options = options or CveEnrichmentOptions()
    intel_dir = Path(data_dir) / "intel"
    nvd = _load_nvd_cache(intel_dir)
    kev = _load_kev_cache(intel_dir)
    epss = _load_epss_cache(intel_dir)
    suricata_rules = _load_json(intel_dir / "suricata_rule_metadata.json")
    cache_status = _cache_status(intel_dir, options.cache_ttl_hours)
    candidates = _extract_candidates(detections, suricata_rules)
    cves = []
    total_risk_modifier = 0
    for cve_id, evidence in sorted(candidates.items()):
        nvd_record = nvd.get(cve_id, {})
        kev_record = kev.get(cve_id)
        epss_record = epss.get(cve_id, {})
        level = _evidence_level(evidence)
        cvss = _cvss_score(nvd_record)
        epss_score = _float_or_none(epss_record.get("epss"))
        epss_percentile = _float_or_none(epss_record.get("percentile"))
        risk_modifier = _risk_modifier(bool(kev_record), epss_score)
        total_risk_modifier += risk_modifier
        cves.append({
            "cve_id": cve_id,
            "short_description": _description(nvd_record) or _description_from_evidence(evidence),
            "cvss": cvss,
            "epss": epss_score,
            "epss_percentile": epss_percentile,
            "cisa_kev": bool(kev_record),
            "kev": kev_record or {},
            "affected_products": _affected_products(nvd_record, kev_record),
            "evidence_level": level,
            "match_confidence": _match_confidence(level, bool(kev_record), epss_score),
            "local_evidence": evidence[:8],
            "data_sources": _sources_for_record(nvd_record, kev_record, epss_record, evidence),
            "fetched_at": _fetched_at(nvd_record, kev_record, epss_record),
            "vendor_recommendation": _vendor_recommendation(kev_record, nvd_record),
            "claim_limit": (
                "CVE context prioritizes investigation. It does not confirm a vulnerable product, "
                "affected version, exploitation success, or justify automatic blocking by itself."
            ),
            "automatic_block_basis_allowed": False,
        })
    return {
        "enabled": True,
        "external_lookup": options.external_lookup,
        "offline_operable": True,
        "sources": SOURCE_URLS,
        "cache": cache_status,
        "cves": cves,
        "risk_modifier": min(25, total_risk_modifier),
        "matching_policy": {
            "no_source_ip_only_matching": True,
            "requires_local_evidence": True,
            "success_never_assumed": True,
            "evidence_levels": list(EVIDENCE_RANK),
        },
    }


def extract_cve_ids(value: Any) -> list[str]:
    matches = set()
    _walk_text(value, matches)
    return sorted(matches)


def _extract_candidates(detections: list[dict[str, Any]], suricata_rules: Any) -> dict[str, list[dict[str, Any]]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    rule_index = suricata_rules if isinstance(suricata_rules, dict) else {}
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        evidence = detection.get("evidence") if isinstance(detection.get("evidence"), dict) else {}
        signature_id = str(evidence.get("signature_id") or evidence.get("sid") or "")
        rule_meta = rule_index.get(signature_id, {}) if signature_id else {}
        cve_ids = set(extract_cve_ids({
            "title": detection.get("title"),
            "description": detection.get("description"),
            "evidence": evidence,
            "suricata_rule_metadata": rule_meta,
        }))
        for cve_id in cve_ids:
            local = {
                "detection_id": detection.get("detection_id"),
                "detector_id": detection.get("detector_id"),
                "category": detection.get("category"),
                "timestamp": detection.get("timestamp"),
                "source_ip": detection.get("source_ip"),
                "destination_ip": detection.get("destination_ip"),
                "protocol": evidence.get("protocol"),
                "ports": evidence.get("ports") or evidence.get("destination_ports") or evidence.get("port"),
                "signature_id": signature_id or None,
                "product": evidence.get("product") or rule_meta.get("product"),
                "cpe": evidence.get("cpe") or rule_meta.get("cpe"),
                "version": evidence.get("version") or rule_meta.get("version"),
                "mitre_attack": evidence.get("mitre_attack") or rule_meta.get("mitre_attack") or rule_meta.get("attack"),
                "suricata_reference": True if signature_id or rule_meta else False,
                "exploit_success": bool(evidence.get("exploit_success") or evidence.get("compromise_confirmed")),
                "suricata_action": evidence.get("suricata_action") or evidence.get("action"),
            }
            candidates.setdefault(cve_id.upper(), []).append({key: value for key, value in local.items() if value not in (None, "", [])})
    return candidates


def _evidence_level(evidence: list[dict[str, Any]]) -> str:
    level = "referenced"
    for item in evidence:
        if item.get("product") or item.get("cpe"):
            level = _max_level(level, "product_matched")
        if item.get("version"):
            level = _max_level(level, "version_matched")
        if item.get("category") == "signature" or item.get("suricata_reference"):
            level = _max_level(level, "exploitation_attempt_observed")
        if item.get("exploit_success"):
            level = _max_level(level, "exploitation_success_unconfirmed")
        if not item.get("suricata_reference") and (item.get("ports") or item.get("protocol")):
            level = _max_level(level, "possible")
    return level


def _max_level(left: str, right: str) -> str:
    return right if EVIDENCE_RANK[right] > EVIDENCE_RANK[left] else left


def _load_nvd_cache(intel_dir: Path) -> dict[str, dict[str, Any]]:
    raw = _load_json(intel_dir / "nvd_cve_cache.json")
    if not raw:
        return {}
    if isinstance(raw, dict) and "vulnerabilities" in raw:
        records: dict[str, dict[str, Any]] = {}
        for item in raw.get("vulnerabilities") or []:
            cve = (item.get("cve") or {}) if isinstance(item, dict) else {}
            cve_id = str(cve.get("id") or "").upper()
            if cve_id:
                records[cve_id] = dict(cve, fetched_at=raw.get("fetched_at"))
        return records
    if isinstance(raw, dict):
        return {str(key).upper(): value for key, value in raw.items() if isinstance(value, dict)}
    return {}


def _load_kev_cache(intel_dir: Path) -> dict[str, dict[str, Any]]:
    raw = _load_json(intel_dir / "cisa_kev.json")
    records: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict):
        for item in raw.get("vulnerabilities") or []:
            if isinstance(item, dict) and item.get("cveID"):
                records[str(item["cveID"]).upper()] = dict(item, fetched_at=raw.get("dateReleased") or raw.get("fetched_at"))
    return records


def _load_epss_cache(intel_dir: Path) -> dict[str, dict[str, Any]]:
    raw = _load_json(intel_dir / "epss_cache.json")
    records: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict) and isinstance(raw.get("data"), list):
        for item in raw["data"]:
            if isinstance(item, dict) and item.get("cve"):
                records[str(item["cve"]).upper()] = dict(item, fetched_at=raw.get("fetched_at") or item.get("date"))
    elif isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict):
                records[str(key).upper()] = value
    return records


def _load_json(path: Path) -> Any:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, PermissionError, json.JSONDecodeError):
        return None


def _cache_status(intel_dir: Path, ttl_hours: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    files = {}
    for name in ("nvd_cve_cache.json", "cisa_kev.json", "epss_cache.json", "suricata_rule_metadata.json"):
        path = intel_dir / name
        try:
            present = path.exists()
        except OSError:
            present = False
        if not present:
            files[name] = {"present": False, "fresh": False}
            continue
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            files[name] = {"present": True, "fresh": False, "error": "not_readable"}
            continue
        age_hours = round((now - modified).total_seconds() / 3600, 2)
        files[name] = {"present": True, "fresh": age_hours <= ttl_hours, "age_hours": age_hours}
    return {"ttl_hours": ttl_hours, "files": files}


def _walk_text(value: Any, matches: set[str]) -> None:
    if isinstance(value, str):
        for match in CVE_RE.findall(value):
            matches.add(match.upper())
    elif isinstance(value, dict):
        for item in value.values():
            _walk_text(item, matches)
    elif isinstance(value, list):
        for item in value:
            _walk_text(item, matches)


def _description(record: dict[str, Any]) -> str | None:
    descriptions = record.get("descriptions") if isinstance(record, dict) else None
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
                return str(item["value"])[:280]
    return None


def _description_from_evidence(evidence: list[dict[str, Any]]) -> str:
    ids = sorted({str(item.get("signature_id")) for item in evidence if item.get("signature_id")})
    if ids:
        return f"CVE referenced by local Suricata rule metadata/signature id {', '.join(ids[:3])}."
    return "CVE referenced by local detection evidence."


def _cvss_score(record: dict[str, Any]) -> float | None:
    metrics = record.get("metrics") if isinstance(record, dict) else {}
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values:
            data = values[0].get("cvssData", {}) if isinstance(values[0], dict) else {}
            score = _float_or_none(data.get("baseScore"))
            if score is not None:
                return score
    return None


def _affected_products(nvd_record: dict[str, Any], kev_record: dict[str, Any] | None) -> list[dict[str, Any]]:
    products = []
    if kev_record:
        products.append({
            "vendor": kev_record.get("vendorProject"),
            "product": kev_record.get("product"),
            "versions": "See vendor advisory",
            "source": "cisa_kev",
        })
    configurations = nvd_record.get("configurations") if isinstance(nvd_record, dict) else []
    for configuration in configurations or []:
        for node in configuration.get("nodes", []) if isinstance(configuration, dict) else []:
            for match in node.get("cpeMatch", []) if isinstance(node, dict) else []:
                criteria = match.get("criteria") if isinstance(match, dict) else None
                if criteria:
                    products.append({"cpe": criteria, "source": "nvd"})
                    if len(products) >= 8:
                        return products
    return products


def _sources_for_record(nvd_record: dict[str, Any], kev_record: dict[str, Any] | None, epss_record: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources = []
    if nvd_record:
        sources.append({"name": "NVD CVE API 2.0", "url": SOURCE_URLS["nvd"]})
    if kev_record:
        sources.append({"name": "CISA Known Exploited Vulnerabilities JSON", "url": SOURCE_URLS["cisa_kev"]})
    if epss_record:
        sources.append({"name": "FIRST EPSS API", "url": SOURCE_URLS["first_epss"]})
    if any(item.get("mitre_attack") for item in evidence):
        sources.append({"name": "MITRE ATT&CK tactic/technique mapping", "url": SOURCE_URLS["mitre_attack"]})
    sources.append({"name": "Local Suricata rule metadata", "url": SOURCE_URLS["suricata_local_metadata"]})
    return sources


def _fetched_at(*records: dict[str, Any] | None) -> str | None:
    values = [str(record.get("fetched_at")) for record in records if isinstance(record, dict) and record.get("fetched_at")]
    return max(values) if values else None


def _vendor_recommendation(kev_record: dict[str, Any] | None, nvd_record: dict[str, Any]) -> str:
    if kev_record and kev_record.get("requiredAction"):
        return str(kev_record["requiredAction"])
    references = nvd_record.get("references", {}) if isinstance(nvd_record, dict) else {}
    data = references.get("referenceData") if isinstance(references, dict) else []
    if isinstance(data, list) and data:
        return f"Review vendor advisory/reference: {data[0].get('url')}"
    return "Review the vendor advisory, confirm product/version exposure, then patch, mitigate, or disable the affected service."


def _risk_modifier(is_kev: bool, epss_score: float | None) -> int:
    modifier = 0
    if is_kev:
        modifier += 10
    if epss_score is not None:
        if epss_score >= 0.9:
            modifier += 8
        elif epss_score >= 0.5:
            modifier += 4
    return modifier


def _match_confidence(level: str, is_kev: bool, epss_score: float | None) -> float:
    base = {
        "referenced": 0.35,
        "possible": 0.45,
        "product_matched": 0.65,
        "version_matched": 0.8,
        "exploitation_attempt_observed": 0.85,
        "exploitation_success_unconfirmed": 0.9,
    }.get(level, 0.3)
    if is_kev:
        base += 0.04
    if epss_score is not None and epss_score >= 0.9:
        base += 0.03
    return round(min(base, 0.95), 2)


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
