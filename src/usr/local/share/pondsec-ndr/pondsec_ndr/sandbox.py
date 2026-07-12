"""File verdict and sandbox-result enrichment.

The sandbox pipeline consumes file metadata and external verdict result files. It
does not execute submitted artifacts and it does not copy packet payloads from
network telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from pondsec_ndr.config import SandboxConfig


EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
SCRIPT_EXTENSIONS = (".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".scr", ".lnk", ".iso", ".img")
ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z")


@dataclass(slots=True)
class SandboxStats:
    processed_file_events: int = 0
    matched_results: int = 0
    local_static_verdicts: int = 0
    pending_requests: int = 0
    timed_out_requests: int = 0
    stale_results_ignored: int = 0
    errors: int = 0
    last_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    value: str
    kind: str
    verdict: str
    confidence: float
    status: str
    source: str
    submitted_at: str | None = None
    completed_at: str | None = None
    expires_at: str | None = None
    analysis_id: str | None = None
    findings: tuple[str, ...] = ()


def enrich_events_with_sandbox(
    events: list[dict[str, Any]],
    data_dir: Path,
    config: SandboxConfig,
) -> tuple[list[dict[str, Any]], SandboxStats]:
    stats = SandboxStats()
    if not config.enabled:
        return events, stats

    results_dir = Path(config.results_dir) if config.results_dir else Path(data_dir) / "sandbox" / "results"
    pending_dir = Path(config.pending_dir) if config.pending_dir else Path(data_dir) / "sandbox" / "pending"
    results = load_sandbox_results(results_dir, config.result_ttl_hours, stats)
    now = datetime.now(timezone.utc)
    enriched: list[dict[str, Any]] = []
    pending_written = 0

    for event in events:
        artifact = file_artifact(event)
        if artifact is None:
            enriched.append(event)
            continue
        stats.processed_file_events += 1
        metadata = dict(event.get("metadata") if isinstance(event.get("metadata"), dict) else {})
        result = _match_result(artifact, results)
        if result is not None:
            metadata.update(_result_metadata(result))
            stats.matched_results += 1
        elif config.mode == "local_static":
            local = _local_static_result(artifact)
            if local is not None:
                metadata.update(_result_metadata(local))
                stats.local_static_verdicts += 1
            else:
                pending_written += _mark_pending(metadata, artifact, pending_dir, config, now, stats, pending_written)
        else:
            pending_written += _mark_pending(metadata, artifact, pending_dir, config, now, stats, pending_written)
        updated = dict(event)
        updated["metadata"] = metadata
        enriched.append(updated)
    return enriched, stats


def load_sandbox_results(results_dir: Path, ttl_hours: int, stats: SandboxStats | None = None) -> dict[tuple[str, str], SandboxResult]:
    stats = stats or SandboxStats()
    index: dict[tuple[str, str], SandboxResult] = {}
    if not results_dir.exists():
        return index
    now = datetime.now(timezone.utc)
    for path in sorted(results_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            stats.errors += 1
            stats.last_error = f"sandbox result read failed for {path.name}: {exc}"
            continue
        for item in _result_rows(raw):
            result = _result_from_mapping(item, path.name)
            if result is None:
                continue
            if _result_expired(result, ttl_hours, now):
                stats.stale_results_ignored += 1
                continue
            index[(result.kind, result.value)] = result
    return index


def file_artifact(event: Mapping[str, Any]) -> dict[str, Any] | None:
    metadata = event.get("metadata") if isinstance(event.get("metadata"), Mapping) else {}
    hashes = {
        "sha256": _clean_hash(metadata.get("sha256"), 64),
        "sha1": _clean_hash(metadata.get("sha1"), 40),
        "md5": _clean_hash(metadata.get("md5"), 32),
    }
    filename = str(metadata.get("filename") or metadata.get("file_name") or "").strip()
    has_file_context = event.get("event_type") == "fileinfo" or bool(filename or any(hashes.values()))
    if not has_file_context:
        return None
    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "provider_id": metadata.get("event_source") or event.get("raw_source") or "unknown",
        "filename": filename,
        "mime_type": metadata.get("mime_type"),
        "file_size": metadata.get("file_size") or metadata.get("seen_bytes") or metadata.get("total_bytes") or metadata.get("size"),
        "hashes": {key: value for key, value in hashes.items() if value},
    }


def _result_rows(raw: Any) -> list[Mapping[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, Mapping)]
    if not isinstance(raw, Mapping):
        return []
    rows: list[Mapping[str, Any]] = []
    for key in ("results", "items", "verdicts", "artifacts"):
        value = raw.get(key)
        if isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, Mapping))
    if not rows:
        rows.append(raw)
    keyed = raw.get("hashes")
    if isinstance(keyed, Mapping):
        for value, verdict in keyed.items():
            if isinstance(verdict, Mapping):
                item = dict(verdict)
                item.setdefault("value", value)
                rows.append(item)
            else:
                rows.append({"value": value, "verdict": verdict})
    return rows


def _result_from_mapping(item: Mapping[str, Any], source: str) -> SandboxResult | None:
    kind, value = _hash_from_mapping(item)
    if not value:
        return None
    verdict = str(item.get("verdict") or item.get("sandbox_verdict") or item.get("result") or item.get("status") or "unknown").strip().lower()
    status = str(item.get("status") or ("completed" if verdict not in {"pending", "timeout"} else verdict)).strip().lower()
    findings_raw = item.get("findings") or item.get("signatures") or []
    if isinstance(findings_raw, str):
        findings = tuple(part.strip() for part in findings_raw.split(",") if part.strip())
    elif isinstance(findings_raw, list):
        findings = tuple(str(part).strip() for part in findings_raw if str(part).strip())
    else:
        findings = ()
    return SandboxResult(
        value=value,
        kind=kind,
        verdict=verdict,
        confidence=_confidence(item.get("confidence"), 0.9 if verdict in {"malicious", "infected"} else 0.65),
        status=status,
        source=str(item.get("source") or source or "sandbox_result"),
        submitted_at=_iso_or_none(item.get("submitted_at")),
        completed_at=_iso_or_none(item.get("completed_at") or item.get("updated_at") or item.get("analyzed_at")),
        expires_at=_iso_or_none(item.get("expires_at")),
        analysis_id=str(item.get("analysis_id") or item.get("id") or "") or None,
        findings=findings,
    )


def _hash_from_mapping(item: Mapping[str, Any]) -> tuple[str, str | None]:
    for kind, length in (("sha256", 64), ("sha1", 40), ("md5", 32)):
        value = _clean_hash(item.get(kind) or item.get(f"file.{kind}") or item.get(f"hash.{kind}"), length)
        if value:
            return kind, value
    value = _clean_hash(item.get("value") or item.get("hash") or item.get("indicator"), 64)
    if value:
        return "sha256", value
    value = _clean_hash(item.get("value") or item.get("hash") or item.get("indicator"), 40)
    if value:
        return "sha1", value
    value = _clean_hash(item.get("value") or item.get("hash") or item.get("indicator"), 32)
    if value:
        return "md5", value
    return "", None


def _match_result(artifact: Mapping[str, Any], results: Mapping[tuple[str, str], SandboxResult]) -> SandboxResult | None:
    hashes = artifact.get("hashes") if isinstance(artifact.get("hashes"), Mapping) else {}
    for kind in ("sha256", "sha1", "md5"):
        value = hashes.get(kind)
        if value and (kind, str(value)) in results:
            return results[(kind, str(value))]
    return None


def _local_static_result(artifact: Mapping[str, Any]) -> SandboxResult | None:
    hashes = artifact.get("hashes") if isinstance(artifact.get("hashes"), Mapping) else {}
    if hashes.get("sha256") == EICAR_SHA256 or hashes.get("sha1") == EICAR_SHA1 or hashes.get("md5") == EICAR_MD5:
        return SandboxResult(
            value=str(hashes.get("sha256") or hashes.get("sha1") or hashes.get("md5")),
            kind="sha256" if hashes.get("sha256") else "sha1" if hashes.get("sha1") else "md5",
            verdict="malicious",
            confidence=0.99,
            status="completed",
            source="local_static_eicar",
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings=("eicar_safe_test_file",),
        )
    filename = str(artifact.get("filename") or "").lower()
    if filename.endswith(SCRIPT_EXTENSIONS):
        return SandboxResult(
            value=_artifact_key(artifact),
            kind="sha256" if hashes.get("sha256") else "file",
            verdict="suspicious",
            confidence=0.62,
            status="completed",
            source="local_static_file_profile",
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings=("script_or_disk_image_extension",),
        )
    if filename.endswith(ARCHIVE_EXTENSIONS):
        return SandboxResult(
            value=_artifact_key(artifact),
            kind="sha256" if hashes.get("sha256") else "file",
            verdict="unknown",
            confidence=0.3,
            status="completed",
            source="local_static_file_profile",
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings=("archive_observed",),
        )
    return None


def _mark_pending(
    metadata: dict[str, Any],
    artifact: Mapping[str, Any],
    pending_dir: Path,
    config: SandboxConfig,
    now: datetime,
    stats: SandboxStats,
    pending_written: int,
) -> int:
    artifact_key = _artifact_key(artifact)
    if not artifact_key:
        metadata.setdefault("sandbox_status", "metadata_only")
        return 0
    pending_path = pending_dir / f"{artifact_key}.json"
    existing = _read_json(pending_path)
    requested_at = _parse_time(existing.get("requested_at") if isinstance(existing, Mapping) else None)
    if requested_at and now - requested_at > timedelta(seconds=config.request_timeout_seconds):
        metadata.update({
            "sandbox_status": "timeout",
            "sandbox_requested_at": requested_at.isoformat(),
            "sandbox_timeout_seconds": config.request_timeout_seconds,
        })
        stats.timed_out_requests += 1
        return 0
    metadata.setdefault("sandbox_status", "pending")
    metadata.setdefault("sandbox_requested_at", (requested_at or now).isoformat())
    if pending_written >= config.queue_limit or existing:
        return 0
    try:
        pending_dir.mkdir(parents=True, exist_ok=True)
        payload = _pending_payload(artifact, now, config.privacy_mode)
        pending_path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        stats.pending_requests += 1
        return 1
    except OSError as exc:
        stats.errors += 1
        stats.last_error = f"sandbox pending request cannot be written: {exc}"
        return 0


def _pending_payload(artifact: Mapping[str, Any], now: datetime, privacy_mode: bool) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "requested_at": now.isoformat(),
        "provider_id": artifact.get("provider_id"),
        "hashes": artifact.get("hashes") or {},
        "mime_type": artifact.get("mime_type"),
        "file_size": artifact.get("file_size"),
        "status": "pending",
    }
    if not privacy_mode:
        payload["event_id"] = artifact.get("event_id")
        payload["filename"] = artifact.get("filename")
        payload["timestamp"] = artifact.get("timestamp")
    return {key: value for key, value in payload.items() if value not in (None, "", {}, [])}


def _result_metadata(result: SandboxResult) -> dict[str, Any]:
    return {
        "sandbox_status": result.status,
        "sandbox_verdict": result.verdict,
        "sandbox_confidence": result.confidence,
        "sandbox_source": result.source,
        "sandbox_analysis_id": result.analysis_id,
        "sandbox_submitted_at": result.submitted_at,
        "sandbox_completed_at": result.completed_at,
        "sandbox_expires_at": result.expires_at,
        "sandbox_findings": list(result.findings),
    }


def _artifact_key(artifact: Mapping[str, Any]) -> str:
    hashes = artifact.get("hashes") if isinstance(artifact.get("hashes"), Mapping) else {}
    return str(hashes.get("sha256") or hashes.get("sha1") or hashes.get("md5") or "").lower()


def _result_expired(result: SandboxResult, ttl_hours: int, now: datetime) -> bool:
    expires = _parse_time(result.expires_at)
    if expires is not None:
        return now >= expires
    completed = _parse_time(result.completed_at)
    if completed is None:
        return False
    return now - completed > timedelta(hours=max(1, int(ttl_hours)))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_or_none(value: Any) -> str | None:
    parsed = _parse_time(value)
    return parsed.isoformat() if parsed else None


def _clean_hash(value: Any, length: int) -> str | None:
    text = str(value or "").strip().lower()
    if len(text) != length:
        return None
    if not all(char in "0123456789abcdef" for char in text):
        return None
    return text


def _confidence(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number > 1:
        number /= 100
    return max(0.0, min(1.0, number))
