"""Local indicator enrichment for network events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


DEFAULT_IOC_FILES = ("local_iocs.json", "local_iocs.txt")
DEFAULT_OVERRIDE_FILES = ("local_ioc_overrides.json", "local_ioc_allowlist.txt")
BENIGN_REPUTATIONS = {"allow", "allowlist", "benign", "known_good", "false_positive", "suppress"}
MALICIOUS_REPUTATIONS = {"malicious", "known_bad", "bad", "high", "block", "blocked"}


@dataclass(frozen=True)
class LocalIndicator:
    kind: str
    value: str
    source: str = "local_ioc_feed"
    confidence: float = 0.95
    threat_name: str = "local threat indicator"
    reputation: str = "malicious"
    priority: int = 50
    expires_at: str | None = None
    updated_at: str | None = None
    action: str = "detect"


def enrich_events_with_local_iocs(events: list[dict[str, Any]], data_dir: Path, config: Any | None = None) -> list[dict[str, Any]]:
    indicators = load_local_indicators(data_dir, config=config)
    if not indicators:
        return events
    enriched = []
    for event in events:
        match = match_event(event, indicators)
        if match is None:
            enriched.append(event)
            continue
        metadata = dict(event.get("metadata") if isinstance(event.get("metadata"), dict) else {})
        metadata.setdefault("ioc_match", match.value)
        metadata.setdefault("ioc_type", match.kind)
        metadata.setdefault("reputation", match.reputation)
        metadata.setdefault("threat_intel_confidence", match.confidence)
        metadata.setdefault("threat_intel_source", match.source)
        metadata.setdefault("threat_name", match.threat_name)
        metadata.setdefault("threat_intel_priority", match.priority)
        if match.expires_at:
            metadata.setdefault("threat_intel_expires_at", match.expires_at)
        if match.updated_at:
            metadata.setdefault("threat_intel_updated_at", match.updated_at)
        enriched_event = dict(event)
        enriched_event["metadata"] = metadata
        enriched.append(enriched_event)
    return enriched


def load_local_indicators(data_dir: Path, config: Any | None = None, now: datetime | None = None) -> list[LocalIndicator]:
    intel_dir = Path(data_dir) / "intel"
    indicators: list[LocalIndicator] = []
    for name in DEFAULT_IOC_FILES:
        path = intel_dir / name
        if not path.exists():
            continue
        try:
            if path.suffix == ".json":
                indicators.extend(_load_json_feed(path))
            else:
                indicators.extend(_load_text_feed(path))
        except (OSError, json.JSONDecodeError):
            continue
    for name in DEFAULT_OVERRIDE_FILES:
        path = intel_dir / name
        if not path.exists():
            continue
        try:
            if path.suffix == ".json":
                indicators.extend(_load_json_feed(path, default_reputation="benign", default_priority=100, default_action="suppress"))
            else:
                indicators.extend(_load_text_feed(path, default_reputation="benign", default_priority=100, default_action="suppress"))
        except (OSError, json.JSONDecodeError):
            continue
    ttl_hours = int(getattr(config, "feed_ttl_hours", 168) or 168) if config is not None else 168
    return _resolve_indicators(indicators, ttl_hours=ttl_hours, now=now)


def match_event(event: dict[str, Any], indicators: list[LocalIndicator]) -> LocalIndicator | None:
    values = _event_values(event)
    for indicator in indicators:
        candidates = values.get(indicator.kind, set())
        if indicator.kind == "domain":
            if any(_domain_matches(candidate, indicator.value) for candidate in candidates):
                return indicator
            continue
        if indicator.value in candidates:
            return indicator
    return None


def _load_json_feed(
    path: Path,
    *,
    default_reputation: str = "malicious",
    default_priority: int = 50,
    default_action: str = "detect",
) -> list[LocalIndicator]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    rows: list[Any]
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        rows = []
        for kind in ("domain", "domains", "ip", "ips", "url", "urls", "hash", "hashes"):
            values = raw.get(kind)
            if isinstance(values, list):
                normalized_kind = kind[:-1] if kind.endswith("s") else kind
                for value in values:
                    if isinstance(value, dict):
                        row = dict(value)
                        row.setdefault("type", normalized_kind)
                        rows.append(row)
                    else:
                        rows.append({"type": normalized_kind, "value": value})
    else:
        rows = []
    return [
        _indicator_from_mapping(
            item,
            path.name,
            default_reputation=default_reputation,
            default_priority=default_priority,
            default_action=default_action,
        )
        for item in rows
        if isinstance(item, dict)
    ]


def _load_text_feed(
    path: Path,
    *,
    default_reputation: str = "malicious",
    default_priority: int = 50,
    default_action: str = "detect",
) -> list[LocalIndicator]:
    indicators = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        kind = ""
        value = text
        if ":" in text:
            maybe_kind, maybe_value = text.split(":", 1)
            if maybe_kind.strip().lower() in {"domain", "ip", "url", "hash"}:
                kind = maybe_kind.strip().lower()
                value = maybe_value.strip()
        indicators.append(_indicator_from_mapping(
            {
                "type": kind or _infer_kind(value),
                "value": value,
                "reputation": default_reputation,
                "priority": default_priority,
                "action": default_action,
            },
            path.name,
            default_reputation=default_reputation,
            default_priority=default_priority,
            default_action=default_action,
        ))
    return indicators


def _indicator_from_mapping(
    item: dict[str, Any],
    source: str,
    *,
    default_reputation: str = "malicious",
    default_priority: int = 50,
    default_action: str = "detect",
) -> LocalIndicator:
    kind = str(item.get("type") or item.get("kind") or item.get("ioc_type") or _infer_kind(item.get("value"))).lower()
    if kind.endswith("s"):
        kind = kind[:-1]
    if kind not in {"domain", "ip", "url", "hash"}:
        kind = _infer_kind(item.get("value"))
    confidence = _confidence(item.get("confidence"), 0.95)
    value = _normalize_value(kind, item.get("value") or item.get("indicator") or item.get("ioc"))
    reputation = str(item.get("reputation") or default_reputation).lower()
    return LocalIndicator(
        kind=kind,
        value=value,
        source=str(item.get("source") or source or "local_ioc_feed"),
        confidence=confidence,
        threat_name=str(item.get("threat_name") or item.get("label") or "local threat indicator"),
        reputation=reputation,
        priority=_priority(item.get("priority"), default_priority, reputation),
        expires_at=_iso_or_none(item.get("expires_at") or item.get("valid_until")),
        updated_at=_iso_or_none(item.get("updated_at") or item.get("last_seen") or item.get("created_at")),
        action=str(item.get("action") or default_action).lower(),
    )


def _event_values(event: dict[str, Any]) -> dict[str, set[str]]:
    metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    values: dict[str, set[str]] = {"domain": set(), "ip": set(), "url": set(), "hash": set()}
    for side in ("source", "destination"):
        address = (event.get(side) or {}).get("ip") if isinstance(event.get(side), dict) else None
        if address:
            values["ip"].add(str(address).lower())
    for key in ("domain", "hostname", "sni", "tls_sni", "server_name", "rrname", "query"):
        _add_domain(values, metadata.get(key))
    for key in ("url", "uri"):
        _add_url(values, metadata.get(key))
    for key in ("md5", "sha1", "sha256"):
        if metadata.get(key):
            values["hash"].add(str(metadata[key]).strip().lower())
    return values


def _add_url(values: dict[str, set[str]], value: Any) -> None:
    if not value:
        return
    text = str(value).strip()
    if not text:
        return
    values["url"].add(text.lower())
    parsed = urlsplit(text if "://" in text else "http://" + text.lstrip("/"))
    _add_domain(values, parsed.hostname)


def _add_domain(values: dict[str, set[str]], value: Any) -> None:
    if not value:
        return
    text = str(value).strip().lower().rstrip(".")
    if text:
        values["domain"].add(text)


def _domain_matches(candidate: str, indicator: str) -> bool:
    candidate = candidate.lower().rstrip(".")
    indicator = indicator.lower().rstrip(".")
    return candidate == indicator or candidate.endswith("." + indicator)


def _infer_kind(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "://" in text:
        return "url"
    if len(text) in {32, 40, 64} and all(char in "0123456789abcdef" for char in text):
        return "hash"
    if text.replace(".", "").isdigit() and text.count(".") == 3:
        return "ip"
    return "domain"


def _normalize_value(kind: str, value: Any) -> str:
    text = str(value or "").strip().lower()
    if kind == "domain":
        return text.rstrip(".")
    if kind == "url":
        return text
    return text


def _confidence(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number > 1:
        number /= 100
    return max(0.0, min(1.0, number))


def _priority(value: Any, default: int, reputation: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if reputation in BENIGN_REPUTATIONS:
        number = max(number, 100)
    return max(0, min(1000, number))


def _resolve_indicators(indicators: list[LocalIndicator], ttl_hours: int = 168, now: datetime | None = None) -> list[LocalIndicator]:
    now = now or datetime.now(timezone.utc)
    grouped: dict[tuple[str, str], list[LocalIndicator]] = {}
    for indicator in indicators:
        key = (indicator.kind, indicator.value)
        if not indicator.value or _expired(indicator, ttl_hours, now):
            continue
        grouped.setdefault(key, []).append(indicator)
    result = []
    for group in grouped.values():
        suppressors = [
            item for item in group
            if item.reputation in BENIGN_REPUTATIONS or item.action in {"allow", "suppress", "ignore"}
        ]
        if suppressors:
            continue
        result.append(max(group, key=lambda item: (item.priority, item.confidence, _parse_time(item.updated_at) or datetime.min.replace(tzinfo=timezone.utc))))
    return result


def _expired(indicator: LocalIndicator, ttl_hours: int, now: datetime) -> bool:
    expires = _parse_time(indicator.expires_at)
    if expires is not None:
        return now >= expires
    updated = _parse_time(indicator.updated_at)
    if updated is None:
        return False
    return now - updated > timedelta(hours=max(1, int(ttl_hours)))


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
