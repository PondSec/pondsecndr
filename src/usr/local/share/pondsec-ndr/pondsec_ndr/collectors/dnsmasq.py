"""dnsmasq DNS and DHCP telemetry collector."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from pondsec_ndr.schema import EVENT_SCHEMA_VERSION, event_id_from, parse_timestamp, valid_ip


MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")


@dataclass(slots=True)
class DnsmasqStats:
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None
    active_path: str | None = None
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)


class DnsmasqCollector:
    def __init__(
        self,
        dns_log_path: Path | None,
        dhcp_log_path: Path | None,
        lease_path: Path | None,
        offset_dir: Path,
        *,
        sensor_name: str = "",
        queue_limit: int = 10000,
        start_at_end: bool = True,
    ) -> None:
        self.dns_log_path = dns_log_path
        self.dhcp_log_path = dhcp_log_path
        self.lease_path = lease_path
        self.offset_dir = offset_dir
        self.sensor_name = sensor_name
        self.queue_limit = queue_limit
        self.start_at_end = start_at_end
        self.offset_dir.mkdir(parents=True, exist_ok=True)

    def read_once(self, max_lines: int = 1000) -> tuple[list[dict[str, Any]], DnsmasqStats]:
        stats = DnsmasqStats()
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for name, path in self._log_sources():
            source_events, source_stats = self._read_log_source(name, path, max_lines=max_lines)
            stats.sources[name] = source_stats
            self._merge_stats(stats, source_stats)
            self._append_unique(events, source_events, seen_ids, stats)

        if self.lease_path:
            lease_events, lease_stats = self._read_lease_source(max_lines=max_lines)
            stats.sources["leases"] = lease_stats
            self._merge_stats(stats, lease_stats)
            self._append_unique(events, lease_events, seen_ids, stats)

        return events, stats

    def _log_sources(self) -> list[tuple[str, Path]]:
        sources: list[tuple[str, Path]] = []
        if self.dns_log_path:
            sources.append(("dns_log", self.dns_log_path))
        if self.dhcp_log_path and self.dhcp_log_path != self.dns_log_path:
            sources.append(("dhcp_log", self.dhcp_log_path))
        elif self.dhcp_log_path and not self.dns_log_path:
            sources.append(("dhcp_log", self.dhcp_log_path))
        return sources

    def _read_log_source(self, name: str, path: Path, max_lines: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        stats = DnsmasqStats()
        path = self._active_log_path(path, stats)
        if path is None:
            return [], _stats_dict(stats)
        try:
            file_stat = path.stat()
        except FileNotFoundError:
            stats.last_error = f"dnsmasq log does not exist: {path}"
            return [], _stats_dict(stats)
        except PermissionError:
            stats.last_error = f"dnsmasq log is not readable by pondsec-ndr: {path}"
            return [], _stats_dict(stats)
        except OSError as exc:
            stats.last_error = f"dnsmasq log cannot be inspected: {exc}"
            return [], _stats_dict(stats)
        stats.active_path = str(path)

        offset_path = self.offset_dir / f"dnsmasq_{name}.json"
        state = _load_json(offset_path)
        inode = int(file_stat.st_ino)
        if not state:
            offset = int(file_stat.st_size) if self.start_at_end else 0
        else:
            offset = int(state.get("offset") or 0)
        if state and (state.get("inode") != inode or file_stat.st_size < offset):
            offset = 0
            stats.rotation_detected = True

        events: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while stats.read_lines < max_lines:
                    line = handle.readline()
                    if not line:
                        break
                    if stats.read_lines >= max_lines:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    stats.read_lines += 1
                    try:
                        event = normalize_dnsmasq_line(stripped, sensor_name=self.sensor_name, source_log=str(path))
                    except ValueError as exc:
                        stats.parser_errors += 1
                        stats.last_error = str(exc)
                        continue
                    if event is None:
                        continue
                    events.append(event)
                    stats.accepted_events += 1
                offset = handle.tell()
        except OSError as exc:
            stats.last_error = str(exc)
            return events, _stats_dict(stats)

        try:
            _save_json(offset_path, {"inode": inode, "offset": offset})
        except OSError as exc:
            stats.last_error = f"dnsmasq collector offset cannot be saved: {exc}"
        return events, _stats_dict(stats)

    def _active_log_path(self, path: Path, stats: DnsmasqStats) -> Path | None:
        try:
            if not path.is_dir():
                return path
        except PermissionError:
            stats.last_error = f"dnsmasq log directory is not readable by pondsec-ndr: {path}"
            return None
        except OSError as exc:
            stats.last_error = f"dnsmasq log directory cannot be inspected: {exc}"
            return None
        try:
            candidates = [item for item in path.iterdir() if item.is_file() and item.suffix == ".log"]
        except PermissionError:
            stats.last_error = f"dnsmasq log directory is not readable by pondsec-ndr: {path}"
            return None
        except OSError as exc:
            stats.last_error = f"dnsmasq log directory cannot be inspected: {exc}"
            return None
        if not candidates:
            stats.last_error = f"dnsmasq log directory contains no .log files: {path}"
            return None
        return max(candidates, key=lambda item: item.stat().st_mtime)

    def _read_lease_source(self, max_lines: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        stats = DnsmasqStats()
        path = self.lease_path
        if path is None:
            return [], _stats_dict(stats)
        try:
            file_stat = path.stat()
        except FileNotFoundError:
            return [], _stats_dict(stats)
        except PermissionError:
            stats.last_error = f"dnsmasq lease file is not readable by pondsec-ndr: {path}"
            return [], _stats_dict(stats)
        except OSError as exc:
            stats.last_error = f"dnsmasq lease file cannot be inspected: {exc}"
            return [], _stats_dict(stats)

        snapshot_path = self.offset_dir / "dnsmasq_leases.json"
        state = _load_json(snapshot_path)
        seen_before = set(state.get("event_ids") or []) if isinstance(state, dict) else set()
        first_run = not bool(state)
        seen_now: set[str] = set()
        events: list[dict[str, Any]] = []
        observed_at = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat()

        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if stats.read_lines >= max_lines:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    stats.read_lines += 1
                    try:
                        event = normalize_dnsmasq_lease(stripped, observed_at, self.sensor_name, str(path))
                    except ValueError as exc:
                        stats.parser_errors += 1
                        stats.last_error = str(exc)
                        continue
                    if event is None:
                        continue
                    seen_now.add(event["event_id"])
                    if first_run and self.start_at_end:
                        continue
                    if event["event_id"] in seen_before:
                        stats.duplicates += 1
                        continue
                    events.append(event)
                    stats.accepted_events += 1
        except OSError as exc:
            stats.last_error = str(exc)
            return events, _stats_dict(stats)

        try:
            _save_json(snapshot_path, {"event_ids": sorted(seen_now), "updated_at": observed_at})
        except OSError as exc:
            stats.last_error = f"dnsmasq lease snapshot cannot be saved: {exc}"
        return events, _stats_dict(stats)

    def _append_unique(
        self,
        target: list[dict[str, Any]],
        source: list[dict[str, Any]],
        seen_ids: set[str],
        stats: DnsmasqStats,
    ) -> None:
        for event in source:
            event_id = event["event_id"]
            if event_id in seen_ids:
                stats.duplicates += 1
                continue
            seen_ids.add(event_id)
            if len(target) >= self.queue_limit:
                stats.queue_drops += 1
                continue
            target.append(event)

    @staticmethod
    def _merge_stats(target: DnsmasqStats, source: dict[str, Any]) -> None:
        target.read_lines += int(source.get("read_lines") or 0)
        target.accepted_events += int(source.get("accepted_events") or 0)
        target.parser_errors += int(source.get("parser_errors") or 0)
        target.normalization_errors += int(source.get("normalization_errors") or 0)
        target.duplicates += int(source.get("duplicates") or 0)
        target.queue_drops += int(source.get("queue_drops") or 0)
        target.rotation_detected = target.rotation_detected or bool(source.get("rotation_detected"))
        if source.get("last_error"):
            target.last_error = str(source["last_error"])


def normalize_dnsmasq_line(line: str, sensor_name: str = "", source_log: str = "") -> dict[str, Any] | None:
    timestamp = _timestamp_from_syslog(line)
    payload = _payload(line)
    if "dnsmasq" not in line.lower() and not payload.startswith(("query[", "DHCP")):
        return None
    dns_event = _dns_query_event(payload, timestamp, sensor_name, source_log)
    if dns_event is not None:
        return dns_event
    dhcp_event = _dnsmasq_dhcp_event(payload, timestamp, sensor_name, source_log)
    if dhcp_event is not None:
        return dhcp_event
    return _dhcpd_event(payload, timestamp, sensor_name, source_log)


def normalize_dnsmasq_lease(line: str, observed_at: str, sensor_name: str = "", source_log: str = "") -> dict[str, Any] | None:
    parts = line.split()
    if len(parts) < 3:
        return None
    expiry, mac, ip = parts[:3]
    hostname = parts[3] if len(parts) >= 4 and parts[3] not in {"*", "-"} else None
    client_id = parts[4] if len(parts) >= 5 and parts[4] not in {"*", "-"} else None
    source_ip = valid_ip(ip)
    if not source_ip:
        return None
    expiry_at = None
    try:
        expiry_int = int(expiry)
    except ValueError:
        expiry_int = 0
    if expiry_int > 0:
        expiry_at = datetime.fromtimestamp(expiry_int, tz=timezone.utc).isoformat()
    metadata = _metadata({
        "event_source": "dnsmasq",
        "source_log": source_log or None,
        "sensor_name": sensor_name or None,
        "dhcp_action": "lease",
        "mac": _mac(mac),
        "hostname": hostname,
        "client_id": client_id,
        "lease_expires_at": expiry_at,
        "entity_confidence": 0.95,
        "entity_evidence": ["dnsmasq_lease"],
    })
    return _event("dhcp", observed_at, source_ip, None, None, metadata, "dnsmasq")


def _dns_query_event(payload: str, timestamp: str, sensor_name: str, source_log: str) -> dict[str, Any] | None:
    match = re.search(r"\bquery\[(?P<qtype>[^\]]+)]\s+(?P<name>\S+)\s+from\s+(?P<src>\S+)", payload)
    if not match:
        return None
    source_ip = valid_ip(match.group("src"))
    if not source_ip:
        return None
    rrname = match.group("name").rstrip(".")
    metadata = _metadata({
        "event_source": "dnsmasq",
        "source_log": source_log or None,
        "sensor_name": sensor_name or None,
        "dnsmasq_action": "query",
        "rrname": rrname,
        "rrtype": match.group("qtype").upper(),
    })
    return _event("dns", timestamp, source_ip, None, "UDP", metadata, "dnsmasq")


def _dnsmasq_dhcp_event(payload: str, timestamp: str, sensor_name: str, source_log: str) -> dict[str, Any] | None:
    match = re.search(r"\b(?P<action>DHCP[A-Z]+)\((?P<interface>[^)]*)\)\s+(?P<body>.*)", payload)
    if not match:
        return None
    action = match.group("action").lower()
    body = match.group("body")
    source_ip = _first_ip(body)
    mac = _first_mac(body)
    hostname = _hostname_from_tokens(body.split(), source_ip, mac)
    metadata = _metadata({
        "event_source": "dnsmasq",
        "source_log": source_log or None,
        "sensor_name": sensor_name or None,
        "dhcp_action": action,
        "mac": mac,
        "hostname": hostname,
        "entity_confidence": 0.9 if source_ip and mac else 0.6,
        "entity_evidence": ["dnsmasq_dhcp"],
    })
    return _event("dhcp", timestamp, source_ip, match.group("interface") or None, None, metadata, "dnsmasq")


def _dhcpd_event(payload: str, timestamp: str, sensor_name: str, source_log: str) -> dict[str, Any] | None:
    match = re.search(
        r"\b(?P<action>DHCP[A-Z]+)\s+(?:on|for)\s+(?P<ip>\S+)\s+to\s+(?P<mac>[0-9a-fA-F:]{17})(?:\s+\((?P<hostname>[^)]*)\))?(?:\s+via\s+(?P<interface>\S+))?",
        payload,
    )
    if not match:
        return None
    source_ip = valid_ip(match.group("ip"))
    metadata = _metadata({
        "event_source": "dhcpd",
        "source_log": source_log or None,
        "sensor_name": sensor_name or None,
        "dhcp_action": match.group("action").lower(),
        "mac": _mac(match.group("mac")),
        "hostname": match.group("hostname"),
        "entity_confidence": 0.9 if source_ip and match.group("mac") else 0.6,
        "entity_evidence": ["dhcpd_log"],
    })
    return _event("dhcp", timestamp, source_ip, match.group("interface"), None, metadata, "dhcpd")


def _event(
    event_type: str,
    timestamp: str,
    source_ip: str | None,
    interface: str | None,
    protocol: str | None,
    metadata: dict[str, Any],
    raw_source: str,
) -> dict[str, Any]:
    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "event_type": event_type,
        "timestamp": parse_timestamp(timestamp) or parse_timestamp(None),
        "source": {"ip": source_ip, "port": None, "interface": interface},
        "destination": {"ip": None, "port": 53 if event_type == "dns" else None},
        "protocol": protocol,
        "direction": "internal" if source_ip else "unknown",
        "metadata": metadata,
        "raw_source": raw_source,
    }
    event["event_id"] = event_id_from(event)
    return event


def _timestamp_from_syslog(line: str) -> str:
    rfc5424 = re.search(r">1\s+(\d{4}-\d\d-\d\dT\S+)", line)
    if rfc5424:
        return rfc5424.group(1)
    iso = re.search(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)", line)
    if iso:
        return iso.group(1)
    classic = re.match(r"(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", line)
    if classic:
        current_year = datetime.now(timezone.utc).year
        try:
            parsed = datetime.strptime(f"{current_year} {classic.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now(timezone.utc).isoformat()
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    return datetime.now(timezone.utc).isoformat()


def _payload(line: str) -> str:
    match = re.search(r"\b(?:dnsmasq(?:-dhcp)?|dhcpd)(?:\[\d+])?:\s+(?P<payload>.*)$", line)
    if match:
        return match.group("payload").strip()
    return line.strip()


def _metadata(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "", [], {})}


def _first_ip(value: str) -> str | None:
    for token in re.split(r"\s+", value):
        ip = valid_ip(token)
        if ip and ip != "0.0.0.0":
            return ip
    return None


def _first_mac(value: str) -> str | None:
    match = MAC_RE.search(value)
    return _mac(match.group(0)) if match else None


def _mac(value: str | None) -> str | None:
    if not value or not MAC_RE.fullmatch(value):
        return None
    return value.lower()


def _hostname_from_tokens(tokens: list[str], ip: str | None, mac: str | None) -> str | None:
    for token in reversed(tokens):
        cleaned = token.strip()
        if not cleaned or cleaned in {"*", "-"}:
            continue
        if valid_ip(cleaned) or _mac(cleaned):
            continue
        if ip and cleaned == ip:
            continue
        if mac and cleaned.lower() == mac:
            continue
        return cleaned
    return None


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def _save_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, sort_keys=True)
    tmp.replace(path)


def _stats_dict(stats: DnsmasqStats) -> dict[str, Any]:
    return {
        "read_lines": stats.read_lines,
        "accepted_events": stats.accepted_events,
        "parser_errors": stats.parser_errors,
        "normalization_errors": stats.normalization_errors,
        "duplicates": stats.duplicates,
        "queue_drops": stats.queue_drops,
        "rotation_detected": stats.rotation_detected,
        "last_error": stats.last_error,
        "active_path": stats.active_path,
    }
