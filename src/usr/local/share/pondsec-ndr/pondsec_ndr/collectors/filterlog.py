"""OPNsense PF filterlog collector.

PF logs cover traffic that Suricata may not see in divert mode, especially
blocked inter-VLAN traffic. The collector converts bounded filterlog tails into
the same internal flow event shape used by the detection pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
import csv
import json
import re
from pathlib import Path
from typing import Any

from pondsec_ndr.schema import EVENT_SCHEMA_VERSION, event_id_from, is_private_ip, parse_timestamp, valid_ip, valid_port


@dataclass(slots=True)
class FilterLogStats:
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None


class FilterLogCollector:
    def __init__(self, log_path: Path, offset_path: Path, queue_limit: int = 10000, start_at_end: bool = True) -> None:
        self.log_path = log_path
        self.offset_path = offset_path
        self.queue_limit = queue_limit
        self.start_at_end = start_at_end
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_offset(self, file_stat: Any) -> dict[str, Any]:
        if not self.offset_path.exists():
            return {"inode": int(file_stat.st_ino), "offset": int(file_stat.st_size) if self.start_at_end else 0}
        try:
            with self.offset_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            return {"inode": None, "offset": 0}
        return {"inode": None, "offset": 0}

    def _save_offset(self, inode: int | None, offset: int) -> None:
        tmp = self.offset_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump({"inode": inode, "offset": offset}, handle, sort_keys=True)
        tmp.replace(self.offset_path)

    def read_once(self, max_lines: int = 1000) -> tuple[list[dict[str, Any]], FilterLogStats]:
        stats = FilterLogStats()
        try:
            file_stat = self.log_path.stat()
        except FileNotFoundError:
            return [], stats
        except PermissionError:
            stats.last_error = f"filter log is not readable by pondsec-ndr: {self.log_path}"
            return [], stats
        except OSError as exc:
            stats.last_error = f"filter log cannot be inspected: {exc}"
            return [], stats

        state = self._load_offset(file_stat)
        inode = int(file_stat.st_ino)
        offset = int(state.get("offset") or 0)
        if state.get("inode") != inode or file_stat.st_size < offset:
            offset = 0
            stats.rotation_detected = True

        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    stats.read_lines += 1
                    if stats.read_lines > max_lines:
                        break
                    if not line.strip():
                        continue
                    try:
                        event = normalize_filterlog_line(line)
                    except ValueError as exc:
                        stats.parser_errors += 1
                        stats.last_error = str(exc)
                        continue
                    if event is None:
                        continue
                    event_id = event["event_id"]
                    if event_id in seen_ids:
                        stats.duplicates += 1
                        continue
                    seen_ids.add(event_id)
                    if len(events) >= self.queue_limit:
                        stats.queue_drops += 1
                        continue
                    events.append(event)
                    stats.accepted_events += 1
                offset = handle.tell()
        except OSError as exc:
            stats.last_error = str(exc)
            return events, stats
        self._save_offset(inode, offset)
        return events, stats


def normalize_filterlog_line(line: str) -> dict[str, Any] | None:
    timestamp = _timestamp_from_syslog(line)
    payload = _payload_from_filterlog(line)
    fields = next(csv.reader([payload]))
    if len(fields) < 20:
        return None
    interface = fields[4] or None
    reason = fields[5] or None
    action = fields[6] or None
    direction = fields[7] or "unknown"
    if str(action).lower() != "block":
        return None
    ip_version = fields[8] or None
    proto = fields[16].upper() if len(fields) > 16 and fields[16] else None
    length = _safe_int(fields[17]) if len(fields) > 17 else 0
    src_ip = valid_ip(fields[18] if len(fields) > 18 else None)
    dst_ip = valid_ip(fields[19] if len(fields) > 19 else None)
    src_port = valid_port(fields[20] if len(fields) > 20 else None)
    dst_port = valid_port(fields[21] if len(fields) > 21 else None)
    if not src_ip or not dst_ip:
        return None
    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "event_type": "flow",
        "timestamp": parse_timestamp(timestamp),
        "source": {"ip": src_ip, "port": src_port, "interface": interface},
        "destination": {"ip": dst_ip, "port": dst_port},
        "protocol": proto,
        "direction": _traffic_direction(src_ip, dst_ip, direction),
        "metadata": {
            "event_source": "opnsense_filterlog",
            "filter_action": action,
            "filter_reason": reason,
            "filter_direction": direction,
            "filter_rule": fields[0] or None,
            "filter_tracker": fields[3] or None,
            "ip_version": ip_version,
            "duration": 1,
            "packets_out": 1,
            "packets_in": 0,
            "packet_count": 1,
            "bytes_out": length or 0,
            "bytes_in": 0,
            "byte_count": length or 0,
            "flow_state": "closed",
            "flow_reason": "reject" if str(action).lower() == "block" else "finished",
        },
        "raw_source": "opnsense_filterlog",
    }
    event["metadata"] = {key: value for key, value in event["metadata"].items() if value is not None}
    event["event_id"] = event_id_from(event)
    return event


def _timestamp_from_syslog(line: str) -> str:
    match = re.search(r">1\s+(\S+)", line)
    if match:
        return match.group(1)
    return ""


def _payload_from_filterlog(line: str) -> str:
    marker = " filterlog "
    index = line.find(marker)
    if index == -1:
        raise ValueError("not a filterlog syslog line")
    close = line.find("] ", index)
    if close == -1:
        raise ValueError("filterlog syslog metadata is incomplete")
    return line[close + 2 :].strip()


def _traffic_direction(src_ip: str, dst_ip: str, filter_direction: str) -> str:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private and dst_private:
        return "internal"
    if src_private and not dst_private:
        return "egress"
    if not src_private and dst_private:
        return "ingress"
    return filter_direction or "unknown"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
