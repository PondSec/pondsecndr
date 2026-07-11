"""Zeek log collector and normalizer.

The collector tails Zeek's default TSV logs from a configured directory. It is
designed for an external Zeek sensor first: no interface or packet-capture
settings are changed by this code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from pondsec_ndr.schema import EVENT_SCHEMA_VERSION, event_id_from, is_private_ip, parse_timestamp, valid_ip, valid_port


SUPPORTED_ZEEK_LOGS = ("conn", "dns", "ssl", "x509", "http", "files", "notice", "weird")


@dataclass(slots=True)
class ZeekSourceStats:
    path: str
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None


@dataclass(slots=True)
class ZeekCollectorStats:
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None
    sources: dict[str, dict[str, Any]] = field(default_factory=dict)


class ZeekLogCollector:
    def __init__(
        self,
        log_paths: Mapping[str, Path],
        offset_dir: Path,
        *,
        sensor_name: str = "",
        interface: str = "",
        remote_target: str = "",
        queue_limit: int = 10000,
        start_at_end: bool = True,
    ) -> None:
        self.log_paths = {name: path for name, path in log_paths.items() if name in SUPPORTED_ZEEK_LOGS and str(path)}
        self.offset_dir = offset_dir
        self.sensor_name = sensor_name
        self.interface = interface
        self.remote_target = remote_target
        self.queue_limit = queue_limit
        self.start_at_end = start_at_end
        self.offset_dir.mkdir(parents=True, exist_ok=True)

    def read_once(self, max_lines: int = 1000) -> tuple[list[dict[str, Any]], ZeekCollectorStats]:
        aggregate = ZeekCollectorStats()
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        remaining = max(0, min(max_lines, self.queue_limit))

        for log_type, path in self.log_paths.items():
            if remaining <= 0:
                break
            source_events, source_stats = self._read_log(log_type, path, remaining, seen_ids)
            events.extend(source_events)
            remaining = max(0, min(max_lines, self.queue_limit) - len(events))
            self._merge_stats(aggregate, log_type, source_stats)

        return events, aggregate

    def _read_log(
        self,
        log_type: str,
        path: Path,
        max_lines: int,
        seen_ids: set[str],
    ) -> tuple[list[dict[str, Any]], ZeekSourceStats]:
        stats = ZeekSourceStats(path=str(path))
        try:
            file_stat = path.stat()
        except FileNotFoundError:
            return [], stats
        except PermissionError:
            stats.last_error = f"Zeek log is not readable by pondsec-ndr: {path}"
            return [], stats
        except OSError as exc:
            stats.last_error = f"Zeek log cannot be inspected: {exc}"
            return [], stats

        offset_path = self.offset_dir / f"zeek_{log_type}.json"
        state = self._load_offset(offset_path)
        inode = int(file_stat.st_ino)
        if state and (state.get("inode") != inode or file_stat.st_size < int(state.get("offset") or 0)):
            state = {}
            stats.rotation_detected = True

        header = self._header_from_state_or_file(path, state)
        offset = int(state.get("offset") or 0)
        if not state and self.start_at_end and not stats.rotation_detected:
            offset = int(file_stat.st_size)

        events: list[dict[str, Any]] = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                for raw_line in handle:
                    if stats.read_lines >= max_lines:
                        break
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue
                    if line.startswith("#"):
                        _update_header_from_control_line(header, line)
                        continue
                    stats.read_lines += 1
                    if not header.get("fields"):
                        stats.parser_errors += 1
                        stats.last_error = f"Zeek {log_type}.log has no #fields header"
                        continue
                    try:
                        row = _parse_zeek_row(line, header)
                    except ValueError as exc:
                        stats.parser_errors += 1
                        stats.last_error = str(exc)
                        continue
                    try:
                        event = normalize_zeek_row(log_type, row, self.sensor_name, self.interface, self.remote_target)
                    except ValueError as exc:
                        stats.normalization_errors += 1
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

        try:
            self._save_offset(offset_path, inode, offset, header)
        except OSError as exc:
            stats.last_error = f"Zeek collector offset cannot be saved: {exc}"
        return events, stats

    @staticmethod
    def _load_offset(offset_path: Path) -> dict[str, Any]:
        if not offset_path.exists():
            return {}
        try:
            with offset_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            return {}
        return {}

    @staticmethod
    def _save_offset(offset_path: Path, inode: int | None, offset: int, header: dict[str, Any]) -> None:
        tmp = offset_path.with_suffix(".tmp")
        payload = {
            "inode": inode,
            "offset": offset,
            "fields": header.get("fields", []),
            "separator": header.get("separator", "\t"),
            "empty_field": header.get("empty_field", ""),
            "unset_field": header.get("unset_field", "-"),
        }
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
        tmp.replace(offset_path)

    @staticmethod
    def _header_from_state_or_file(path: Path, state: dict[str, Any]) -> dict[str, Any]:
        header = {
            "fields": list(state.get("fields") or []),
            "separator": state.get("separator") or "\t",
            "empty_field": state.get("empty_field") if state.get("empty_field") is not None else "",
            "unset_field": state.get("unset_field") or "-",
        }
        if header["fields"]:
            return header
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if not line.startswith("#"):
                        break
                    _update_header_from_control_line(header, line.rstrip("\n"))
        except OSError:
            return header
        return header

    @staticmethod
    def _merge_stats(aggregate: ZeekCollectorStats, log_type: str, stats: ZeekSourceStats) -> None:
        aggregate.read_lines += stats.read_lines
        aggregate.accepted_events += stats.accepted_events
        aggregate.parser_errors += stats.parser_errors
        aggregate.normalization_errors += stats.normalization_errors
        aggregate.duplicates += stats.duplicates
        aggregate.queue_drops += stats.queue_drops
        aggregate.rotation_detected = aggregate.rotation_detected or stats.rotation_detected
        if stats.last_error:
            aggregate.last_error = stats.last_error
        aggregate.sources[log_type] = {
            "path": stats.path,
            "read_lines": stats.read_lines,
            "accepted_events": stats.accepted_events,
            "parser_errors": stats.parser_errors,
            "normalization_errors": stats.normalization_errors,
            "duplicates": stats.duplicates,
            "queue_drops": stats.queue_drops,
            "rotation_detected": stats.rotation_detected,
            "last_error": stats.last_error,
        }


def normalize_zeek_row(
    log_type: str,
    row: Mapping[str, Any],
    sensor_name: str = "",
    interface: str = "",
    remote_target: str = "",
) -> dict[str, Any] | None:
    timestamp = parse_timestamp(row.get("ts"))
    if not timestamp:
        raise ValueError(f"Zeek {log_type}.log row has invalid timestamp")

    source_ip = valid_ip(row.get("id.orig_h") or _first_set_item(row.get("tx_hosts")))
    destination_ip = valid_ip(row.get("id.resp_h") or _first_set_item(row.get("rx_hosts")))
    source_port = valid_port(row.get("id.orig_p"))
    destination_port = valid_port(row.get("id.resp_p"))
    protocol = str(row.get("proto") or "").upper() or None

    if log_type in {"conn", "dns", "ssl", "http"} and (not source_ip or not destination_ip):
        return None

    metadata = _base_metadata(log_type, row, sensor_name, interface, remote_target)
    metadata.update(_typed_metadata(log_type, row))
    metadata = {key: value for key, value in metadata.items() if value not in (None, "", [], {})}

    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "event_type": _event_type(log_type),
        "timestamp": timestamp,
        "source": {"ip": source_ip, "port": source_port, "interface": interface or None},
        "destination": {"ip": destination_ip, "port": destination_port},
        "protocol": protocol,
        "direction": _traffic_direction(source_ip, destination_ip),
        "metadata": metadata,
        "raw_source": "zeek",
    }
    event["event_id"] = event_id_from(event)
    return event


def _update_header_from_control_line(header: dict[str, Any], line: str) -> None:
    if line.startswith("#separator"):
        value = _control_value(line, "#separator")
        if value is None:
            return
        header["separator"] = _decode_zeek_control_value(value)
    elif line.startswith("#empty_field"):
        header["empty_field"] = _control_value(line, "#empty_field")
    elif line.startswith("#unset_field"):
        header["unset_field"] = _control_value(line, "#unset_field")
    elif line.startswith("#fields"):
        value = _control_value(line, "#fields")
        if value is not None:
            header["fields"] = value.split(header.get("separator", "\t"))


def _control_value(line: str, name: str) -> str | None:
    if not line.startswith(name):
        return None
    value = line[len(name) :]
    if not value:
        return None
    return value[1:] if value[0].isspace() else value


def _decode_zeek_control_value(value: str) -> str:
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return "\t"


def _parse_zeek_row(line: str, header: Mapping[str, Any]) -> dict[str, Any]:
    separator = str(header.get("separator") or "\t")
    fields = list(header.get("fields") or [])
    values = line.split(separator)
    if len(values) < len(fields):
        raise ValueError("Zeek row has fewer values than header fields")
    row: dict[str, Any] = {}
    empty_field = header.get("empty_field")
    unset_field = header.get("unset_field", "-")
    for key, value in zip(fields, values):
        if value == empty_field or value == unset_field:
            row[key] = None
        else:
            row[key] = value
    return row


def _base_metadata(log_type: str, row: Mapping[str, Any], sensor_name: str, interface: str, remote_target: str) -> dict[str, Any]:
    return {
        "event_source": "zeek",
        "zeek_log": log_type,
        "uid": row.get("uid"),
        "sensor_name": sensor_name or None,
        "sensor_interface": interface or None,
        "remote_target": remote_target or None,
    }


def _typed_metadata(log_type: str, row: Mapping[str, Any]) -> dict[str, Any]:
    if log_type == "conn":
        return {
            "service": row.get("service"),
            "duration": _float(row.get("duration")),
            "bytes_out": _int(row.get("orig_bytes")),
            "bytes_in": _int(row.get("resp_bytes")),
            "byte_count": _int(row.get("orig_bytes")) + _int(row.get("resp_bytes")),
            "packets_out": _int(row.get("orig_pkts")),
            "packets_in": _int(row.get("resp_pkts")),
            "packet_count": _int(row.get("orig_pkts")) + _int(row.get("resp_pkts")),
            "conn_state": row.get("conn_state"),
            "missed_bytes": _int(row.get("missed_bytes")),
            "history": row.get("history"),
        }
    if log_type == "dns":
        return {
            "query": row.get("query"),
            "rrtype": row.get("qtype_name") or row.get("qtype"),
            "rcode": row.get("rcode_name") or row.get("rcode"),
            "answers": _set_items(row.get("answers"))[:8],
            "rejected": _boolish(row.get("rejected")),
        }
    if log_type == "ssl":
        return {
            "server_name": row.get("server_name"),
            "version": row.get("version"),
            "cipher": row.get("cipher"),
            "ja3": row.get("ja3"),
            "ja3s": row.get("ja3s"),
            "fingerprint": row.get("cert_chain_fuids") or row.get("client_cert_chain_fuids"),
            "validation_status": row.get("validation_status"),
            "established": _boolish(row.get("established")),
        }
    if log_type == "x509":
        return {
            "certificate_fingerprint": row.get("fingerprint") or row.get("id"),
            "certificate_subject": row.get("certificate.subject"),
            "certificate_issuer": row.get("certificate.issuer"),
            "certificate_not_valid_before": row.get("certificate.not_valid_before"),
            "certificate_not_valid_after": row.get("certificate.not_valid_after"),
            "san_dns": _set_items(row.get("san.dns"))[:8],
        }
    if log_type == "http":
        return {
            "hostname": row.get("host"),
            "url_path": _url_path(row.get("uri")),
            "method": row.get("method"),
            "status": _int_or_none(row.get("status_code")),
            "user_agent": row.get("user_agent"),
            "request_body_len": _int(row.get("request_body_len")),
            "response_body_len": _int(row.get("response_body_len")),
            "byte_count": _int(row.get("request_body_len")) + _int(row.get("response_body_len")),
        }
    if log_type == "files":
        return {
            "file_id": row.get("fuid"),
            "tx_hosts": _set_items(row.get("tx_hosts"))[:8],
            "rx_hosts": _set_items(row.get("rx_hosts"))[:8],
            "mime_type": row.get("mime_type"),
            "filename": Path(str(row.get("filename"))).name if row.get("filename") else None,
            "seen_bytes": _int(row.get("seen_bytes")),
            "total_bytes": _int(row.get("total_bytes")),
            "md5": row.get("md5"),
            "sha1": row.get("sha1"),
            "sha256": row.get("sha256"),
        }
    if log_type == "notice":
        return {
            "note": row.get("note"),
            "message": _bounded(row.get("msg"), 512),
            "sub": _bounded(row.get("sub"), 256),
            "actions": _set_items(row.get("actions"))[:8],
            "dropped": _boolish(row.get("dropped")),
        }
    if log_type == "weird":
        return {
            "name": row.get("name"),
            "addl": _bounded(row.get("addl"), 256),
            "notice": _boolish(row.get("notice")),
            "peer": row.get("peer"),
        }
    return {}


def _event_type(log_type: str) -> str:
    return {
        "conn": "flow",
        "ssl": "tls",
        "x509": "tls",
        "files": "fileinfo",
        "notice": "notice",
        "weird": "anomaly",
    }.get(log_type, log_type)


def _traffic_direction(src_ip: str | None, dst_ip: str | None) -> str:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private and dst_private:
        return "internal"
    if src_private and not dst_private:
        return "egress"
    if not src_private and dst_private:
        return "ingress"
    return "unknown"


def _first_set_item(value: Any) -> str | None:
    items = _set_items(value)
    return items[0] if items else None


def _set_items(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    return [item for item in str(value).split(",") if item]


def _url_path(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    parsed = urlsplit(text)
    if parsed.path:
        return parsed.path
    if text.startswith("/"):
        return text.split("?", 1)[0]
    return None


def _boolish(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if text in {"t", "true", "1", "yes"}:
        return True
    if text in {"f", "false", "0", "no"}:
        return False
    return None


def _int(value: Any) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return _int(value)


def _float(value: Any) -> float | None:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _bounded(value: Any, limit: int) -> str | None:
    if value in (None, ""):
        return None
    text = str(value)
    return text[:limit]
