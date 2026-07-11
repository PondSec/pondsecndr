"""Zenarmor reporting collector.

Zenarmor integration intentionally consumes exported reporting data such as
Syslog/JSON lines. It does not read license data, TLS inspection secrets,
engine binaries, or undocumented internal databases.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import select
import socket
from typing import Any, Mapping
from urllib.parse import urlsplit

from pondsec_ndr.schema import EVENT_SCHEMA_VERSION, event_id_from, is_private_ip, parse_timestamp, valid_ip, valid_port


@dataclass(slots=True)
class ZenarmorStats:
    read_datagrams: int = 0
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None


class ZenarmorCollector:
    def __init__(
        self,
        log_path: Path,
        offset_path: Path,
        *,
        sensor_name: str = "",
        remote_target: str = "",
        queue_limit: int = 10000,
        start_at_end: bool = True,
        import_options: Mapping[str, bool] | None = None,
    ) -> None:
        self.log_path = log_path
        self.offset_path = offset_path
        self.sensor_name = sensor_name
        self.remote_target = remote_target
        self.queue_limit = queue_limit
        self.start_at_end = start_at_end
        self.import_options = dict(import_options or {})
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)

    def read_once(self, max_lines: int = 1000) -> tuple[list[dict[str, Any]], ZenarmorStats]:
        stats = ZenarmorStats()
        try:
            file_stat = self.log_path.stat()
        except FileNotFoundError:
            stats.last_error = f"Zenarmor export log does not exist: {self.log_path}"
            return [], stats
        except PermissionError:
            stats.last_error = f"Zenarmor export log is not readable by pondsec-ndr: {self.log_path}"
            return [], stats
        except OSError as exc:
            stats.last_error = f"Zenarmor export log cannot be inspected: {exc}"
            return [], stats

        state = self._load_offset()
        inode = int(file_stat.st_ino)
        offset = int(state.get("offset") or 0)
        if state and (state.get("inode") != inode or file_stat.st_size < offset):
            offset = 0
            stats.rotation_detected = True
        elif not state and self.start_at_end:
            offset = int(file_stat.st_size)

        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                for line in handle:
                    if stats.read_lines >= max_lines:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    stats.read_lines += 1
                    try:
                        raw = parse_zenarmor_line(stripped)
                    except ValueError as exc:
                        stats.parser_errors += 1
                        stats.last_error = str(exc)
                        continue
                    try:
                        event = normalize_zenarmor_event(raw, self.sensor_name, self.remote_target, self.import_options)
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
            self._save_offset(inode, offset)
        except OSError as exc:
            stats.last_error = f"Zenarmor collector offset cannot be saved: {exc}"
        return events, stats

    def _load_offset(self) -> dict[str, Any]:
        if not self.offset_path.exists():
            return {}
        try:
            with self.offset_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            return {}
        return {}

    def _save_offset(self, inode: int | None, offset: int) -> None:
        tmp = self.offset_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump({"inode": inode, "offset": offset}, handle, sort_keys=True)
        tmp.replace(self.offset_path)


class ZenarmorSyslogCollector:
    def __init__(
        self,
        listen_address: str,
        port: int,
        *,
        allowed_senders: list[str] | None = None,
        sensor_name: str = "",
        remote_target: str = "",
        queue_limit: int = 10000,
        max_datagrams_per_run: int = 1000,
        import_options: Mapping[str, bool] | None = None,
    ) -> None:
        self.listen_address = listen_address
        self.port = int(port)
        self.allowed_senders = set(allowed_senders or [])
        self.sensor_name = sensor_name
        self.remote_target = remote_target
        self.queue_limit = queue_limit
        self.max_datagrams_per_run = max(1, int(max_datagrams_per_run))
        self.import_options = dict(import_options or {})
        self.socket: socket.socket | None = None
        self.seen_ids: set[str] = set()

    def close(self) -> None:
        if self.socket is None:
            return
        try:
            self.socket.close()
        finally:
            self.socket = None

    def read_once(self, max_datagrams: int | None = None) -> tuple[list[dict[str, Any]], ZenarmorStats]:
        stats = ZenarmorStats()
        try:
            sock = self._socket()
        except OSError as exc:
            stats.last_error = f"Zenarmor Syslog collector cannot bind {self.listen_address}:{self.port}: {exc}"
            return [], stats

        events: list[dict[str, Any]] = []
        limit = min(max_datagrams or self.max_datagrams_per_run, self.max_datagrams_per_run)
        for _ in range(limit):
            ready, _, _ = select.select([sock], [], [], 0)
            if not ready:
                break
            try:
                payload, address = sock.recvfrom(65535)
            except BlockingIOError:
                break
            except OSError as exc:
                stats.last_error = f"Zenarmor Syslog receive failed: {exc}"
                break
            sender = str(address[0])
            stats.read_datagrams += 1
            stats.read_lines += 1
            if self.allowed_senders and sender not in self.allowed_senders:
                stats.parser_errors += 1
                stats.last_error = f"Zenarmor Syslog sender is not allowed: {sender}"
                continue
            text = payload.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                raw = parse_zenarmor_line(text)
            except ValueError as exc:
                stats.parser_errors += 1
                stats.last_error = str(exc)
                continue
            try:
                event = normalize_zenarmor_event(raw, self.sensor_name, self.remote_target or sender, self.import_options)
            except ValueError as exc:
                stats.normalization_errors += 1
                stats.last_error = str(exc)
                continue
            if event is None:
                continue
            event_id = event["event_id"]
            if event_id in self.seen_ids:
                stats.duplicates += 1
                continue
            self.seen_ids.add(event_id)
            if len(self.seen_ids) > 50000:
                self.seen_ids = set(list(self.seen_ids)[-25000:])
            if len(events) >= self.queue_limit:
                stats.queue_drops += 1
                continue
            events.append(event)
            stats.accepted_events += 1
        return events, stats

    def _socket(self) -> socket.socket:
        if self.socket is not None:
            return self.socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind((self.listen_address, self.port))
        self.socket = sock
        return sock


def parse_zenarmor_line(line: str) -> dict[str, Any]:
    data_match = re.search(r"\bdata=(\{.*\})\s*$", line)
    if data_match:
        try:
            parsed = json.loads(data_match.group(1))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Zenarmor data JSON parse error: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Zenarmor data payload is not an object")
        prefix = line[:data_match.start()]
        for key, value in re.findall(r"([A-Za-z0-9_.-]+)=([^,\s]+)", prefix):
            parsed.setdefault(key, value.rstrip(","))
        return parsed

    json_start = line.find("{")
    if json_start >= 0:
        try:
            parsed = json.loads(line[json_start:])
        except json.JSONDecodeError as exc:
            raise ValueError(f"Zenarmor JSON parse error: {exc.msg}") from exc
        if isinstance(parsed, dict):
            return parsed
        raise ValueError("Zenarmor JSON line is not an object")

    pairs = dict(re.findall(r"([A-Za-z0-9_.-]+)=([^\s]+)", line))
    if pairs:
        return pairs
    raise ValueError("Zenarmor line is neither JSON nor key-value syslog")


def normalize_zenarmor_event(
    raw: Mapping[str, Any],
    sensor_name: str = "",
    remote_target: str = "",
    import_options: Mapping[str, bool] | None = None,
) -> dict[str, Any] | None:
    timestamp = _zenarmor_timestamp(_first(raw, "timestamp", "@timestamp", "time", "ts", "event_time", "start_time"))
    if not timestamp:
        raise ValueError("Zenarmor event has invalid timestamp")

    source_ip = valid_ip(_first(raw, "src_ip", "source_ip", "src", "client_ip", "local_ip", "ip_src_saddr", "source.ip"))
    destination_ip = valid_ip(_first(raw, "dst_ip", "dest_ip", "destination_ip", "dst", "server_ip", "remote_ip", "ip_dst_saddr", "destination.ip"))
    if not source_ip and not destination_ip:
        return None

    source_port = valid_port(_first(raw, "src_port", "source_port", "sport", "ip_src_port", "source.port"))
    destination_port = valid_port(_first(raw, "dst_port", "dest_port", "destination_port", "dport", "ip_dst_port", "destination.port"))
    protocol = str(_first(raw, "protocol", "proto", "transport_proto", "network.protocol") or "").upper() or None
    decision = _decision(raw)
    event_type = _event_type(raw, decision)
    bytes_out = _int(_first(raw, "bytes_out", "sent_bytes", "source.bytes", "src_nbytes", "output"))
    bytes_in = _int(_first(raw, "bytes_in", "received_bytes", "destination.bytes", "dst_nbytes", "input"))
    packet_count = _int(_first(raw, "packets", "packet_count", "network.packets"))
    if not packet_count:
        packet_count = _int(_first(raw, "src_npackets")) + _int(_first(raw, "dst_npackets"))

    metadata = {
        "event_source": "zenarmor",
        "sensor_name": sensor_name or None,
        "remote_target": remote_target or None,
        "application": _first(raw, "application", "app", "app_name", "application.name"),
        "application_category": _first(raw, "application_category", "app_category", "appcat", "application.category"),
        "web_category": _first(raw, "web_category", "category", "domain_categories", "url_category", "web.category"),
        "security_category": _first(raw, "security_category", "threat_category", "security.category"),
        "decision": decision or None,
        "policy_name": _first(raw, "policy", "policy_name", "policy.name"),
        "rule_name": _first(raw, "rule", "rule_name", "rule.name"),
        "domain": _first(raw, "domain", "host", "hostname", "dst_hostname", "query", "sni", "tls_sni", "server_name", "url.domain"),
        "url_path": _url_path(_first(raw, "url", "uri", "http.url")),
        "url": _safe_url(_first(raw, "url", "uri", "http.url")),
        "tls_sni": _first(raw, "tls_sni", "sni", "server_name", "tls.server_name"),
        "tls_version": _first(raw, "tls_version", "tls.version"),
        "tls_inspected": _first(raw, "tls_inspected", "tls_inspection", "ssl_inspected", "ssl_inspection", "tls.inspected"),
        "ja3": _first(raw, "ja3", "tls.ja3"),
        "ja4": _first(raw, "ja4", "tls.ja4"),
        "filename": _basename(_first(raw, "filename", "file_name", "file.name", "http.file.name")),
        "mime_type": _first(raw, "mime_type", "file_mime_type", "file.mime_type", "http.response.mime_type"),
        "file_size": _int(_first(raw, "file_size", "file.size", "http.file.size")),
        "md5": _first(raw, "md5", "file.md5", "hash.md5"),
        "sha1": _first(raw, "sha1", "file.sha1", "hash.sha1"),
        "sha256": _first(raw, "sha256", "file.sha256", "hash.sha256"),
        "file_verdict": _first(raw, "file_verdict", "file.verdict", "file_disposition", "file.disposition"),
        "sandbox_verdict": _first(raw, "sandbox_verdict", "sandbox.verdict", "sandbox_result", "sandbox.result"),
        "av_verdict": _first(raw, "av_verdict", "antivirus_verdict", "antivirus.verdict", "malware_verdict"),
        "email_protocol": _first(raw, "email_protocol", "mail_protocol", "mail.protocol"),
        "email_attachment": _first(raw, "email_attachment", "mail_attachment", "mail.attachment"),
        "device_id": _first(raw, "device_id", "device.id"),
        "device_name": _first(raw, "device_name", "device.name"),
        "device_os": _first(raw, "device_os", "device.os"),
        "device_vendor": _first(raw, "device_vendor", "device.vendor"),
        "session_id": _first(raw, "session_id", "session.id", "conn_id", "conn_uuid"),
        "connection_uuid": _first(raw, "conn_uuid"),
        "interface": _first(raw, "interface", "source.interface"),
        "vlan_id": _first(raw, "vlan", "vlanid"),
        "community_id": _first(raw, "community_id"),
        "user": _first(raw, "user", "username", "src_username", "user.name"),
        "asn": _first(raw, "asn", "destination.asn"),
        "country": _first(raw, "country", "destination.country"),
        "sase_event": _first(raw, "sase_event", "sase.event", "ztna_event"),
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "packet_count": packet_count,
        "threat_name": _first(raw, "threat", "threat_name", "signature", "alert.signature"),
        "indexes": _indexes(raw),
        "integration_notes": "exported_reporting_data_only",
    }
    metadata["byte_count"] = int(metadata["bytes_out"] or 0) + int(metadata["bytes_in"] or 0)
    metadata = _filter_metadata(metadata, import_options or {})
    metadata = {key: value for key, value in metadata.items() if value not in (None, "", [], {})}

    event = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "",
        "event_type": event_type,
        "timestamp": timestamp,
        "source": {"ip": source_ip, "port": source_port, "interface": _first(raw, "interface", "source.interface")},
        "destination": {"ip": destination_ip, "port": destination_port},
        "protocol": protocol,
        "direction": _traffic_direction(source_ip, destination_ip),
        "metadata": metadata,
        "raw_source": "zenarmor",
    }
    event["event_id"] = event_id_from(event)
    return event


def _event_type(raw: Mapping[str, Any], decision: str) -> str:
    if decision in {"block", "blocked", "deny", "denied", "drop", "dropped"}:
        return "drop"
    indexes = {item.lower() for item in _indexes(raw)}
    if "alert" in indexes:
        return "alert"
    if "dns" in indexes:
        return "dns"
    if "http" in indexes:
        return "http"
    if "tls" in indexes:
        return "tls"
    if _first(raw, "threat", "threat_name", "signature", "alert.signature"):
        return "alert"
    if _first(raw, "query", "qtype", "dns.question.name"):
        return "dns"
    if _first(raw, "tls_sni", "sni", "server_name", "tls.version", "tls_version"):
        return "tls"
    if _first(raw, "url", "uri", "host", "hostname", "web_category"):
        return "http"
    return "flow"


def _zenarmor_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return parse_timestamp(value)
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000
        return parse_timestamp(number)
    text = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", text):
        number = float(text)
        if number > 10_000_000_000:
            number /= 1000
        return parse_timestamp(number)
    return parse_timestamp(value)


def _decision(raw: Mapping[str, Any]) -> str:
    explicit = _first(raw, "decision", "action", "verdict", "policy_action", "event.action")
    blocked = _first(raw, "is_blocked", "blocked")
    if blocked not in (None, ""):
        text = str(blocked).strip().lower()
        if text in {"1", "true", "yes"}:
            return "blocked"
        if text in {"0", "false", "no"}:
            return "allowed"
    return str(explicit or "").strip().lower()


def _enabled(import_options: Mapping[str, bool], key: str) -> bool:
    return bool(import_options.get(key, True))


def _filter_metadata(metadata: dict[str, Any], import_options: Mapping[str, bool]) -> dict[str, Any]:
    if not import_options:
        return metadata
    filtered = dict(metadata)
    groups = {
        "import_applications": {"application", "application_category"},
        "import_categories": {"application_category", "web_category", "security_category"},
        "import_tls_metadata": {"tls_sni", "tls_version", "tls_inspected", "ja3", "ja4"},
        "import_session_context": {"session_id", "bytes_out", "bytes_in", "byte_count", "packet_count", "asn", "country"},
        "import_policy_actions": {"decision", "policy_name", "rule_name"},
        "import_device_context": {"device_id", "device_name", "user"},
        "import_security_events": {
            "security_category", "threat_name", "sase_event", "filename",
            "mime_type", "file_size", "md5", "sha1", "sha256",
            "file_verdict", "sandbox_verdict", "av_verdict",
            "email_protocol", "email_attachment",
        },
    }
    for option, keys in groups.items():
        if _enabled(import_options, option):
            continue
        for key in keys:
            filtered.pop(key, None)
    return filtered


def _first(raw: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
        if "." in key:
            value = _nested(raw, key.split("."))
            if value not in (None, ""):
                return value
    return None


def _nested(raw: Mapping[str, Any], keys: list[str]) -> Any:
    current: Any = raw
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            return None
        current = current[key]
    return current


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


def _safe_url(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    parsed = urlsplit(text)
    path = parsed.path or (text if text.startswith("/") else "")
    if not path:
        return None
    return path.split("?", 1)[0][:256]


def _basename(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).replace("\\", "/").rsplit("/", 1)[-1].strip()
    return text[:256] if text else None


def _indexes(raw: Mapping[str, Any]) -> list[str]:
    value = _first(raw, "index", "indexes", "report_index", "type")
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [item.strip() for item in str(value).split(",") if item.strip()]
    return []


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


def _int(value: Any) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0
