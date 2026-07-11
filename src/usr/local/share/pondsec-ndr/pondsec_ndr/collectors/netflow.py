"""NetFlow v5/v9 and IPFIX collector foundation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import select
import socket
import struct
from typing import Any

from pondsec_ndr.schema import EVENT_SCHEMA_VERSION, event_id_from


NETFLOW_V5_HEADER = struct.Struct("!HHIIIIBBH")
NETFLOW_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")
NETFLOW_V9_HEADER = struct.Struct("!HHIIII")
IPFIX_HEADER = struct.Struct("!HHIII")


@dataclass(slots=True)
class NetFlowStats:
    read_datagrams: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    template_errors: int = 0
    sequence_gaps: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    bad_exporters: int = 0
    templates_seen: int = 0
    last_error: str | None = None
    exporters: dict[str, dict[str, Any]] = field(default_factory=dict)


class NetFlowCollector:
    def __init__(
        self,
        listen_address: str,
        port: int,
        *,
        allowed_exporters: list[str] | None = None,
        sampling_rate: int = 1,
        queue_limit: int = 10000,
        max_datagrams_per_run: int = 1000,
    ) -> None:
        self.listen_address = listen_address
        self.port = port
        self.allowed_exporters = allowed_exporters or []
        self.sampling_rate = max(1, sampling_rate)
        self.queue_limit = queue_limit
        self.max_datagrams_per_run = max_datagrams_per_run
        self.socket: socket.socket | None = None
        self.last_sequences: dict[str, int] = {}
        self.templates: dict[tuple[str, int, int], dict[str, Any]] = {}
        self.seen_flow_ids: set[str] = set()

    def close(self) -> None:
        if self.socket is None:
            return
        try:
            self.socket.close()
        finally:
            self.socket = None

    def read_once(self, max_datagrams: int | None = None) -> tuple[list[dict[str, Any]], NetFlowStats]:
        stats = NetFlowStats()
        try:
            sock = self._socket()
        except OSError as exc:
            stats.last_error = f"NetFlow collector cannot bind {self.listen_address}:{self.port}: {exc}"
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
                stats.last_error = f"NetFlow collector receive failed: {exc}"
                break
            exporter_ip = str(address[0])
            parsed, packet_stats = self.parse_datagram(payload, exporter_ip)
            self._merge_stats(stats, exporter_ip, packet_stats)
            for event in parsed:
                if len(events) >= self.queue_limit:
                    stats.queue_drops += 1
                    continue
                events.append(event)
        return events, stats

    def parse_datagram(self, payload: bytes, exporter_ip: str) -> tuple[list[dict[str, Any]], NetFlowStats]:
        stats = NetFlowStats(read_datagrams=1)
        if not self._exporter_allowed(exporter_ip):
            stats.bad_exporters = 1
            stats.last_error = f"NetFlow exporter is not allowed: {exporter_ip}"
            return [], stats
        if len(payload) < 2:
            stats.parser_errors = 1
            stats.last_error = "NetFlow datagram too short"
            return [], stats
        version = int.from_bytes(payload[:2], "big")
        if version == 5:
            return self._parse_v5(payload, exporter_ip, stats)
        if version == 9:
            return self._parse_v9(payload, exporter_ip, stats)
        if version == 10:
            return self._parse_ipfix(payload, exporter_ip, stats)
        stats.parser_errors = 1
        stats.last_error = f"unsupported flow export version: {version}"
        return [], stats

    def _socket(self) -> socket.socket:
        if self.socket is not None:
            return self.socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind((self.listen_address, self.port))
        self.socket = sock
        return sock

    def _parse_v5(self, payload: bytes, exporter_ip: str, stats: NetFlowStats) -> tuple[list[dict[str, Any]], NetFlowStats]:
        if len(payload) < NETFLOW_V5_HEADER.size:
            stats.parser_errors = 1
            stats.last_error = "NetFlow v5 header is incomplete"
            return [], stats
        version, count, sys_uptime, unix_secs, unix_nsecs, sequence, engine_type, engine_id, sampling = NETFLOW_V5_HEADER.unpack_from(payload)
        del version, sys_uptime, unix_nsecs, engine_type, engine_id
        expected = NETFLOW_V5_HEADER.size + (count * NETFLOW_V5_RECORD.size)
        if count < 1 or len(payload) < expected:
            stats.parser_errors = 1
            stats.last_error = "NetFlow v5 datagram has invalid record count or length"
            return [], stats
        self._track_sequence(exporter_ip, sequence, count, stats)
        timestamp = datetime.fromtimestamp(unix_secs, tz=timezone.utc).isoformat()
        sampling_interval = sampling & 0x3FFF
        effective_sampling = max(1, sampling_interval or self.sampling_rate)
        events = []
        offset = NETFLOW_V5_HEADER.size
        for index in range(count):
            values = NETFLOW_V5_RECORD.unpack_from(payload, offset)
            offset += NETFLOW_V5_RECORD.size
            event = self._event_from_v5_record(values, exporter_ip, sequence, index, timestamp, effective_sampling)
            flow_id = event["event_id"]
            if flow_id in self.seen_flow_ids:
                stats.duplicates += 1
                continue
            self.seen_flow_ids.add(flow_id)
            if len(self.seen_flow_ids) > 50000:
                self.seen_flow_ids = set(list(self.seen_flow_ids)[-25000:])
            events.append(event)
            stats.accepted_events += 1
        return events, stats

    def _parse_v9(self, payload: bytes, exporter_ip: str, stats: NetFlowStats) -> tuple[list[dict[str, Any]], NetFlowStats]:
        if len(payload) < NETFLOW_V9_HEADER.size:
            stats.parser_errors = 1
            stats.last_error = "NetFlow v9 header is incomplete"
            return [], stats
        _, count, _, _, sequence, source_id = NETFLOW_V9_HEADER.unpack_from(payload)
        self._track_sequence(exporter_ip, sequence, count, stats)
        self._inspect_template_sets(payload[NETFLOW_V9_HEADER.size :], exporter_ip, source_id, stats, version=9)
        return [], stats

    def _parse_ipfix(self, payload: bytes, exporter_ip: str, stats: NetFlowStats) -> tuple[list[dict[str, Any]], NetFlowStats]:
        if len(payload) < IPFIX_HEADER.size:
            stats.parser_errors = 1
            stats.last_error = "IPFIX header is incomplete"
            return [], stats
        _, length, _, sequence, domain_id = IPFIX_HEADER.unpack_from(payload)
        if len(payload) < length:
            stats.parser_errors = 1
            stats.last_error = "IPFIX datagram is shorter than declared length"
            return [], stats
        self._track_sequence(exporter_ip, sequence, 0, stats)
        self._inspect_template_sets(payload[IPFIX_HEADER.size : length], exporter_ip, domain_id, stats, version=10)
        return [], stats

    def _inspect_template_sets(
        self,
        payload: bytes,
        exporter_ip: str,
        observation_domain: int,
        stats: NetFlowStats,
        *,
        version: int,
    ) -> None:
        offset = 0
        template_set_ids = {0, 1} if version == 9 else {2, 3}
        while offset + 4 <= len(payload):
            set_id, length = struct.unpack_from("!HH", payload, offset)
            if length < 4 or offset + length > len(payload):
                stats.template_errors += 1
                stats.last_error = "flow template set has invalid length"
                return
            body = payload[offset + 4 : offset + length]
            if set_id in template_set_ids:
                seen = self._store_template_records(body, exporter_ip, observation_domain, stats)
                stats.templates_seen += seen
            elif set_id > 255:
                key = (exporter_ip, observation_domain, set_id)
                if key not in self.templates:
                    stats.template_errors += 1
                    stats.last_error = f"flow data set has no known template: {set_id}"
            offset += length

    def _store_template_records(self, body: bytes, exporter_ip: str, observation_domain: int, stats: NetFlowStats) -> int:
        offset = 0
        seen = 0
        while offset + 4 <= len(body):
            template_id, field_count = struct.unpack_from("!HH", body, offset)
            offset += 4
            field_bytes = field_count * 4
            if field_count < 1 or offset + field_bytes > len(body):
                stats.template_errors += 1
                stats.last_error = "flow template record is incomplete"
                return seen
            fields = []
            for _ in range(field_count):
                field_type, field_length = struct.unpack_from("!HH", body, offset)
                fields.append({"type": field_type, "length": field_length})
                offset += 4
            self.templates[(exporter_ip, observation_domain, template_id)] = {"fields": fields}
            seen += 1
        return seen

    def _event_from_v5_record(
        self,
        values: tuple[Any, ...],
        exporter_ip: str,
        sequence: int,
        record_index: int,
        timestamp: str,
        sampling: int,
    ) -> dict[str, Any]:
        (
            srcaddr,
            dstaddr,
            nexthop,
            input_snmp,
            output_snmp,
            packets,
            octets,
            first_seen,
            last_seen,
            srcport,
            dstport,
            pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            pad2,
        ) = values
        del nexthop, pad1, pad2
        source_ip = str(ipaddress.ip_address(srcaddr))
        destination_ip = str(ipaddress.ip_address(dstaddr))
        scaled_packets = int(packets) * sampling
        scaled_octets = int(octets) * sampling
        metadata = {
            "event_source": "netflow",
            "flow_version": 5,
            "exporter_ip": exporter_ip,
            "sequence": sequence,
            "record_index": record_index,
            "input_snmp": input_snmp,
            "output_snmp": output_snmp,
            "packet_count": scaled_packets,
            "byte_count": scaled_octets,
            "bytes_out": scaled_octets if is_private_to_external(source_ip, destination_ip) else 0,
            "bytes_in": scaled_octets if is_external_to_private(source_ip, destination_ip) else 0,
            "tcp_flags": tcp_flags,
            "protocol_number": protocol,
            "tos": tos,
            "src_as": src_as,
            "dst_as": dst_as,
            "src_mask": src_mask,
            "dst_mask": dst_mask,
            "first_switched": first_seen,
            "last_switched": last_seen,
            "sampling_rate": sampling,
        }
        event = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_id": "",
            "event_type": "flow",
            "timestamp": timestamp,
            "source": {"ip": source_ip, "port": int(srcport), "interface": str(input_snmp) if input_snmp else None},
            "destination": {"ip": destination_ip, "port": int(dstport)},
            "protocol": protocol_name(protocol),
            "direction": traffic_direction(source_ip, destination_ip),
            "metadata": metadata,
            "raw_source": "netflow",
        }
        event["event_id"] = event_id_from(event)
        return event

    def _track_sequence(self, exporter_ip: str, sequence: int, count: int, stats: NetFlowStats) -> None:
        expected = self.last_sequences.get(exporter_ip)
        if expected is not None:
            if sequence < expected:
                stats.duplicates += 1
            elif sequence > expected:
                stats.sequence_gaps += sequence - expected
        self.last_sequences[exporter_ip] = sequence + max(1, count)

    def _exporter_allowed(self, exporter_ip: str) -> bool:
        if not self.allowed_exporters:
            return True
        address = ipaddress.ip_address(exporter_ip)
        for value in self.allowed_exporters:
            try:
                if "/" in value:
                    if address in ipaddress.ip_network(value, strict=False):
                        return True
                elif address == ipaddress.ip_address(value):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _merge_stats(target: NetFlowStats, exporter_ip: str, source: NetFlowStats) -> None:
        target.read_datagrams += source.read_datagrams
        target.accepted_events += source.accepted_events
        target.parser_errors += source.parser_errors
        target.template_errors += source.template_errors
        target.sequence_gaps += source.sequence_gaps
        target.duplicates += source.duplicates
        target.queue_drops += source.queue_drops
        target.bad_exporters += source.bad_exporters
        target.templates_seen += source.templates_seen
        if source.last_error:
            target.last_error = source.last_error
        target.exporters[exporter_ip] = {
            "accepted_events": source.accepted_events,
            "parser_errors": source.parser_errors,
            "template_errors": source.template_errors,
            "sequence_gaps": source.sequence_gaps,
            "duplicates": source.duplicates,
            "bad_exporters": source.bad_exporters,
            "templates_seen": source.templates_seen,
            "last_error": source.last_error,
        }


def traffic_direction(src_ip: str | None, dst_ip: str | None) -> str:
    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)
    if src_private and dst_private:
        return "internal"
    if src_private and not dst_private:
        return "egress"
    if not src_private and dst_private:
        return "ingress"
    return "unknown"


def is_private_to_external(src_ip: str, dst_ip: str) -> bool:
    return _is_private(src_ip) and not _is_private(dst_ip)


def is_external_to_private(src_ip: str, dst_ip: str) -> bool:
    return not _is_private(src_ip) and _is_private(dst_ip)


def _is_private(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def protocol_name(number: int) -> str | None:
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(int(number), str(number) if number else None)
