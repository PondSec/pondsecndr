"""Suricata EVE JSON normalizer."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from pondsec_ndr.schema import SUPPORTED_EVE_TYPES, empty_event, event_id_from, is_private_ip, parse_timestamp, valid_ip, valid_port


class NormalizationError(ValueError):
    """Raised when an EVE event cannot be represented safely."""


SENSITIVE_HTTP_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def _safe_queryless_url(value: Any) -> str | None:
    if not value:
        return None
    text = str(value)
    if "://" not in text:
        text = "http://placeholder.local" + (text if text.startswith("/") else "/" + text)
    parsed = urlsplit(text)
    path = parsed.path or "/"
    if len(path) > 256:
        path = path[:256]
    return path


def _direction(src_ip: str | None, dst_ip: str | None) -> str:
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)
    if src_private and not dst_private:
        return "egress"
    if not src_private and dst_private:
        return "ingress"
    if src_private and dst_private:
        return "internal"
    if src_ip or dst_ip:
        return "external"
    return "unknown"


def _flow_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    flow = raw.get("flow") or {}
    return {
        "app_proto": raw.get("app_proto"),
        "flow_id": raw.get("flow_id"),
        "flow_state": flow.get("state"),
        "flow_reason": flow.get("reason"),
        "duration": flow.get("age"),
        "packet_count": (flow.get("pkts_toserver") or 0) + (flow.get("pkts_toclient") or 0),
        "bytes_in": flow.get("bytes_toclient") or 0,
        "bytes_out": flow.get("bytes_toserver") or 0,
        "byte_count": (flow.get("bytes_toclient") or 0) + (flow.get("bytes_toserver") or 0),
    }


def _dns_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    dns = raw.get("dns") or {}
    answers = dns.get("answers") or []
    return {
        "rrname": dns.get("rrname") or dns.get("query"),
        "rrtype": dns.get("rrtype"),
        "rcode": dns.get("rcode"),
        "answers_count": len(answers) if isinstance(answers, list) else 0,
        "tx_id": dns.get("tx_id"),
    }


def _tls_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    tls = raw.get("tls") or {}
    return {
        "sni": tls.get("sni"),
        "subject": tls.get("subject"),
        "issuerdn": tls.get("issuerdn"),
        "fingerprint": tls.get("fingerprint") or tls.get("ja3") or tls.get("ja3s"),
        "version": tls.get("version"),
        "notbefore": tls.get("notbefore"),
        "notafter": tls.get("notafter"),
    }


def _http_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    http = raw.get("http") or {}
    headers = {}
    for key, value in (http.get("headers") or {}).items() if isinstance(http.get("headers"), dict) else []:
        if str(key).lower() not in SENSITIVE_HTTP_HEADERS:
            headers[key] = value
    return {
        "hostname": http.get("hostname"),
        "http_method": http.get("http_method"),
        "url_path": _safe_queryless_url(http.get("url")),
        "status": http.get("status"),
        "protocol": http.get("protocol"),
        "length": http.get("length"),
        "headers": headers,
        "has_redacted_fields": any(field in http for field in ("http_user_agent", "http_refer", "cookies")),
    }


def _alert_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    alert = raw.get("alert") or {}
    return {
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "gid": alert.get("gid"),
        "rev": alert.get("rev"),
        "action": alert.get("action"),
    }


def _drop_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    drop = raw.get("drop") or {}
    metadata = _alert_metadata(raw)
    metadata.update({
        "drop_reason": drop.get("reason"),
        "packet_length": drop.get("len"),
        "tcp_syn": drop.get("syn"),
        "tcp_ack": drop.get("ack"),
        "tcp_rst": drop.get("rst"),
        "tcp_fin": drop.get("fin"),
    })
    return metadata


def normalize_eve(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise NormalizationError("event is not an object")
    event_type = str(raw.get("event_type") or "flow")
    if event_type not in SUPPORTED_EVE_TYPES:
        raise NormalizationError(f"unsupported event type: {event_type}")
    timestamp = parse_timestamp(raw.get("timestamp"))
    if timestamp is None:
        raise NormalizationError("invalid timestamp")
    src_ip = valid_ip(raw.get("src_ip"))
    dst_ip = valid_ip(raw.get("dest_ip"))
    if not src_ip and event_type not in {"stats"}:
        raise NormalizationError("invalid source ip")
    if not dst_ip and event_type not in {"stats"}:
        raise NormalizationError("invalid destination ip")
    event = empty_event(event_type, timestamp)
    event["source"] = {
        "ip": src_ip,
        "port": valid_port(raw.get("src_port")),
        "interface": raw.get("in_iface") or raw.get("iface"),
    }
    event["destination"] = {"ip": dst_ip, "port": valid_port(raw.get("dest_port"))}
    event["protocol"] = raw.get("proto") or raw.get("app_proto")
    event["direction"] = _direction(src_ip, dst_ip)

    metadata: dict[str, Any] = {"event_source": "suricata", "community_id": raw.get("community_id")}
    if event_type == "flow":
        metadata.update(_flow_metadata(raw))
    elif event_type == "dns":
        metadata.update(_dns_metadata(raw))
    elif event_type == "tls":
        metadata.update(_tls_metadata(raw))
    elif event_type == "http":
        metadata.update(_http_metadata(raw))
    elif event_type == "alert":
        metadata.update(_alert_metadata(raw))
    elif event_type == "drop":
        metadata.update(_drop_metadata(raw))
    elif event_type == "fileinfo":
        info = raw.get("fileinfo") or {}
        metadata.update({"filename_seen": bool(info.get("filename")), "size": info.get("size"), "state": info.get("state")})
    elif event_type == "anomaly":
        anomaly = raw.get("anomaly") or {}
        metadata.update({"type": anomaly.get("type"), "event": anomaly.get("event"), "layer": anomaly.get("layer")})
    elif event_type == "stats":
        stats = raw.get("stats") or {}
        metadata.update({"uptime": stats.get("uptime"), "capture": stats.get("capture", {})})

    event["metadata"] = {key: value for key, value in metadata.items() if value is not None}
    event["event_id"] = event_id_from(event)
    return event
