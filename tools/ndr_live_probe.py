#!/usr/bin/env python3
"""Harmless live network-path probes for PondSec NDR validation."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import socket
import ssl
import time
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tcp_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            status = "connected"
            error = None
    except OSError as exc:
        status = "failed"
        error = exc.__class__.__name__
    return {
        "target": host,
        "port": port,
        "status": status,
        "error": error,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def _dns_query(name: str, resolver: str | None, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    if resolver:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query = _dns_packet(name)
        try:
            sock.sendto(query, (resolver, 53))
            sock.recvfrom(512)
            status = "answered"
            error = None
        except OSError as exc:
            status = "failed"
            error = exc.__class__.__name__
        finally:
            sock.close()
    else:
        try:
            socket.getaddrinfo(name, 80)
            status = "answered"
            error = None
        except OSError as exc:
            status = "failed"
            error = exc.__class__.__name__
    return {
        "query": name,
        "resolver": resolver or "system",
        "status": status,
        "error": error,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def _dns_packet(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii", "ignore") for label in labels) + b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"


def _tls_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                status = "connected"
                error = None
                protocol = tls.version()
                subject = cert.get("subject") if isinstance(cert, dict) else None
    except OSError as exc:
        status = "failed"
        error = exc.__class__.__name__
        protocol = None
        subject = None
    return {
        "target": host,
        "port": port,
        "status": status,
        "error": error,
        "protocol": protocol,
        "subject": subject,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    results: dict[str, Any] = {
        "status": "ok",
        "started_at": _now(),
        "source_note": "Run this with the VPN disconnected for non-admin-path validation.",
        "safety": {
            "credentials_used": False,
            "exploit_code_used": False,
            "destructive_payload_used": False,
        },
        "tcp_fanout": [],
        "auth_pressure": [],
        "dns_entropy": [],
        "tls": [],
        "beaconing": [],
    }

    for index, port in enumerate(args.scan_ports):
        results["tcp_fanout"].append(_tcp_probe(args.scan_target, port, args.timeout))
        time.sleep(args.delay)

    for index in range(args.auth_attempts):
        port = args.auth_ports[index % len(args.auth_ports)]
        results["auth_pressure"].append(_tcp_probe(args.auth_target, port, args.timeout))
        time.sleep(args.delay)

    for index in range(args.dns_queries):
        label = f"q9w8e7r6t5y4u3i2o1p0asdfghjklzxcvbnm{index:02d}"
        results["dns_entropy"].append(_dns_query(f"{label}.{args.dns_suffix}", args.resolver, args.timeout))
        time.sleep(args.delay)

    for host in args.tls_hosts:
        results["tls"].append(_tls_probe(host, 443, args.timeout))
        time.sleep(args.delay)

    for index in range(args.beacon_count):
        results["beaconing"].append(_tcp_probe(args.beacon_target, args.beacon_port, args.timeout))
        time.sleep(args.beacon_interval)

    results["finished_at"] = _now()
    return results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run harmless live PondSec NDR network-path probes.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--scan-target", default="192.168.10.5")
    parser.add_argument("--scan-ports", type=int, nargs="+", default=[20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993, 3389, 5900])
    parser.add_argument("--auth-target", default="192.168.10.5")
    parser.add_argument("--auth-ports", type=int, nargs="+", default=[22, 445, 3389, 5985])
    parser.add_argument("--auth-attempts", type=int, default=16)
    parser.add_argument("--resolver", default=None)
    parser.add_argument("--dns-suffix", default="validation.pondsec.test")
    parser.add_argument("--dns-queries", type=int, default=12)
    parser.add_argument("--tls-hosts", nargs="+", default=["example.com", "cloudflare.com", "github.com", "python.org", "wikipedia.org", "iana.org", "ietf.org", "mozilla.org"])
    parser.add_argument("--beacon-target", default="1.1.1.1")
    parser.add_argument("--beacon-port", type=int, default=443)
    parser.add_argument("--beacon-count", type=int, default=6)
    parser.add_argument("--beacon-interval", type=float, default=15.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--delay", type=float, default=0.05)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = run_probe(args)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    else:
        print(result["status"])
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
