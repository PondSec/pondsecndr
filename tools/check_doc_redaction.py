#!/usr/bin/env python3
"""Fail when public docs contain live network identifiers."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import re
import sys


DEFAULT_PATHS = ("docs", "reports/external-validation")
TEXT_SUFFIXES = {".md", ".markdown", ".txt"}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INTERNAL_HOST_RE = re.compile(r"\b[A-Za-z0-9-]+\.internal\b", re.IGNORECASE)
SENSITIVE_DOMAIN_RE = re.compile(r"\b(?:proxy\.)?pondsec\.com\b", re.IGNORECASE)
ALLOWED_IP_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=list(DEFAULT_PATHS), help="Files or directories to scan")
    args = parser.parse_args()
    findings = []
    for path_arg in args.paths:
        path = Path(path_arg)
        for file_path in _iter_text_files(path):
            findings.extend(_find_sensitive_tokens(file_path))
    if findings:
        for file_path, line_no, token, reason in findings:
            print(f"{file_path}:{line_no}: {reason}: {token}")
        return 1
    print("redaction check passed")
    return 0


def _iter_text_files(path: Path):
    if path.is_file():
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path
        return
    if not path.exists():
        return
    for file_path in sorted(path.rglob("*")):
        if file_path.is_file() and file_path.suffix.lower() in TEXT_SUFFIXES:
            yield file_path


def _find_sensitive_tokens(file_path: Path) -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []
    text = file_path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in IP_RE.finditer(line):
            token = match.group(0)
            if _is_allowed_example_ip(token):
                continue
            findings.append((file_path, line_no, token, "non-anonymized IP address"))
        for match in INTERNAL_HOST_RE.finditer(line):
            findings.append((file_path, line_no, match.group(0), "internal hostname"))
        for match in SENSITIVE_DOMAIN_RE.finditer(line):
            findings.append((file_path, line_no, match.group(0), "live domain"))
    return findings


def _is_allowed_example_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return any(address in network for network in ALLOWED_IP_RANGES)


if __name__ == "__main__":
    sys.exit(main())
