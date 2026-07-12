"""Small platform helpers for local runtime context."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess


def discover_local_interface_ips(timeout_seconds: float = 2.0) -> set[str]:
    """Return IP addresses assigned to local interfaces.

    OPNsense exposes interface addresses through ifconfig. A Linux fallback is
    included so unit tests and development hosts behave the same way.
    """

    for command in (("ifconfig",), ("ip", "-o", "addr", "show")):
        if not shutil.which(command[0]):
            continue
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            addresses = _extract_interface_ips(result.stdout)
            if addresses:
                return addresses
    return set()


def _extract_interface_ips(output: str) -> set[str]:
    addresses: set[str] = set()
    for match in re.finditer(r"\binet6?\s+([0-9a-fA-F:.]+)(?:/\d+)?", output):
        value = match.group(1).split("%", 1)[0]
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return addresses
