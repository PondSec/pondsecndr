"""DNS sinkhole response helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
from tempfile import NamedTemporaryFile
from typing import Callable


DEFAULT_SINKHOLE_HOSTS_PATH = os.environ.get(
    "PONDSEC_NDR_DNS_SINKHOLE_HOSTS",
    "/var/db/pondsec-ndr/dns-sinkhole.hosts",
)
DEFAULT_SINKHOLE_ADDRESS = os.environ.get("PONDSEC_NDR_DNS_SINKHOLE_ADDRESS", "0.0.0.0")
SINKHOLE_MARKER = "# pondsec-ndr-sinkhole"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{1,62}$")


class SinkholeDenied(ValueError):
    """Raised when a DNS sinkhole operation is unsafe."""


def normalize_domain(value: str) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or "/" in text or "\\" in text or "@" in text:
        raise SinkholeDenied("invalid domain")
    if text.startswith("*."):
        text = text[2:]
    if not DOMAIN_RE.fullmatch(text):
        raise SinkholeDenied("invalid domain")
    return text


@dataclass(slots=True)
class DnsSinkholeResult:
    action: str
    domain: str
    hosts_path: str
    changed: bool
    reload_returncode: int | None
    reload_stdout: str
    reload_stderr: str

    @property
    def ok(self) -> bool:
        return self.reload_returncode in (None, 0)

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "domain": self.domain,
            "hosts_path": self.hosts_path,
            "changed": self.changed,
            "reload_returncode": self.reload_returncode,
            "reload_stdout": self.reload_stdout,
            "reload_stderr": self.reload_stderr,
            "ok": self.ok,
        }


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class DnsmasqSinkholeEnforcer:
    def __init__(
        self,
        hosts_path: str | Path = DEFAULT_SINKHOLE_HOSTS_PATH,
        sinkhole_address: str = DEFAULT_SINKHOLE_ADDRESS,
        runner: Runner | None = None,
        reload_command: list[str] | None = None,
        reload_enabled: bool | None = None,
    ) -> None:
        self.hosts_path = Path(hosts_path)
        self.sinkhole_address = sinkhole_address
        self.runner = runner or self._run
        self.reload_command = reload_command or ["/usr/local/sbin/configctl", "dnsmasq", "restart"]
        self.reload_enabled = bool(os.environ.get("PONDSEC_NDR_DNS_RELOAD")) if reload_enabled is None else reload_enabled

    def add(self, domain: str) -> DnsSinkholeResult:
        domain = normalize_domain(domain)
        domains = set(self.active_domains())
        before = set(domains)
        domains.add(domain)
        changed = domains != before
        if changed:
            self._write_domains(sorted(domains))
        return self._result("add", domain, changed)

    def delete(self, domain: str) -> DnsSinkholeResult:
        domain = normalize_domain(domain)
        domains = set(self.active_domains())
        before = set(domains)
        domains.discard(domain)
        changed = domains != before
        if changed:
            self._write_domains(sorted(domains))
        return self._result("delete", domain, changed)

    def sync(self, domains: list[str]) -> DnsSinkholeResult:
        normalized = sorted({normalize_domain(domain) for domain in domains})
        before = self.active_domains()
        changed = normalized != before
        if changed:
            self._write_domains(normalized)
        domain = ",".join(normalized[:3]) if normalized else "-"
        return self._result("sync", domain, changed)

    def active_domains(self) -> list[str]:
        if not self.hosts_path.exists():
            return []
        domains = []
        try:
            lines = self.hosts_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            if SINKHOLE_MARKER not in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    domains.append(normalize_domain(parts[1]))
                except SinkholeDenied:
                    continue
        return sorted(set(domains))

    def _write_domains(self, domains: list[str]) -> None:
        self.hosts_path.parent.mkdir(parents=True, exist_ok=True)
        unmanaged = []
        if self.hosts_path.exists():
            try:
                unmanaged = [
                    line for line in self.hosts_path.read_text(encoding="utf-8").splitlines()
                    if SINKHOLE_MARKER not in line
                ]
            except OSError:
                unmanaged = []
        managed = [f"{self.sinkhole_address} {domain} {SINKHOLE_MARKER}" for domain in domains]
        content = "\n".join(unmanaged + managed).strip()
        if content:
            content += "\n"
        with NamedTemporaryFile("w", encoding="utf-8", dir=str(self.hosts_path.parent), delete=False) as handle:
            handle.write(content)
            temp_path = Path(handle.name)
        temp_path.replace(self.hosts_path)

    def _result(self, action: str, domain: str, changed: bool) -> DnsSinkholeResult:
        reload_returncode = None
        stdout = ""
        stderr = ""
        if changed and self.reload_enabled:
            try:
                completed = self.runner(self.reload_command)
                reload_returncode = completed.returncode
                stdout = (completed.stdout or "").strip()
                stderr = (completed.stderr or "").strip()
            except OSError as exc:
                reload_returncode = 127
                stderr = str(exc)
        return DnsSinkholeResult(action, domain, str(self.hosts_path), changed, reload_returncode, stdout, stderr)

    @staticmethod
    def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=20)
