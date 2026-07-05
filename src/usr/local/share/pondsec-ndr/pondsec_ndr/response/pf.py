"""PF table enforcement helpers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import subprocess
from typing import Callable

DEFAULT_BLOCK_TABLE = os.environ.get("PONDSEC_NDR_PF_BLOCK_TABLE", "virusprot")


@dataclass(slots=True)
class PFResult:
    table: str
    target: str
    command: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def as_dict(self) -> dict[str, object]:
        return {
            "table": self.table,
            "target": self.target,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "ok": self.ok,
        }


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class PFTableEnforcer:
    def __init__(self, table: str = DEFAULT_BLOCK_TABLE, runner: Runner | None = None, allow_configctl: bool = True) -> None:
        self.table = table
        self.runner = runner or self._run
        self.allow_configctl = allow_configctl

    def add(self, target: str) -> PFResult:
        return self._table_op("add", target)

    def delete(self, target: str) -> PFResult:
        return self._table_op("delete", target)

    def test(self, target: str) -> PFResult:
        return self._table_op("test", target)

    def rule_present(self) -> bool:
        try:
            result = self.runner(["/sbin/pfctl", "-sr"])
        except OSError:
            return self._configctl_rule_present()
        needle = f"<{self.table}>"
        if result.returncode == 0:
            return needle in result.stdout and "block" in result.stdout
        if self._should_fallback(result):
            return self._configctl_rule_present()
        return False

    def _table_op(self, operation: str, target: str) -> PFResult:
        command = ["/sbin/pfctl", "-t", self.table, "-T", operation, target]
        try:
            result = self.runner(command)
        except OSError as exc:
            return PFResult(self.table, target, operation, 127, "", str(exc))
        pf_result = PFResult(self.table, target, operation, result.returncode, result.stdout.strip(), result.stderr.strip())
        if pf_result.ok or not self._should_fallback(result):
            return pf_result
        return self._configctl_table_op(operation, target)

    def _should_fallback(self, result: subprocess.CompletedProcess[str]) -> bool:
        if not self.allow_configctl or os.environ.get("PONDSEC_NDR_SKIP_CONFIGCTL"):
            return False
        output = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        return "permission denied" in output or "operation not permitted" in output

    def _configctl_table_op(self, operation: str, target: str) -> PFResult:
        command = ["/usr/local/sbin/configctl", "pondsecndr", "pf_table", operation, target]
        try:
            result = self.runner(command)
        except OSError as exc:
            return PFResult(self.table, target, f"configctl:{operation}", 127, "", str(exc))
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return PFResult(self.table, target, f"configctl:{operation}", _configctl_returncode(result.returncode, stdout), stdout, stderr)
        pf_payload = payload.get("pf_result") if isinstance(payload, dict) else None
        if not isinstance(pf_payload, dict):
            return PFResult(self.table, target, f"configctl:{operation}", _configctl_returncode(result.returncode, stdout), stdout, stderr)
        return PFResult(
            str(pf_payload.get("table") or self.table),
            str(pf_payload.get("target") or target),
            f"configctl:{pf_payload.get('command') or operation}",
            int(pf_payload.get("returncode") or 0),
            str(pf_payload.get("stdout") or ""),
            str(pf_payload.get("stderr") or ""),
        )

    def _configctl_rule_present(self) -> bool:
        if not self.allow_configctl or os.environ.get("PONDSEC_NDR_SKIP_CONFIGCTL"):
            return False
        command = ["/usr/local/sbin/configctl", "pondsecndr", "pf_rule_present"]
        try:
            result = self.runner(command)
        except OSError:
            return False
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            return False
        return bool(isinstance(payload, dict) and payload.get("rule_present"))

    @staticmethod
    def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)


def _configctl_returncode(returncode: int, stdout: str) -> int:
    if returncode != 0:
        return returncode
    if "execute error" in stdout.lower():
        return 1
    return returncode
