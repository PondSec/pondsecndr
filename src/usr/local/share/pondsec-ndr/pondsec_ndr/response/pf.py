"""PF table enforcement helpers."""

from __future__ import annotations

from dataclasses import dataclass
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
    def __init__(self, table: str = DEFAULT_BLOCK_TABLE, runner: Runner | None = None) -> None:
        self.table = table
        self.runner = runner or self._run

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
            return False
        needle = f"<{self.table}>"
        return result.returncode == 0 and needle in result.stdout and "block" in result.stdout

    def _table_op(self, operation: str, target: str) -> PFResult:
        command = ["/sbin/pfctl", "-t", self.table, "-T", operation, target]
        try:
            result = self.runner(command)
        except OSError as exc:
            return PFResult(self.table, target, operation, 127, "", str(exc))
        return PFResult(self.table, target, operation, result.returncode, result.stdout.strip(), result.stderr.strip())

    @staticmethod
    def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
