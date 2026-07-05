"""Suricata EVE JSON collector with rotation-aware offsets."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any

from pondsec_ndr.normalizers.suricata import NormalizationError, normalize_eve


@dataclass(slots=True)
class CollectorStats:
    read_lines: int = 0
    accepted_events: int = 0
    parser_errors: int = 0
    normalization_errors: int = 0
    duplicates: int = 0
    queue_drops: int = 0
    rotation_detected: bool = False
    last_error: str | None = None


class EveCollector:
    def __init__(self, eve_path: Path, offset_path: Path, queue_limit: int = 10000) -> None:
        self.eve_path = eve_path
        self.offset_path = offset_path
        self.queue_limit = queue_limit
        self.offset_path.parent.mkdir(parents=True, exist_ok=True)

    def _load_offset(self) -> dict[str, Any]:
        if not self.offset_path.exists():
            return {"inode": None, "offset": 0}
        try:
            with self.offset_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except (OSError, json.JSONDecodeError):
            return {"inode": None, "offset": 0}
        return {"inode": None, "offset": 0}

    def _save_offset(self, inode: int | None, offset: int) -> None:
        tmp = self.offset_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump({"inode": inode, "offset": offset}, handle, sort_keys=True)
        tmp.replace(self.offset_path)

    def read_once(self, max_lines: int = 1000) -> tuple[list[dict[str, Any]], CollectorStats]:
        stats = CollectorStats()
        if not self.eve_path.exists():
            stats.last_error = f"EVE file does not exist: {self.eve_path}"
            return [], stats

        state = self._load_offset()
        file_stat = self.eve_path.stat()
        inode = int(file_stat.st_ino)
        offset = int(state.get("offset") or 0)
        if state.get("inode") != inode or file_stat.st_size < offset:
            offset = 0
            stats.rotation_detected = True

        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        try:
            with self.eve_path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                for line in handle:
                    stats.read_lines += 1
                    if stats.read_lines > max_lines:
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        raw = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        stats.parser_errors += 1
                        stats.last_error = f"json parse error at line {stats.read_lines}: {exc.msg}"
                        continue
                    try:
                        event = normalize_eve(raw)
                    except NormalizationError as exc:
                        stats.normalization_errors += 1
                        stats.last_error = str(exc)
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
        self._save_offset(inode, offset)
        return events, stats
