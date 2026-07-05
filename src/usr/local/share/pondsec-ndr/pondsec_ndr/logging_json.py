"""Structured JSON logging."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from uuid import uuid4


RUN_ID = str(uuid4())


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "component": getattr(record, "component", record.name),
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
            "run_id": RUN_ID,
            "incident_id": getattr(record, "incident_id", None),
            "detection_id": getattr(record, "detection_id", None),
            "host_id": getattr(record, "host_id", None),
            "error_code": getattr(record, "error_code", None),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def configure_logging(log_dir: Path, debug: bool = False) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("pondsec_ndr")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        existing.close()
    handler = RotatingFileHandler(log_dir / "pondsec-ndr.log", maxBytes=10 * 1024 * 1024, backupCount=5)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    stderr = logging.StreamHandler()
    stderr.setFormatter(JsonFormatter())
    logger.addHandler(stderr)
    return logger
