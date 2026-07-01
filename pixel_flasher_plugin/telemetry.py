"""Structured logging, operation timing, and audit trail (Layer 9)."""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from contextlib import contextmanager
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects to stderr."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Merge any extra fields supplied via `extra=...`
        for key, value in record.__dict__.items():
            if key not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
                "asctime",
            }:
                payload[key] = value
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    """Return a logger that writes JSON lines to stderr (stdout is MCP protocol)."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    # Avoid adding multiple handlers if the logger is already configured.
    if not any(isinstance(h, logging.StreamHandler) and h.stream is sys.stderr for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    return logger


@contextmanager
def timed_operation(name: str, logger: logging.Logger | None = None):
    """Context manager that logs start, duration_ms, and result of an operation."""
    log = logger or get_logger("pixel_flasher_plugin.timing")
    start = time.perf_counter()
    result = "started"
    log.info("operation_started", operation=name)
    try:
        yield
        result = "success"
    except Exception as exc:
        result = f"error:{type(exc).__name__}"
        raise
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        log.info("operation_completed", operation=name, duration_ms=duration_ms, result=result)


def log_audit(
    event: str,
    device_id: str | None,
    command: str | None,
    result: str,
    **extra: Any,
) -> None:
    """Write a structured audit log entry (Layer 9 of the safety model)."""
    logger = get_logger("pixel_flasher_plugin.audit")
    entry: dict[str, Any] = {
        "event": event,
        "command": command,
        "result": result,
    }
    if device_id:
        entry["device_id_hash"] = hashlib.sha256(device_id.encode("utf-8")).hexdigest()[:16]
    else:
        entry["device_id_hash"] = None
    entry.update(extra)
    logger.info("audit", **entry)
