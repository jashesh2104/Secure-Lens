"""Structured (JSON) logging built on the Python stdlib `logging` module.

Every log line is emitted as a single JSON object so it can be shipped to and
queried by log aggregators. A per-request ID is carried in a ContextVar and
injected into every record, which lets us correlate all the events emitted
while handling one HTTP request (scan start/complete, triage start/complete,
unhandled exceptions).
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar

# Set by the request-id middleware in app.main; read by JSONFormatter so every
# record produced during a request is tagged with the same id.
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

# Standard LogRecord attributes we don't want to duplicate into the JSON body.
# Anything passed via `logger.info(..., extra={...})` that isn't in here gets
# merged into the output, so structured fields "just work".
_RESERVED = set(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JSONFormatter(logging.Formatter):
    """Render a LogRecord as a compact JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        # Merge any structured extras (event, repo, scan_id, ...).
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    """Install the JSON formatter on the root logger (stdout).

    Idempotent: replaces existing handlers so repeated calls (e.g. across test
    runs) don't stack duplicate output.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
