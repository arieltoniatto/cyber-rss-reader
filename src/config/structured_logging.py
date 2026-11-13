"""Optional JSON log lines for Google Cloud Logging and other collectors.

Set ``CYBER_RSS_LOG_FORMAT=json`` to write one JSON object per line to stdout.
Cloud Logging reads the ``severity`` field, so warnings and errors keep their
level instead of every stderr line being reported as an error.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
import sys

LOG_FORMAT_ENV = "CYBER_RSS_LOG_FORMAT"
FORMATS = ("text", "json")
UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")
SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def log_format_from_environment() -> str:
    value = os.environ.get(LOG_FORMAT_ENV, "text").strip().lower() or "text"
    if value not in FORMATS:
        raise ValueError(f"{LOG_FORMAT_ENV} must be one of: {', '.join(FORMATS)}")
    return value


class CloudJSONFormatter(logging.Formatter):
    """Format records with the field names Cloud Logging recognizes."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        if record.exc_info:
            # A stack trace in the message lets Error Reporting group the error.
            message = f"{message}\n{self.formatException(record.exc_info)}"
        if record.stack_info:
            message = f"{message}\n{self.formatStack(record.stack_info)}"
        payload = {
            "severity": record.levelname if record.levelname in SEVERITIES else "DEFAULT",
            "message": message,
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
            "logger": record.name,
            "logging.googleapis.com/sourceLocation": {
                "file": record.pathname, "line": str(record.lineno), "function": record.funcName,
            },
        }
        request = self.http_request(record)
        if request:
            payload["httpRequest"] = request
        return json.dumps(payload, ensure_ascii=False, default=str)

    @staticmethod
    def http_request(record: logging.LogRecord) -> dict | None:
        # uvicorn.access records carry (client, method, path, http_version, status).
        # The client is omitted: behind a load balancer it is the proxy address,
        # and the load balancer's own request log has the real one.
        if record.name != "uvicorn.access" or not isinstance(record.args, tuple) or len(record.args) != 5:
            return None
        _, method, path, version, status = record.args
        return {"requestMethod": method, "requestUrl": path, "protocol": f"HTTP/{version}", "status": status}


def configure_json_logging(level: int = logging.INFO, stream=None) -> None:
    """Send every log record, uvicorn's included, through one JSON handler."""
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(CloudJSONFormatter())
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    for name in UVICORN_LOGGERS:
        logger = logging.getLogger(name)
        for existing in list(logger.handlers):
            logger.removeHandler(existing)
        logger.propagate = True


def json_logging_active() -> bool:
    return any(isinstance(handler.formatter, CloudJSONFormatter) for handler in logging.getLogger().handlers)


def configure_logging_from_environment(level: int) -> bool:
    """Apply JSON logging when requested; return False to keep the caller's text setup.

    Idempotent: once JSON logging is active (for example set up by the API at
    startup), later calls such as a collection container built by the API keep
    the existing level instead of resetting it.
    """
    if log_format_from_environment() != "json":
        return False
    if not json_logging_active():
        configure_json_logging(level)
    return True
