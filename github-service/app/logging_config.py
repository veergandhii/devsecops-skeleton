import logging, json, sys, contextvars
from datetime import datetime, timezone

# A context variable holds the current correlation ID for the running task. Set it once per
# message/request; the formatter reads it automatically — no threading it through every call.
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")


class JsonFormatter(logging.Formatter):
    """Render each log record as a single JSON line with our standard fields."""
    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "service":        self.service,
            "level":          record.levelname,
            "correlation_id": correlation_id_var.get(),
            "message":        record.getMessage(),
        }
        # Include any extra=... fields passed to the logger (e.g. findings_count).
        for k, v in getattr(record, "__dict__", {}).items():
            if k not in ("args", "msg", "levelname", "levelno", "pathname", "filename",
                         "module", "exc_info", "exc_text", "stack_info", "lineno",
                         "funcName", "created", "msecs", "relativeCreated", "thread",
                         "threadName", "processName", "process", "name", "taskName"):
                payload[k] = v
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(service: str):
    """Call once at startup. Routes the root logger through JsonFormatter to stdout."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
