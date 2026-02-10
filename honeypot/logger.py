import json
import logging
import os
import time
from typing import Any, Dict, Optional

LOG_PATH = "/app/logs/honeypot.log"


def create_logger() -> logging.Logger:
    os.makedirs("/app/logs", exist_ok=True)

    logger = logging.getLogger("Honeypot")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if re-imported
    if logger.handlers:
        return logger

    fh = logging.FileHandler(LOG_PATH)
    sh = logging.StreamHandler()

    # We write JSON ourselves; keep formatter minimal
    formatter = logging.Formatter("%(message)s")
    fh.setFormatter(formatter)
    sh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def now_iso() -> str:
    # ISO-like without timezone complexity; good enough for report
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def log_event(logger: logging.Logger, event: str, fields: Dict[str, Any]) -> None:
    payload = {"ts": now_iso(), "event": event, **fields}
    logger.info(json.dumps(payload, ensure_ascii=False))


class AlertTracker:
    """
    Simple in-memory alerting:
    - flags if too many failed logins from the same IP within a window.
    """

    def __init__(self, max_fails: int = 5, window_seconds: int = 60):
        self.max_fails = max_fails
        self.window_seconds = window_seconds
        self.fails: Dict[str, list[float]] = {}

    def record_fail(self, ip: str) -> bool:
        t = time.time()
        self.fails.setdefault(ip, []).append(t)

        # prune old
        cutoff = t - self.window_seconds
        self.fails[ip] = [x for x in self.fails[ip] if x >= cutoff]

        return len(self.fails[ip]) >= self.max_fails
