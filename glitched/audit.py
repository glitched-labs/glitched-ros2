"""Bounded JSONL audit output for findings and monitor health transitions."""

from datetime import datetime, timezone
import copy
import json
import logging
from logging.handlers import RotatingFileHandler

from .core import FindingTracker


class RaisingFileHandler(RotatingFileHandler):
    """Make disk errors visible to the diagnostics adapter instead of swallowing them."""

    def handleError(self, record):
        raise


class AuditLog:
    def __init__(self, path, *, max_bytes=5 * 1024 * 1024, backups=3):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.Logger(f"glitched.audit.{id(self)}")
        self.handler = RaisingFileHandler(path, maxBytes=max_bytes,
                                          backupCount=backups, encoding="utf-8")
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(self.handler)
        self.tracker = FindingTracker()
        self.coverage = {}

    def record(self, checks):
        tracker = copy.deepcopy(self.tracker)
        coverage = dict(self.coverage)
        events = tracker.update(checks)
        for check in checks:
            state = (check.enabled, check.coverage, check.coverage_message)
            if coverage.get(check.name) != state:
                events.append({"event": "coverage", "monitor": check.name,
                               "enabled": check.enabled, "level": check.coverage,
                               "message": check.coverage_message})
                coverage[check.name] = state
        for event in events:
            event["recorded_at"] = datetime.now(timezone.utc).isoformat()
            self.logger.info(json.dumps(event, sort_keys=True, allow_nan=False))
        self.tracker, self.coverage = tracker, coverage

    def close(self):
        self.handler.close()
        self.logger.removeHandler(self.handler)
