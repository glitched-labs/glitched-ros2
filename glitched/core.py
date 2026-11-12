"""Deterministic detection rules. Times and observations are supplied by callers."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import math


OK, WARN, ERROR, STALE = range(4)  # diagnostic_msgs/DiagnosticStatus values


def positive(value, name):
    """Validate configurable thresholds without accepting NaN or booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite positive number")
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return float(value)


@dataclass(frozen=True)
class Finding:
    """An attributable condition; evidence must contain JSON-safe stable values."""

    group: str
    code: str
    severity: str
    message: str
    evidence: dict = field(default_factory=dict)

    @property
    def key(self):
        return f"{self.group}/{self.code}"

    def to_dict(self):
        return asdict(self)


@dataclass
class Check:
    """Coverage and observed condition are deliberately separate."""

    name: str
    coverage: int
    coverage_message: str
    level: int
    message: str
    evidence: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    authoritative: bool = True
    enabled: bool = True

    @classmethod
    def unavailable(cls, name, message, *, enabled=True):
        return cls(name, STALE if enabled else WARN, message, STALE,
                   "Condition not evaluated", authoritative=False, enabled=enabled)


class ScanMonitor:
    """Check arrival deadlines and capture timestamps, never sensor ground truth."""

    def __init__(self, *, started_at, topic="/scan", timeout_s=0.6,
                 grace_s=5.0, future_tolerance_s=0.1, clock_stall_s=1.0,
                 use_sim_time=False, enabled=True):
        self.topic = topic
        self.timeout = positive(timeout_s, "scan timeout")
        self.grace = positive(grace_s, "startup grace")
        self.future_tolerance = positive(future_tolerance_s, "future tolerance")
        self.clock_stall = positive(clock_stall_s, "clock stall timeout")
        self.started = started_at
        self.use_sim_time = use_sim_time
        self.enabled = enabled
        self.sample = None
        self.last_clock = None
        self.last_clock_progress = started_at

    def _clock(self, now, steady):
        if not math.isfinite(now) or now <= 0:
            self.sample = None
            self.last_clock = None
            return "ROS clock unavailable"
        if self.last_clock is not None and now < self.last_clock:
            self.sample = None
        if self.last_clock is None or now != self.last_clock:
            self.last_clock_progress = steady
        self.last_clock = now
        if self.use_sim_time and steady - self.last_clock_progress > self.clock_stall:
            self.sample = None
            return "Simulation clock is not advancing"
        return None

    def record(self, stamp, *, steady, ros_now):
        if self._clock(ros_now, steady) is None:
            self.sample = (steady, stamp)

    def evaluate(self, *, steady, ros_now):
        if not self.enabled:
            return Check.unavailable("scan", "Scan monitoring disabled", enabled=False)
        clock_error = self._clock(ros_now, steady)
        if clock_error:
            return Check.unavailable("scan", clock_error)
        if self.sample is None:
            if steady - self.started < self.grace:
                check = Check.unavailable("scan", "Waiting for first scan (startup grace)")
                check.coverage = WARN
                return check
            finding = Finding("scan", "missing", "ERROR", "No scan received",
                              {"topic": self.topic})
            return Check("scan", STALE, "No current sensor observation", ERROR,
                         finding.message, {"topic": self.topic}, [finding], authoritative=False)
        received, stamp = self.sample
        arrival_age = max(0.0, steady - received)
        evidence = {"topic": self.topic, "arrival_age_s": arrival_age,
                    "timeout_s": self.timeout}
        issues = []
        if not math.isfinite(stamp) or stamp <= 0:
            issues.append(("invalid_timestamp", "Invalid scan timestamp"))
        else:
            age = ros_now - stamp
            evidence["source_age_s"] = age
            if age < -self.future_tolerance:
                issues.append(("future_timestamp", "Scan timestamp is in the future"))
            elif age > self.timeout:
                issues.append(("stale_source", "Scan source timestamp is stale"))
        if arrival_age > self.timeout:
            issues.append(("stale_arrival", "Scan messages stopped arriving"))
        findings = [Finding("scan", code, "ERROR", text,
                            {"topic": self.topic, "timeout_s": self.timeout})
                    for code, text in issues]
        return Check("scan", STALE if issues else OK,
                     "Sensor observation unavailable or stale" if issues else "Fresh scan observed",
                     ERROR if issues else OK,
                     "; ".join(text for _, text in issues) if issues else "Scan freshness checks passed",
                     evidence, findings)


class CommandMonitor:
    """Observe all six Twist components, with optional norm limits."""

    def __init__(self, *, started_at, topic="/cmd_vel", timeout_s=1.0,
                 grace_s=5.0, enabled=True, limits_enabled=False,
                 max_linear=0.5, max_angular=1.0):
        self.topic = topic
        self.started = started_at
        self.timeout = positive(timeout_s, "command timeout")
        self.grace = positive(grace_s, "startup grace")
        self.enabled = enabled
        self.limits_enabled = limits_enabled
        self.max_linear = positive(max_linear, "linear limit")
        self.max_angular = positive(max_angular, "angular limit")
        self.sample = None

    def record(self, components, *, steady):
        if len(components) != 6:
            raise ValueError("A Twist observation must have six components")
        self.sample = (steady, tuple(components))

    def evaluate(self, *, steady):
        if not self.enabled:
            return Check.unavailable("commands", "Command monitoring disabled", enabled=False)
        if self.sample is None or steady - self.sample[0] > self.timeout:
            check = Check.unavailable("commands", "No current command observation")
            if self.sample is None and steady - self.started < self.grace:
                check.coverage = WARN
                check.coverage_message = "Waiting for first command (startup grace)"
            return check
        values = self.sample[1]
        findings = []
        evidence = {"topic": self.topic, "limits_enabled": self.limits_enabled}
        if not all(math.isfinite(x) for x in values):
            findings.append(Finding("commands", "nonfinite", "ERROR",
                                    "Command contains a nonfinite value",
                                    {"topic": self.topic,
                                     "components": [x if math.isfinite(x) else str(x)
                                                    for x in values]}))
        elif self.limits_enabled:
            for label, value, limit in (
                    ("linear", math.hypot(*values[:3]), self.max_linear),
                    ("angular", math.hypot(*values[3:]), self.max_angular)):
                safe_value = value if math.isfinite(value) else str(value)
                evidence[f"{label}_norm"] = safe_value
                if value > limit:
                    findings.append(Finding("commands", f"{label}_limit", "ERROR",
                                            f"Command exceeds configured {label} limit",
                                            {"topic": self.topic, "value": safe_value,
                                             "limit": limit}))
        message = "Command checks passed" if not findings else "; ".join(f.message for f in findings)
        check = Check("commands", OK, "Current command observed",
                      ERROR if findings else OK, message, evidence, findings)
        if not self.limits_enabled:
            check.coverage = WARN
            check.coverage_message = "Finite-value checks active; command limits disabled"
        return check


def parse_allowlist(entries):
    """Parse topic=/fully/qualified/node rules into a topic-to-node map."""
    if not isinstance(entries, (list, tuple)) or any(not isinstance(x, str) for x in entries):
        raise ValueError("publisher_allowlist must be a list of strings")
    rules = {}
    for entry in entries:
        topic, separator, node = entry.partition("=")
        if not separator or not topic.startswith("/") or not node.startswith("/"):
            raise ValueError("Allowlist entries must use /topic=/namespace/node")
        if any(ch.isspace() for ch in entry) or not topic.strip("/") or not node.strip("/"):
            raise ValueError("Allowlist names must be absolute and nonempty without whitespace")
        rules.setdefault(topic, set()).add(node)
    return rules


def publishers_check(rules, observed=None, *, enabled=False, error=None):
    """Names are anomaly indicators, never proof of publisher identity."""
    if not enabled:
        return Check.unavailable("publishers", "Publisher checks disabled", enabled=False)
    if not rules:
        return Check.unavailable("publishers", "No publisher allowlist configured")
    if error:
        return Check.unavailable("publishers", f"ROS graph inspection failed: {error}")
    if observed is None or any(topic not in observed for topic in rules):
        return Check.unavailable("publishers", "ROS graph observation incomplete")
    findings = []
    for topic, allowed in rules.items():
        for name in sorted(set(observed[topic]) - allowed):
            code = hashlib.sha256(f"{topic}\0{name}".encode()).hexdigest()[:20]
            findings.append(Finding("publishers", code, "WARN",
                                    "Unexpected publisher name (identity unverified)",
                                    {"topic": topic, "node": name}))
    return Check("publishers", OK, "Configured topics inspected; names are not authenticated",
                 WARN if findings else OK,
                 "Unexpected publisher names observed" if findings else "No unexpected publisher names",
                 {"topics": sorted(rules)}, findings)


class FindingTracker:
    """Emit transitions, retaining findings when their monitor loses coverage."""

    def __init__(self):
        self.active = {}

    def update(self, checks):
        events = []
        for check in checks:
            current = {finding.key: finding for finding in check.findings}
            for key, finding in current.items():
                previous = self.active.get(key)
                if previous != finding:
                    events.append({"event": "activated" if previous is None else "changed",
                                   "finding": finding.to_dict()})
                self.active[key] = finding
            if check.authoritative:
                for key, finding in list(self.active.items()):
                    if finding.group == check.name and key not in current:
                        events.append({"event": "resolved", "finding": finding.to_dict()})
                        del self.active[key]
        return events


def fingerprint(value):
    """Canonical JSON used for meaningful-change comparisons."""
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":"))
