"""Sensor CONTENT plausibility rules in the glitched Check framework.

The existing ScanMonitor proves messages are *fresh*; this module asks whether
the values inside them are *believable*. It deliberately follows core.py's
conventions: deterministic rules, caller-supplied times, coverage separated
from condition, and no claim of ground truth — an implausible reading is an
anomaly indicator, not proof of attack, and a plausible one is not proof of
safety. A spoofed-but-statistically-plausible stream passes these checks.
"""

from collections import deque
import hashlib
import math
import struct

from .core import Check, Finding, OK, WARN, ERROR, STALE, positive


def _fraction(value, name):
    value = positive(value, name)
    if value > 1:
        raise ValueError(f"{name} must be within (0, 1]")
    return value


def frame_signature(ranges, *, decimals=3):
    """Quantized digest so float jitter below ~1 mm still counts as 'same frame'."""
    quantized = struct.pack(
        f"{len(ranges)}q",
        *((2 ** 62) if not math.isfinite(r) else round(r * 10 ** decimals)
          for r in ranges))
    return hashlib.sha256(quantized).hexdigest()


class ScanContentMonitor:
    """Judge LaserScan *values*: dropouts, frozen frames, stuck echoes, bad bounds.

    All thresholds are ratios of beams or consecutive-frame counts, so the rules
    are rate-independent. The caller records each arriving frame; evaluation is
    pull-based once per diagnostics tick, like the freshness monitors.
    """

    def __init__(self, *, topic="/scan",
                 max_invalid_ratio=0.95,      # beams that are NaN/inf/out-of-bounds
                 frozen_frames=10,            # identical consecutive frames => frozen
                 stuck_value_ratio=0.98,      # valid beams sharing one value => stuck
                 min_beams=8,                 # fewer beams is unassessable, not OK
                 history_s=5.0,               # observation must be this recent
                 enabled=True):
        self.topic = topic
        self.max_invalid = _fraction(max_invalid_ratio, "max invalid ratio")
        self.frozen_limit = int(positive(frozen_frames, "frozen frame count"))
        self.stuck_ratio = _fraction(stuck_value_ratio, "stuck value ratio")
        self.min_beams = int(positive(min_beams, "minimum beam count"))
        self.history = positive(history_s, "history window")
        self.enabled = enabled
        self.sample = None           # (steady, stats dict)
        self.last_signature = None
        self.identical_streak = 0

    def record(self, ranges, *, range_min, range_max, steady):
        """Summarize one frame. Malformed metadata is itself an observation."""
        ranges = tuple(float(r) for r in ranges)
        bounds_valid = (math.isfinite(range_min) and math.isfinite(range_max)
                        and 0 <= range_min < range_max)
        signature = frame_signature(ranges)
        if signature == self.last_signature:
            self.identical_streak += 1
        else:
            self.identical_streak = 0
        self.last_signature = signature

        total = len(ranges)
        valid = []
        if bounds_valid:
            valid = [r for r in ranges
                     if math.isfinite(r) and range_min <= r <= range_max]
        mode_count = 0
        if valid:
            counts = {}
            for r in valid:
                key = round(r, 3)
                counts[key] = counts.get(key, 0) + 1
            mode_count = max(counts.values())
        self.sample = (steady, {
            "total": total,
            "valid": len(valid),
            "bounds_valid": bounds_valid,
            "range_min": range_min if math.isfinite(range_min) else str(range_min),
            "range_max": range_max if math.isfinite(range_max) else str(range_max),
            "mode_count": mode_count,
            "identical_streak": self.identical_streak,
        })

    def evaluate(self, *, steady):
        if not self.enabled:
            return Check.unavailable("scan_content",
                                     "Scan content checks disabled", enabled=False)
        if self.sample is None or steady - self.sample[0] > self.history:
            return Check.unavailable(
                "scan_content", "No recent scan frame to assess (freshness is "
                "reported separately by the scan monitor)")
        _, stats = self.sample
        evidence = {"topic": self.topic, **stats}
        issues = []
        if not stats["bounds_valid"]:
            issues.append(("invalid_bounds", "ERROR",
                           "Scan range_min/range_max metadata is invalid"))
        if stats["total"] < self.min_beams:
            issues.append(("too_few_beams", "ERROR",
                           "Scan has too few beams to assess"))
        else:
            invalid_ratio = 1.0 - stats["valid"] / stats["total"]
            evidence["invalid_ratio"] = round(invalid_ratio, 4)
            if stats["bounds_valid"] and invalid_ratio > self.max_invalid:
                issues.append(("blinded", "ERROR",
                               "Nearly all beams are invalid; sensor may be "
                               "blinded, saturated or disconnected"))
            if (stats["valid"] >= self.min_beams
                    and stats["mode_count"] / stats["valid"] >= self.stuck_ratio):
                issues.append(("stuck_value", "WARN",
                               "Valid beams collapse to a single value; echo may "
                               "be stuck or synthetic"))
        if stats["identical_streak"] >= self.frozen_limit:
            issues.append(("frozen_frame", "ERROR",
                           "Consecutive frames are bit-identical; sensor output "
                           "appears frozen or replayed"))
        findings = [Finding("scan_content", code, severity, text,
                            {"topic": self.topic}) for code, severity, text in issues]
        worst = (ERROR if any(f.severity == "ERROR" for f in findings)
                 else WARN if findings else OK)
        return Check("scan_content", OK,
                     "Scan content assessed (plausibility, not ground truth)",
                     worst,
                     "; ".join(text for _, _, text in issues)
                     if issues else "Scan content plausibility checks passed",
                     evidence, findings)


class MotionConsistencyMonitor:
    """Cross-check commanded speed against odometry — disagreement is an anomaly.

    Catches a planner commanding motion into a dead base, a base moving with no
    command (runaway/injection), and grossly spoofed odometry. Tolerances must
    be calibrated per robot; the defaults are examples, exactly like the
    command-limit defaults in core.py.
    """

    def __init__(self, *, mismatch_tolerance_mps=0.3, dwell_s=2.0,
                 history_s=1.0, enabled=False):
        self.tolerance = positive(mismatch_tolerance_mps, "mismatch tolerance")
        self.dwell = positive(dwell_s, "mismatch dwell")
        self.history = positive(history_s, "history window")
        self.enabled = enabled
        self.command = None   # (steady, speed_mps)
        self.odom = None      # (steady, speed_mps)
        self.mismatch_since = None

    def record_command(self, linear_xyz, *, steady):
        self.command = (steady, math.hypot(*linear_xyz))

    def record_odometry(self, linear_xyz, *, steady):
        self.odom = (steady, math.hypot(*linear_xyz))

    def evaluate(self, *, steady):
        if not self.enabled:
            return Check.unavailable("motion_consistency",
                                     "Motion consistency checks disabled",
                                     enabled=False)
        stale = [name for name, sample in (("command", self.command),
                                           ("odometry", self.odom))
                 if sample is None or steady - sample[0] > self.history]
        if stale:
            self.mismatch_since = None
            return Check.unavailable(
                "motion_consistency",
                f"Missing current observations: {', '.join(stale)}")
        commanded, measured = self.command[1], self.odom[1]
        if not (math.isfinite(commanded) and math.isfinite(measured)):
            # Nonfinite inputs are the command monitor's finding; here they
            # simply make consistency unassessable.
            self.mismatch_since = None
            return Check.unavailable("motion_consistency",
                                     "Nonfinite speed observation")
        gap = abs(commanded - measured)
        evidence = {"commanded_mps": round(commanded, 4),
                    "measured_mps": round(measured, 4),
                    "gap_mps": round(gap, 4),
                    "tolerance_mps": self.tolerance}
        if gap <= self.tolerance:
            self.mismatch_since = None
            return Check("motion_consistency", OK,
                         "Command and odometry both observed", OK,
                         "Commanded and measured speeds agree within tolerance",
                         evidence)
        if self.mismatch_since is None:
            self.mismatch_since = steady
        sustained = steady - self.mismatch_since
        evidence["sustained_s"] = round(sustained, 3)
        if sustained < self.dwell:
            # Accelerating/decelerating robots legitimately disagree briefly.
            return Check("motion_consistency", OK,
                         "Command and odometry both observed", OK,
                         "Transient speed disagreement within dwell time",
                         evidence)
        finding = Finding("motion_consistency", "speed_mismatch", "ERROR",
                          "Commanded and measured speeds disagree beyond "
                          "tolerance and dwell", evidence)
        return Check("motion_consistency", OK,
                     "Command and odometry both observed", ERROR,
                     finding.message, evidence, [finding])
