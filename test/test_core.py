import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from glitched.audit import AuditLog
from glitched.core import (Check, CommandMonitor, FindingTracker, ScanMonitor,
                           OK, WARN, ERROR, STALE, parse_allowlist, publishers_check)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ScanMonitor(started_at=0)

    def record(self, stamp=100, steady=0, ros_now=100):
        self.monitor.record(stamp, steady=steady, ros_now=ros_now)

    def check(self, steady=0, ros_now=100):
        return self.monitor.evaluate(steady=steady, ros_now=ros_now)

    def test_startup_is_unknown_not_clean(self):
        check = self.check(steady=4)
        self.assertEqual(check.coverage, WARN)
        self.assertEqual(check.level, STALE)
        self.assertFalse(check.authoritative)

    def test_missing_after_grace_is_finding(self):
        check = self.check(steady=5)
        self.assertEqual(check.level, ERROR)
        self.assertEqual(check.findings[0].code, "missing")

    def test_fresh_and_boundary(self):
        self.record()
        self.assertEqual(self.check(steady=0.6, ros_now=100.5).level, OK)

    def test_stopped_delivery_and_stale_source(self):
        self.record()
        codes = {finding.code for finding in self.check(steady=1, ros_now=101).findings}
        self.assertEqual(codes, {"stale_source", "stale_arrival"})

    def test_repeated_capture_timestamp_does_not_refresh_source(self):
        self.record()
        self.record(stamp=100, steady=2, ros_now=102)
        check = self.check(steady=2, ros_now=102)
        self.assertEqual([f.code for f in check.findings], ["stale_source"])

    def test_future_timestamp(self):
        self.record(stamp=101)
        self.assertEqual(self.check().findings[0].code, "future_timestamp")

    def test_invalid_timestamps(self):
        for value in (0, -1, math.nan, math.inf):
            with self.subTest(value=value):
                self.record(stamp=value)
                check = self.check()
                self.assertEqual(check.findings[0].code, "invalid_timestamp")
                json.dumps(check.evidence, allow_nan=False)

    def test_clock_reset_invalidates_old_sample_and_new_sample_recovers(self):
        self.record()
        check = self.check(steady=6, ros_now=90)
        self.assertNotEqual(check.coverage, OK)
        self.assertFalse(check.authoritative)
        self.record(stamp=90, steady=6.1, ros_now=90)
        self.assertEqual(self.check(steady=6.1, ros_now=90).level, OK)

    def test_unavailable_clock(self):
        for now in (0, math.nan, math.inf):
            check = self.check(ros_now=now)
            self.assertEqual(check.level, STALE)
            self.assertFalse(check.authoritative)

    def test_simulation_clock_pause_and_resume(self):
        self.monitor = ScanMonitor(started_at=0, use_sim_time=True)
        self.record()
        self.assertEqual(self.check(steady=2).level, STALE)
        # Old samples cannot become fresh simply because /clock resumed.
        self.assertNotEqual(self.check(steady=2.1, ros_now=100.1).level, OK)
        self.record(stamp=100.1, steady=2.2, ros_now=100.1)
        self.assertEqual(self.check(steady=2.2, ros_now=100.1).level, OK)

    def test_disabled_is_explicit(self):
        self.monitor.enabled = False
        check = self.check()
        self.assertFalse(check.enabled)
        self.assertEqual(check.level, STALE)

    def test_thresholds_reject_nonfinite_and_nonpositive_values(self):
        for value in (math.nan, math.inf, 0, -1, True, "0.6"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ScanMonitor(started_at=0, timeout_s=value)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.monitor = CommandMonitor(started_at=0)

    def test_unobserved_and_expired_commands_not_clean(self):
        self.assertEqual(self.monitor.evaluate(steady=0).level, STALE)
        self.monitor.record([0] * 6, steady=0)
        self.assertEqual(self.monitor.evaluate(steady=2).level, STALE)

    def test_nonfinite_components_even_when_limits_disabled(self):
        for index in range(6):
            for value in (math.inf, -math.inf, math.nan):
                components = [0.0] * 6
                components[index] = value
                self.monitor.record(components, steady=0)
                check = self.monitor.evaluate(steady=0)
                self.assertEqual(check.level, ERROR)
                json.dumps(check.findings[0].to_dict(), allow_nan=False)

    def test_limits_disabled_is_partial_coverage(self):
        self.monitor.record([100] * 6, steady=0)
        check = self.monitor.evaluate(steady=0)
        self.assertEqual(check.level, OK)
        self.assertEqual(check.coverage, WARN)
        self.assertFalse(check.evidence["limits_enabled"])

    def test_limits_use_all_axes_and_norm(self):
        self.monitor.limits_enabled = True
        self.monitor.record([0.4, 0.4, 0, 0, 0, -1.1], steady=0)
        check = self.monitor.evaluate(steady=0)
        self.assertEqual({f.code for f in check.findings}, {"linear_limit", "angular_limit"})

    def test_extreme_finite_commands_cannot_break_reporting(self):
        self.monitor.limits_enabled = True
        self.monitor.record([1.7e308] * 6, steady=0)
        check = self.monitor.evaluate(steady=0)
        self.assertEqual(check.level, ERROR)
        json.dumps(check.evidence, allow_nan=False)
        for finding in check.findings:
            json.dumps(finding.to_dict(), allow_nan=False)

    def test_valid_command_resolves_finding_but_silence_does_not(self):
        tracker = FindingTracker()
        self.monitor.record([math.nan] + [0] * 5, steady=0)
        self.assertEqual(tracker.update([self.monitor.evaluate(steady=0)])[0]["event"], "activated")
        self.assertEqual(tracker.update([self.monitor.evaluate(steady=2)]), [])
        self.monitor.record([0] * 6, steady=3)
        self.assertEqual(tracker.update([self.monitor.evaluate(steady=3)])[0]["event"], "resolved")


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.rules = parse_allowlist(["/cmd_vel=/control/controller"])

    def test_allowlist_and_unexpected_names(self):
        self.assertEqual(publishers_check(
            self.rules, {"/cmd_vel": ["/control/controller"]}, enabled=True).level, OK)
        check = publishers_check(self.rules, {"/cmd_vel": ["/other"]}, enabled=True)
        self.assertEqual(check.level, WARN)
        self.assertIn("identity unverified", check.findings[0].message)

    def test_disabled_unconfigured_and_failed_graph_are_not_clean(self):
        cases = [publishers_check(self.rules), publishers_check({}, enabled=True),
                 publishers_check(self.rules, enabled=True, error="DDS error"),
                 publishers_check(self.rules, {}, enabled=True)]
        for check in cases:
            self.assertEqual(check.level, STALE)
            self.assertFalse(check.authoritative)

    def test_invalid_rule(self):
        for rules in (["relative=/node"], ["/topic=node"], ["/=/node"],
                      ["/topic=/bad name"], [12], "not a list"):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                parse_allowlist(rules)


class AuditTests(unittest.TestCase):
    def test_deduplicate_change_and_recover(self):
        monitor = CommandMonitor(started_at=0, limits_enabled=True)
        tracker = FindingTracker()
        monitor.record([1, 0, 0, 0, 0, 0], steady=0)
        check = monitor.evaluate(steady=0)
        self.assertEqual(tracker.update([check])[0]["event"], "activated")
        self.assertEqual(tracker.update([check]), [])
        monitor.record([2, 0, 0, 0, 0, 0], steady=0)
        self.assertEqual(tracker.update([monitor.evaluate(steady=0)])[0]["event"], "changed")
        monitor.record([0] * 6, steady=0)
        self.assertEqual(tracker.update([monitor.evaluate(steady=0)])[0]["event"], "resolved")

    def test_scan_ages_do_not_spam_findings(self):
        monitor = ScanMonitor(started_at=0)
        monitor.record(100, steady=0, ros_now=100)
        tracker = FindingTracker()
        self.assertEqual(len(tracker.update([monitor.evaluate(steady=1, ros_now=101)])), 2)
        self.assertEqual(tracker.update([monitor.evaluate(steady=2, ros_now=102)]), [])

    def test_rotating_json_log_and_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            log = AuditLog(path, max_bytes=400, backups=2)
            try:
                for index in range(15):
                    log.record([Check.unavailable("test", f"Failure {index}")])
            finally:
                log.close()
            files = list(Path(temporary).glob("events.jsonl*"))
            self.assertEqual(len(files), 3)
            for file in files:
                for line in file.read_text().splitlines():
                    self.assertEqual(json.loads(line)["event"], "coverage")

    def test_failed_write_does_not_consume_transition(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = AuditLog(Path(temporary) / "events.jsonl")
            try:
                check = Check.unavailable("test", "Not available")
                with patch.object(log.logger, "info", side_effect=OSError("disk full")):
                    with self.assertRaises(OSError):
                        log.record([check])
                self.assertEqual(log.coverage, {})
                log.record([check])
                self.assertEqual(len(log.coverage), 1)
            finally:
                log.close()

    def test_handler_surfaces_disk_write_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = AuditLog(Path(temporary) / "events.jsonl")
            try:
                with patch.object(log.handler.stream, "write", side_effect=OSError("disk full")):
                    with self.assertRaises(OSError):
                        log.record([Check.unavailable("test", "Unknown")])
                self.assertEqual(log.coverage, {})
            finally:
                log.close()


if __name__ == "__main__":
    unittest.main()
