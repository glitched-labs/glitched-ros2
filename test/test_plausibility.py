"""Deterministic tests for sensor-content plausibility rules."""

import math
import unittest

from glitched.core import OK, WARN, ERROR, STALE
from glitched.plausibility import (MotionConsistencyMonitor, ScanContentMonitor,
                                   frame_signature)


def frame(monitor, ranges, *, steady, range_min=0.1, range_max=10.0):
    monitor.record(ranges, range_min=range_min, range_max=range_max, steady=steady)


class ScanContentTests(unittest.TestCase):
    def setUp(self):
        self.monitor = ScanContentMonitor(frozen_frames=3)

    def test_disabled_and_unobserved_never_report_ok(self):
        disabled = ScanContentMonitor(enabled=False).evaluate(steady=0.0)
        self.assertEqual((disabled.coverage, disabled.level), (WARN, STALE))
        empty = self.monitor.evaluate(steady=0.0)
        self.assertEqual((empty.coverage, empty.level), (STALE, STALE))
        self.assertFalse(empty.authoritative)

    def test_healthy_varied_frame_passes(self):
        frame(self.monitor, [1.0 + 0.01 * i for i in range(360)], steady=0.0)
        check = self.monitor.evaluate(steady=0.1)
        self.assertEqual((check.coverage, check.level), (OK, OK))
        self.assertEqual(check.findings, [])

    def test_old_observation_is_missing_coverage_not_ok(self):
        frame(self.monitor, [1.0, 2.0, 3.0] * 20, steady=0.0)
        check = self.monitor.evaluate(steady=100.0)
        self.assertEqual(check.coverage, STALE)

    def test_blinded_sensor_all_invalid(self):
        frame(self.monitor, [math.inf] * 350 + [1.0] * 10, steady=0.0)
        check = self.monitor.evaluate(steady=0.0)
        self.assertEqual(check.level, ERROR)
        self.assertIn("blinded", [f.code for f in check.findings])

    def test_out_of_bounds_values_count_as_invalid(self):
        frame(self.monitor, [99.0] * 360, steady=0.0, range_max=10.0)
        check = self.monitor.evaluate(steady=0.0)
        self.assertIn("blinded", [f.code for f in check.findings])

    def test_invalid_metadata_is_an_error_not_a_crash(self):
        frame(self.monitor, [1.0] * 360, steady=0.0, range_min=math.nan)
        check = self.monitor.evaluate(steady=0.0)
        self.assertIn("invalid_bounds", [f.code for f in check.findings])

    def test_frozen_frame_detected_after_streak(self):
        ranges = [1.0 + 0.01 * i for i in range(360)]
        for tick in range(3):
            frame(self.monitor, ranges, steady=float(tick))
            self.assertNotIn("frozen_frame",
                             [f.code for f in self.monitor.evaluate(steady=float(tick)).findings])
        frame(self.monitor, ranges, steady=3.0)
        check = self.monitor.evaluate(steady=3.0)
        self.assertEqual(check.level, ERROR)
        self.assertIn("frozen_frame", [f.code for f in check.findings])

    def test_changing_frames_reset_frozen_streak(self):
        for tick in range(10):
            frame(self.monitor, [1.0 + 0.01 * tick] * 360, steady=float(tick))
        check = self.monitor.evaluate(steady=9.0)
        self.assertNotIn("frozen_frame", [f.code for f in check.findings])

    def test_quantization_treats_subminimeter_jitter_as_identical(self):
        base = [1.0] * 360
        jitter = [1.0 + 1e-7] * 360
        self.assertEqual(frame_signature(base), frame_signature(jitter))
        self.assertNotEqual(frame_signature(base),
                            frame_signature([1.0] * 359 + [1.5]))
        self.assertNotEqual(frame_signature([math.inf] * 4),
                            frame_signature([1.0] * 4))

    def test_stuck_value_warns_but_varied_wall_does_not(self):
        frame(self.monitor, [2.5] * 360, steady=0.0)
        check = self.monitor.evaluate(steady=0.0)
        self.assertEqual(check.level, WARN)
        self.assertIn("stuck_value", [f.code for f in check.findings])
        frame(self.monitor, [2.5 + 0.02 * i for i in range(360)], steady=1.0)
        self.assertEqual(self.monitor.evaluate(steady=1.0).level, OK)

    def test_too_few_beams_is_unassessable(self):
        frame(self.monitor, [1.0, 2.0], steady=0.0)
        check = self.monitor.evaluate(steady=0.0)
        self.assertIn("too_few_beams", [f.code for f in check.findings])

    def test_threshold_validation(self):
        for kwargs in ({"max_invalid_ratio": 0}, {"max_invalid_ratio": 1.5},
                       {"frozen_frames": -1}, {"stuck_value_ratio": math.nan},
                       {"history_s": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ScanContentMonitor(**kwargs)


class MotionConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.monitor = MotionConsistencyMonitor(enabled=True,
                                                mismatch_tolerance_mps=0.3,
                                                dwell_s=2.0)

    def observe(self, commanded, measured, *, steady):
        self.monitor.record_command((commanded, 0.0, 0.0), steady=steady)
        self.monitor.record_odometry((measured, 0.0, 0.0), steady=steady)
        return self.monitor.evaluate(steady=steady)

    def test_disabled_by_default_and_never_ok(self):
        check = MotionConsistencyMonitor().evaluate(steady=0.0)
        self.assertEqual((check.coverage, check.level), (WARN, STALE))

    def test_missing_either_stream_is_unassessable(self):
        self.monitor.record_command((0.5, 0.0, 0.0), steady=0.0)
        check = self.monitor.evaluate(steady=0.0)
        self.assertEqual(check.coverage, STALE)
        self.assertIn("odometry", check.coverage_message)

    def test_agreement_and_transient_disagreement_pass(self):
        self.assertEqual(self.observe(0.5, 0.45, steady=0.0).level, OK)
        self.assertEqual(self.observe(1.0, 0.1, steady=1.0).level, OK)  # within dwell

    def test_sustained_mismatch_is_an_error(self):
        self.observe(1.0, 0.0, steady=0.0)
        self.observe(1.0, 0.0, steady=1.0)
        check = self.observe(1.0, 0.0, steady=3.0)
        self.assertEqual(check.level, ERROR)
        self.assertEqual(check.findings[0].code, "speed_mismatch")

    def test_recovery_resets_dwell(self):
        self.observe(1.0, 0.0, steady=0.0)
        self.observe(1.0, 1.0, steady=1.0)   # agreement resets the clock
        check = self.observe(1.0, 0.0, steady=2.5)
        self.assertEqual(check.level, OK)    # new mismatch, dwell restarted

    def test_nonfinite_speeds_are_unassessable_here(self):
        check = self.observe(math.nan, 0.0, steady=0.0)
        self.assertEqual(check.coverage, STALE)
        self.assertEqual(check.findings, [])


if __name__ == "__main__":
    unittest.main()
