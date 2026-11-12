# Wiring the plausibility monitors into glitched_monitor
#
# STATUS: APPLIED. The changes below are already present in this tree's
# glitched/monitor.py, config/monitor.yaml, package.xml and README.md.
# This file is kept as the rationale/calibration reference.
# This is the integration sketch for glitched/monitor.py. It follows the
# package's existing patterns exactly: read-only parameters, _guard-wrapped
# evaluation, coverage+condition status pairs, best-effort sensor QoS.
# Verified logic lives in glitched/plausibility.py + test/test_plausibility.py
# (18 passing stdlib tests); this ROS adapter layer needs rclpy on the robot.

*** glitched/monitor.py changes ***

# 1. imports
from nav_msgs.msg import Odometry           # add nav_msgs to package.xml deps
from .plausibility import MotionConsistencyMonitor, ScanContentMonitor

# 2. in __init__, after self.commands = CommandMonitor(...):
self.scan_content = ScanContentMonitor(
    topic=self.scan.topic,
    enabled=self._parameter("scan_content_enabled", True),
    max_invalid_ratio=self._parameter("scan_max_invalid_ratio", 0.95),
    frozen_frames=int(self._parameter("scan_frozen_frames", 10)),
    stuck_value_ratio=self._parameter("scan_stuck_value_ratio", 0.98),
    history_s=self._parameter("scan_content_history_s", 5.0))
self.motion = MotionConsistencyMonitor(
    enabled=self._parameter("motion_consistency_enabled", False),  # opt-in:
    # tolerance must be calibrated per robot, like command limits
    mismatch_tolerance_mps=self._parameter("motion_mismatch_tolerance_mps", 0.3),
    dwell_s=self._parameter("motion_mismatch_dwell_s", 2.0))
self.odom_subscription = None
if self.motion.enabled:
    self.odom_subscription = self.create_subscription(
        Odometry, self._parameter("odom_topic", "/odom"),
        self._on_odometry, qos_profile_sensor_data)

# 3. feed observations (reuse existing callbacks)
def _on_scan(self, message):            # extend the existing one
    ...existing stamp handling...
    if self.scan_content.enabled:
        self.scan_content.record(message.ranges,
                                 range_min=message.range_min,
                                 range_max=message.range_max,
                                 steady=time.monotonic())

def _on_command(self, message):         # extend the existing one
    ...existing record...
    self.motion.record_command(
        (message.linear.x, message.linear.y, message.linear.z),
        steady=time.monotonic())

def _on_odometry(self, message):        # new
    v = message.twist.twist.linear
    self.motion.record_odometry((v.x, v.y, v.z), steady=time.monotonic())

# 4. in _tick, extend the checks list:
checks = [
    ...existing three...,
    self._guard("scan_content",
                lambda: self.scan_content.evaluate(steady=steady)),
    self._guard("motion_consistency",
                lambda: self.motion.evaluate(steady=steady)),
]

*** config/monitor.yaml additions ***
    scan_content_enabled: true
    scan_max_invalid_ratio: 0.95
    scan_frozen_frames: 10
    scan_stuck_value_ratio: 0.98
    scan_content_history_s: 5.0
    # Opt-in; calibrate tolerance/dwell on YOUR base before enabling.
    motion_consistency_enabled: false
    odom_topic: /odom
    motion_mismatch_tolerance_mps: 0.3
    motion_mismatch_dwell_s: 2.0

*** What this adds / still does not add ***
Catches: blinded lidar (all-NaN/inf/out-of-bounds), frozen or replayed frames
(bit-identical streak), stuck single-value echoes, broken range metadata,
base ignoring commands, base moving without commands, grossly fake odometry.
Does NOT catch: a spoofed stream with realistic noise and consistent motion —
that needs cross-sensor fusion residuals (IMU vs odom vs lidar ego-motion)
and ultimately signed/authenticated transport (SROS2). Plausibility shrinks
the attacker's budget; it does not authenticate the sensor.

Calibration notes:
- frozen_frames: 10 frames at a 10 Hz lidar = 1 s. CPU-cheap; hashing 360
  floats per frame is ~microseconds.
- stuck_value_ratio 0.98 tolerates a flat wall across 98% of the FOV; a real
  wall still varies by incidence angle, a stuck DSP does not.
- motion tolerance: watch gap_mps evidence in /diagnostics during normal
  teleop for 10 minutes, set tolerance ~2x observed p99, dwell > your worst
  acceleration ramp.
