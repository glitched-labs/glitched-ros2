"""ROS 2 adapter: subscribe to observations and publish diagnostics only."""

import json
import math
import time

import rclpy
from diagnostic_msgs.msg import DiagnosticArray, DiagnosticStatus, KeyValue
from geometry_msgs.msg import Twist
from rcl_interfaces.msg import ParameterDescriptor
from rclpy.clock import Clock
from rclpy.clock_type import ClockType
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from sensor_msgs.msg import LaserScan

from .audit import AuditLog
from .core import (Check, CommandMonitor, ScanMonitor, OK,
                   parse_allowlist, positive, publishers_check)
from .paths import state_directory
from .reports import ReportReader


def diagnostic_status(name, level, message, values):
    status = DiagnosticStatus()
    status.name = "glitched/" + name
    status.hardware_id = "robot-host"
    status.level = level
    status.message = message
    status.values = [KeyValue(key=str(key), value=json.dumps(value, sort_keys=True,
                                                           allow_nan=False))
                     for key, value in sorted(values.items())]
    return status


class GlitchedMonitor(Node):
    def __init__(self, **kwargs):
        super().__init__("glitched_monitor", **kwargs)
        started = time.monotonic()
        self._errors = {}
        self.audit = None
        self.audit_error = None
        if not self.has_parameter("use_sim_time"):
            self.declare_parameter("use_sim_time", False)
        grace = self._parameter("startup_grace_s", 5.0)
        self.scan = ScanMonitor(
            started_at=started, topic=self._parameter("scan_topic", "/scan"),
            enabled=self._parameter("scan_enabled", True), grace_s=grace,
            timeout_s=self._parameter("scan_timeout_s", 0.6),
            future_tolerance_s=self._parameter("future_tolerance_s", 0.1),
            clock_stall_s=self._parameter("clock_stall_s", 1.0),
            use_sim_time=bool(self.get_parameter("use_sim_time").value))
        self.commands = CommandMonitor(
            started_at=started, topic=self._parameter("command_topic", "/cmd_vel"),
            enabled=self._parameter("command_enabled", True), grace_s=grace,
            timeout_s=self._parameter("command_timeout_s", 1.0),
            limits_enabled=self._parameter("command_limits_enabled", False),
            max_linear=self._parameter("max_linear_speed_mps", 0.5),
            max_angular=self._parameter("max_angular_speed_radps", 1.0))
        self.publishers_enabled = self._parameter("publisher_check_enabled", False)
        self.allowlist = parse_allowlist(self._parameter("publisher_allowlist", []))
        directory = state_directory(self._parameter("state_dir", ""))
        self.report_reader = ReportReader(
            directory / "scan-state.json",
            max_age_s=positive(self._parameter("max_scan_age_s", 86400.0), "max scan age"))
        self.audit_path = directory / "events.jsonl"
        try:
            self.audit = AuditLog(self.audit_path)
        except OSError as error:
            self.audit_error = str(error)
            self.get_logger().error(f"Audit logging unavailable: {error}")
        # BEST_EFFORT subscriptions also accept reliable publishers, including
        # common sensor drivers; a missing connection becomes degraded coverage.
        self.scan_subscription = None
        self.command_subscription = None
        if self.scan.enabled:
            self.scan_subscription = self.create_subscription(
                LaserScan, self.scan.topic, self._on_scan, qos_profile_sensor_data)
        if self.commands.enabled:
            self.command_subscription = self.create_subscription(
                Twist, self.commands.topic, self._on_command, qos_profile_sensor_data)
        self.diagnostics = self.create_publisher(DiagnosticArray, "/diagnostics", 10)
        # A ROS-time timer would stop reporting when /clock pauses. Always tick
        # using a steady clock; only capture timestamps use ROS time.
        self.steady_clock = Clock(clock_type=ClockType.STEADY_TIME)
        self.timer = self.create_timer(1.0, self._tick, clock=self.steady_clock)
        self.get_logger().info(f"Observational monitoring started; state directory: {directory}")

    def _parameter(self, name, default):
        descriptor = ParameterDescriptor(read_only=True, dynamic_typing=isinstance(default, list))
        return self.declare_parameter(name, default, descriptor).value

    def _ros_now(self):
        return self.get_clock().now().nanoseconds / 1_000_000_000.0

    def _on_scan(self, message):
        stamp = message.header.stamp
        value = (stamp.sec + stamp.nanosec / 1_000_000_000.0
                 if stamp.sec >= 0 and 0 <= stamp.nanosec < 1_000_000_000
                 else math.nan)
        self.scan.record(value, steady=time.monotonic(), ros_now=self._ros_now())

    def _on_command(self, message):
        values = [getattr(vector, axis) for vector in (message.linear, message.angular)
                  for axis in ("x", "y", "z")]
        self.commands.record(values, steady=time.monotonic())

    def _publisher_check(self):
        if not self.publishers_enabled or not self.allowlist:
            return publishers_check(self.allowlist, enabled=self.publishers_enabled)
        observed = {}
        for topic in self.allowlist:
            endpoints = self.get_publishers_info_by_topic(topic)
            observed[topic] = ["/" + "/".join(
                part for part in (endpoint.node_namespace.strip("/"), endpoint.node_name)
                if part) for endpoint in endpoints]
        return publishers_check(self.allowlist, observed, enabled=True)

    def _guard(self, name, callback):
        try:
            result = callback()
            self._errors.pop(name, None)
            return result
        except Exception as error:  # Keep other monitors reporting on adapter failures.
            message = str(error)
            if self._errors.get(name) != message:
                self.get_logger().error(f"{name} monitor unavailable: {message}")
                self._errors[name] = message
            return Check.unavailable(name, f"Monitor failed: {message}")

    def _tick(self):
        steady, ros_now = time.monotonic(), self._ros_now()
        self.scan.use_sim_time = bool(self.get_parameter("use_sim_time").value)
        checks = [
            self._guard("scan", lambda: self.scan.evaluate(steady=steady, ros_now=ros_now)),
            self._guard("commands", lambda: self.commands.evaluate(steady=steady)),
            self._guard("publishers", self._publisher_check),
        ]
        checks.extend(self.report_reader.checks(now=time.time()))
        try:
            if self.audit is None:
                self.audit = AuditLog(self.audit_path)
            self.audit.record(checks)
            self.audit_error = None
        except (OSError, ValueError) as error:
            if self.audit_error != str(error):
                self.get_logger().error(f"Audit logging unavailable: {error}")
            self.audit_error = str(error)
        if self.audit_error:
            checks.append(Check.unavailable("audit", f"Audit logging unavailable: {self.audit_error}"))
        else:
            checks.append(Check("audit", OK, "Local audit logging available", OK,
                                "Audit logging active", {"path": str(self.audit_path)}))
        array = DiagnosticArray()
        array.header.stamp = self.get_clock().now().to_msg()
        for check in checks:
            common = {"enabled": check.enabled, "condition_current": check.authoritative}
            array.status.append(diagnostic_status(
                "coverage/" + check.name, check.coverage, check.coverage_message, common))
            array.status.append(diagnostic_status(
                check.name, check.level, check.message, {**common, **check.evidence}))
        self.diagnostics.publish(array)

    def destroy_node(self):
        if self.audit is not None:
            self.audit.close()
        return super().destroy_node()


def main(args=None):
    rclpy.init(args=args)
    node = None
    try:
        node = GlitchedMonitor()
        rclpy.spin(node)
    except (KeyboardInterrupt, ExternalShutdownException):
        pass
    finally:
        if node is not None:
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
