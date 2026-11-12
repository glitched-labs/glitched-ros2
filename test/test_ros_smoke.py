"""Runs with real ROS messages on Jazzy; explicitly skipped on non-ROS hosts."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from support import fake_trivy


ROS_AVAILABLE = importlib.util.find_spec("rclpy") is not None


@unittest.skipUnless(ROS_AVAILABLE, "ROS 2 runtime not installed")
class RosSmokeTests(unittest.TestCase):
    def setUp(self):
        import rclpy
        from diagnostic_msgs.msg import DiagnosticArray
        from geometry_msgs.msg import Twist
        from rclpy.context import Context
        from rclpy.executors import SingleThreadedExecutor
        from rclpy.node import Node
        from rclpy.parameter import Parameter
        from rclpy.qos import qos_profile_sensor_data
        from sensor_msgs.msg import LaserScan
        from glitched.monitor import GlitchedMonitor

        self.rclpy = rclpy
        self.Parameter = Parameter
        self.LaserScan, self.Twist = LaserScan, Twist
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.context = Context()
        rclpy.init(args=[], context=self.context)
        self.executor = SingleThreadedExecutor(context=self.context)
        self.source_name = f"glitched_test_source_{os.getpid()}"
        self.scan_topic = f"/glitched_test_{os.getpid()}/scan"
        self.command_topic = f"/glitched_test_{os.getpid()}/cmd_vel"
        overrides = {
            "state_dir": str(self.directory / "state"), "scan_topic": self.scan_topic,
            "command_topic": self.command_topic, "command_limits_enabled": True,
            "publisher_check_enabled": True,
            "publisher_allowlist": [f"{self.command_topic}=/{self.source_name}"],
        }
        self.monitor = GlitchedMonitor(context=self.context, parameter_overrides=[
            Parameter(name, value=value) for name, value in overrides.items()])
        self.source = Node(self.source_name, context=self.context)
        self.executor.add_node(self.monitor)
        self.executor.add_node(self.source)
        self.scan_publisher = self.source.create_publisher(
            LaserScan, self.scan_topic, qos_profile_sensor_data)
        self.command_publisher = self.source.create_publisher(Twist, self.command_topic, 10)
        self.received = []
        self.latest = {}

        def receive(message):
            self.received.append(message)
            self.latest = {status.name: status for status in message.status}

        self.sink = self.source.create_subscription(DiagnosticArray, "/diagnostics", receive, 10)
        self.helper = None
        self.rogue = None

    def tearDown(self):
        if self.helper is not None and self.helper.poll() is None:
            self.helper.terminate()
            self.helper.wait(timeout=5)
        if self.rogue is not None:
            self.executor.remove_node(self.rogue)
            self.rogue.destroy_node()
        self.executor.remove_node(self.monitor)
        self.executor.remove_node(self.source)
        self.monitor.destroy_node()
        self.source.destroy_node()
        self.executor.shutdown()
        self.rclpy.shutdown(context=self.context)
        self.temporary.cleanup()

    def observe_until(self, predicate, *, timeout=8, scans=True, speed=0.1, stamp=None):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if scans:
                message = self.LaserScan()
                if stamp is None:
                    message.header.stamp = self.source.get_clock().now().to_msg()
                else:
                    message.header.stamp.sec = stamp
                message.ranges = [1.0, 1.0, 1.0]
                self.scan_publisher.publish(message)
            command = self.Twist()
            command.linear.x = speed
            self.command_publisher.publish(command)
            self.executor.spin_once(timeout_sec=0.02)
            if predicate():
                return
        self.fail("Timed out waiting for diagnostics: " + str(
            {name: (status.level, status.message) for name, status in self.latest.items()}))

    def status_is(self, name, level):
        status = self.latest.get("glitched/" + name)
        return status is not None and status.level == level

    def test_reporting_and_recovery_while_separate_scanner_runs(self):
        from rclpy.node import Node

        executable = fake_trivy(self.directory)
        config = self.directory / "scanner.json"
        config.write_text(json.dumps({"rootfs": str(self.directory),
                                      "trivy_executable": str(executable), "timeout_s": 15}))
        environment = dict(os.environ, GLITCHED_TEST_MODE="success", GLITCHED_TEST_DELAY="8")
        self.helper = subprocess.Popen(
            [sys.executable, "-m", "glitched.scanner", "--config", str(config),
             "--state-dir", str(self.directory / "state"), "--once"],
            cwd=Path(__file__).resolve().parents[1], env=environment)
        self.observe_until(lambda: self.status_is("scan", 0) and self.status_is("commands", 0))
        self.assertIsNone(self.helper.poll(), "Scanner should still be running independently")
        self.observe_until(lambda: self.status_is("commands", 2), speed=1.0)
        self.observe_until(lambda: self.status_is("commands", 0))
        self.observe_until(lambda: self.status_is("scan", 2), scans=False)
        self.observe_until(lambda: self.status_is("scan", 0))
        self.rogue = Node(f"glitched_unexpected_{os.getpid()}", context=self.context)
        self.executor.add_node(self.rogue)
        publisher = self.rogue.create_publisher(self.Twist, self.command_topic, 10)
        self.observe_until(lambda: self.status_is("publishers", 1))
        self.rogue.destroy_publisher(publisher)
        self.observe_until(lambda: self.status_is("publishers", 0))
        self.observe_until(lambda: any(
            name.startswith("glitched/packages/") and status.level == 2
            for name, status in self.latest.items()), timeout=12)
        self.assertEqual(self.helper.wait(timeout=5), 0)

    def test_paused_simulation_clock_does_not_stop_diagnostics(self):
        from rosgraph_msgs.msg import Clock

        self.monitor.set_parameters([self.Parameter("use_sim_time", value=True)])
        clock_publisher = self.source.create_publisher(Clock, "/clock", 10)
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            clock = Clock()
            clock.clock.sec = 100
            clock_publisher.publish(clock)
            self.executor.spin_once(timeout_sec=0.02)
        self.observe_until(lambda: self.status_is("coverage/scan", 3) and
                           "not advancing" in self.latest["glitched/coverage/scan"].message,
                           stamp=100)
        previous = len(self.received)
        self.observe_until(lambda: len(self.received) >= previous + 2, stamp=100)


if __name__ == "__main__":
    unittest.main()
