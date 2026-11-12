"""Start the ROS observer and the separate non-ROS scanner process."""

from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, ExecuteProcess
from launch.substitutions import LaunchConfiguration, PathJoinSubstitution
from launch_ros.actions import Node
from launch_ros.parameter_descriptions import ParameterValue
from launch_ros.substitutions import FindPackagePrefix, FindPackageShare


def generate_launch_description():
    share = FindPackageShare("glitched")
    state_dir = LaunchConfiguration("state_dir")
    return LaunchDescription([
        DeclareLaunchArgument("state_dir", default_value="",
                              description="Shared local state directory; empty uses XDG default"),
        DeclareLaunchArgument("monitor_config", default_value=PathJoinSubstitution(
            [share, "config", "monitor.yaml"])),
        DeclareLaunchArgument("scanner_config", default_value=PathJoinSubstitution(
            [share, "config", "scanner.json"])),
        Node(package="glitched", executable="glitched_monitor", name="glitched_monitor",
             output="screen", parameters=[LaunchConfiguration("monitor_config"),
                                           {"state_dir": ParameterValue(state_dir, value_type=str)}]),
        ExecuteProcess(
            cmd=[PathJoinSubstitution([FindPackagePrefix("glitched"), "lib", "glitched",
                                       "glitched_scan"]),
                 "--config", LaunchConfiguration("scanner_config"), "--state-dir", state_dir],
            name="glitched_scan", output="screen"),
    ])
