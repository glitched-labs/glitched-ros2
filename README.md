# glitched

**A watchdog for your ROS 2 robot.** glitched runs alongside your robot software
and continuously answers two questions:

1. **Is the robot behaving plausibly right now?** Are sensor messages arriving
   on time, do their values look believable, are motion commands sane, and is
   anything unexpected publishing on critical topics?
2. **Is the robot's software known to be vulnerable?** A background helper
   periodically scans the installed OS packages (and optionally your project
   directories) for published CVEs using [Trivy](https://trivy.dev).

Everything it finds is reported on the standard ROS `/diagnostics` topic once
per second, and every change is appended to a local JSONL audit log. That's
all it does: **glitched observes and reports — it never stops the robot,
changes software, or takes any corrective action.** Think of it as a smoke
detector, not a sprinkler system.

## What it checks

| Check | On by default? | What it catches |
| --- | --- | --- |
| Scan freshness | Yes | Lidar driver dead, stalled, or publishing stale/future-dated frames on `/scan` |
| Scan content | Yes | Blinded sensor (nearly all beams invalid), frozen bit-identical frames, stuck single-value echoes, broken range metadata |
| Command sanity | Yes | NaN/infinite values in `/cmd_vel` from a buggy planner or teleop |
| Command limits | No — calibrate first | Commanded speeds above limits you set for your robot |
| Motion consistency | No — calibrate first | Robot ignoring commands, moving without commands, or grossly implausible odometry |
| Publisher allowlist | No — configure first | An unexpected node name publishing on a critical topic |
| Package vulnerabilities | Yes (helper process) | Known CVEs in installed OS packages and configured project dependencies |

Two design rules run through every check:

- **Coverage and condition are separate.** "I cannot see the sensor" is never
  reported as "the sensor is fine." A disabled, unobserved, or failed check
  never reports OK.
- **Plausibility is not ground truth.** These checks catch faults and lazy
  attacks (frozen, blinded, replayed, inconsistent data). A spoofed stream
  with realistic noise and consistent motion passes them. Publisher names are
  anomaly indicators, not authenticated identities — use SROS2/DDS security
  for real authentication.

## What it does NOT do

No motion commands, no emergency stops, no firmware changes, no package
installs or patches, no network calls of its own (Trivy fetches its own
vulnerability database). It does not cover source-built ROS packages or
firmware in CVE scans, does not detect host intrusions (processes/files), and
claims no safety certification. If the host is compromised, this observer and
its local results may be too. Essential physical protection belongs in
independent safety hardware and validated control logic.

## How it works

Two independent processes share a local state directory:

```
 /scan ──────────┐
 /cmd_vel ───────┤   glitched_monitor (ROS node)
 /odom ──────────┤   freshness + content + command + publisher checks
 ROS graph ──────┘        │                    ▲
                          ▼                    │ reads scan-state.json
                    /diagnostics          state directory ◄── glitched_scan
                    (1 Hz, coverage +     events.jsonl         (no ROS; runs
                     condition per check)  audit log            Trivy every 6 h)
```

- `glitched_monitor` subscribes to your robot's topics and publishes paired
  statuses per check: `glitched/coverage/<name>` (can I currently assess
  this?) and `glitched/<name>` (what did I observe?). Evidence is attached as
  JSON key/values in standard `DiagnosticArray` messages.
- `glitched_scan` is a plain Python process (no ROS required) that invokes an
  installed Trivy executable, normalizes the results, and atomically writes
  them to `scan-state.json` for the monitor to report. Failed scans never
  erase the last good findings; results older than 24 h are flagged stale.

HIGH/CRITICAL findings produce ERROR level diagnostics; LOW/MEDIUM/UNKNOWN
produce WARN. Finding activations, changes, and resolutions are appended to
`events.jsonl` (rotated at ~5 MiB, 3 backups).

## Requirements

- Ubuntu 24.04 with ROS 2 Jazzy, `colcon`, `rosdep`, Python 3.12
- [Trivy](https://trivy.dev) installed separately (must support
  `rootfs --pkg-types os` and JSON SchemaVersion 2 reports); its database
  downloads need network access. A missing tool or failed database update is
  reported as a coverage failure, never as a clean scan.

## Quick start

```bash
source /opt/ros/jazzy/setup.bash
mkdir -p ~/glitched_ws/src
cd ~/glitched_ws
git clone https://github.com/glitched-labs/glitched-ros2.git src/glitched
rosdep install --from-paths src/glitched --ignore-src -r -y
colcon build --packages-select glitched --symlink-install
source install/setup.bash
ros2 launch glitched glitched.launch.py
```

Watch the results in another sourced terminal:

```bash
ros2 topic echo /diagnostics
```

The launch file starts both processes. The scanner scans immediately, then
every six hours; each target has a five-minute timeout. Run one helper per
robot and run both processes as the same unprivileged account — no
administrator privileges are requested.

## State directory

By default `$XDG_STATE_HOME/glitched`, falling back to
`~/.local/state/glitched`:

| File | Purpose |
| --- | --- |
| `scan-state.json` | Latest attempt and last successful findings for each target |
| `events.jsonl` | Finding activation, meaningful changes, resolution and coverage transitions |
| `events.jsonl.1`–`.3` | Rotated audit history; approximately 5 MiB per file |
| `scan.lock` | Cross-process helper lock |

Override with `state_dir:=/absolute/path` on the launch command; a file lock
prevents two helpers from scanning into the same directory concurrently.
Treat the directory as sensitive operational data; diagnostics are visible to
any ROS subscriber your network/security policy allows.

## Configuration

Copy `config/monitor.yaml` and `config/scanner.json` somewhere writable and
launch with absolute paths:

```bash
ros2 launch glitched glitched.launch.py \
  monitor_config:=/absolute/path/monitor.yaml \
  scanner_config:=/absolute/path/scanner.json \
  state_dir:=/absolute/path/glitched-state
```

All monitor parameters except ROS's `use_sim_time` are read-only after
startup; restart to apply changes. The launch `state_dir` argument takes
precedence over the monitor YAML value so both processes share one directory.

### Monitor parameters

| Monitor | Default / configuration |
| --- | --- |
| Scan freshness | Enabled, `sensor_msgs/LaserScan` on `/scan`; five-second initial grace, 0.6-second arrival and capture-age limits, 0.1-second future tolerance |
| Clock health | Monotonic arrival deadlines and a steady diagnostics timer; ROS time for capture-age comparisons. With `use_sim_time: true`, a clock that does not advance for one second makes scan coverage unavailable |
| Scan content | Enabled; flags frames where more than `scan_max_invalid_ratio` of beams are invalid, `scan_frozen_frames` consecutive bit-identical frames, or `scan_stuck_value_ratio` of valid beams collapsing to one value |
| Commands | Enabled, `geometry_msgs/Twist` on `/cmd_vel`; observe all six components for NaN/infinity. Coverage expires after one second without a command |
| Command limits | Disabled. Enable `command_limits_enabled` after setting `max_linear_speed_mps` and `max_angular_speed_radps`; norms include all three axes. Example 0.5 m/s and 1 rad/s values are not validated robot limits |
| Motion consistency | Disabled. Enable `motion_consistency_enabled` after calibrating `motion_mismatch_tolerance_mps` and `motion_mismatch_dwell_s`; compares commanded `/cmd_vel` speed with `nav_msgs/Odometry` twist on `odom_topic`. Calibrate by watching `gap_mps` in the evidence during ~10 minutes of normal driving: set tolerance ≈ 2× the observed worst case and dwell longer than your hardest acceleration ramp |
| Publishers | Disabled. Enable `publisher_check_enabled` with `publisher_allowlist`, a string list such as `["/cmd_vel=/control/controller"]`. Repeat the topic for multiple permitted nodes |
| Package results | Degraded without a successful report; reports become stale after `max_scan_age_s`, default 86400 seconds |

Publisher allowlists apply separately to each configured topic. Nodes not
listed on that topic produce an anomaly. No publishers on a topic is not
itself an unexpected-publisher event; command/scan coverage reports missing
observations separately.

The observer subscribes using best-effort, volatile sensor-data QoS, accepting
common best-effort and reliable publishers. A delivery problem or incompatible
topic type becomes missing coverage. `/cmd_vel` must be `Twist`; this draft
does not support `TwistStamped`. Configure the topics to match the robot.

Arrival timestamps use `time.monotonic()`, while sensor header stamps are
compared with the node's ROS clock. Drivers must use that same clock domain.
Backwards clock jumps, invalid/unavailable ROS time and stalled simulated time
invalidate old sensor observations; new valid observations are needed for
recovery. A paused simulation deliberately produces degraded coverage, with
diagnostics continuing at one-second intervals using a steady clock.

### Scanner configuration

`config/scanner.json`:

```json
{
  "rootfs": "/",
  "project_dirs": [],
  "interval_s": 21600,
  "timeout_s": 300,
  "trivy_executable": "trivy"
}
```

`rootfs` selects OS-package scanning (`trivy rootfs --pkg-types os`); set it
to `null` to disable. `project_dirs` adds directories scanned with `trivy fs`
for supported language dependencies (pip, npm, etc.). At least one target is
required. **In a container, `/` means the container's filesystem, not the
host's** — mount and target the host filesystem explicitly if that is what
you intend.

Run a single scan manually (with or without ROS installed):

```bash
ros2 run glitched glitched_scan --config /absolute/path/scanner.json \
  --state-dir /absolute/path/glitched-state --once
# or, without ROS:
python3 -m glitched.scanner --config config/scanner.json \
  --state-dir /absolute/path/glitched-state --once
```

Omit `--once` for periodic scanning. `--once` exit codes: 0 all targets
scanned with recognized coverage, 1 a target failed/unavailable/unsupported,
2 configuration, locking or state-file error. Found vulnerabilities do **not**
fail a completed scan; severity is reported separately on `/diagnostics`.

A target with no recognized dependencies is reported `unsupported`, never
"clean" — zero findings only count when Trivy actually understood the target.
Scanner timestamps use wall-clock UTC, not simulation time.

The JSON files under `examples/` are synthetic Trivy-shaped fixtures; their
`GLITCHED-DEMO-*` identifiers are not real vulnerability advisories.

## Reading the diagnostics

Every check publishes two statuses once per second:

- `glitched/coverage/<monitor>`: is the check enabled and currently able to
  observe? (OK / WARN / STALE)
- `glitched/<monitor>`: the observed condition with JSON-encoded evidence
  key/values.

Monitor names: `scan`, `scan_content`, `commands`, `motion_consistency`,
`publishers`, `audit`, and `packages/<target-hash>` (target path in the
evidence). Findings have stable IDs; repeated observations do not re-activate
them and changing scan age alone does not flood the audit log. A monitor that
loses coverage retains its last findings rather than silently resolving them;
a fresh valid observation resolves them. On restart, active findings are
re-activated; the event log persists but active tracking is not restored from
it.

## Tests

Core logic tests need only the Python standard library:

```bash
cd /path/to/glitched-ros2
python3 -m unittest discover -s test -v
```

These exercise the detection rules, Trivy report parsing, scanner process
handling (timeouts, locking, atomic state replacement) and the plausibility
monitors with a local synthetic scanner — they never download Trivy, contact
vulnerability services, or scan the host. ROS smoke tests skip when `rclpy`
is absent; on a Jazzy machine run:

```bash
colcon test --packages-select glitched --event-handlers console_direct+
colcon test-result --verbose
```

Run the ROS smoke tests in an isolated ROS domain without other `/clock`
publishers. Finally, verify against reality: run the helper with real Trivy
on a controlled Ubuntu target, inspect the coverage and findings, and launch
both processes with your robot's topics and thresholds. Unit fixtures are not
a substitute for on-target verification.

## Troubleshooting

- **Scan remains stale:** check topic type/QoS, publishing rate, header
  stamps, matching clock domains, `use_sim_time` and whether `/clock` is
  advancing.
- **Commands remain unknown:** the robot may publish commands only while
  moving, use a different topic, or use `TwistStamped`. Silence is unknown
  coverage.
- **Motion consistency stays unavailable:** it needs both a current command
  and current odometry within its one-second history window; check
  `odom_topic` and that the base publishes odometry continuously.
- **Scanner unavailable:** verify the configured executable, readable target,
  vulnerability database access, shared state path and directory permissions.
  After installing a missing scanner, restart the helper for an immediate
  retry.
- **Unsupported rootfs/project:** inspect Trivy's supported OS/package
  ecosystems and dependency files; an arbitrary directory may contain no
  recognizable dependencies.
- **Audit unavailable:** check directory permissions and disk space. Rotation
  bounds retained history; export logs separately for longer retention.

## Scope, licensing, and boundaries

Coverage is limited to the rules above and the dependencies recognized by
Trivy and its vulnerability data. This package does not establish
comprehensive coverage of custom/source-built ROS packages, firmware, active
attacks, sensor content correctness beyond the stated plausibility rules,
collision risk, braking performance or authenticated publisher identity. It
has no host process/file intrusion detector in this version. No safety
certification is claimed.

The package manifest deliberately retains placeholder maintainer details and
`Proprietary` metadata; choose real maintainers and a distribution license
before inviting external reuse. A public repository does not itself grant a
reuse license. The package uses the Python import namespace `glitched`; keep
it in a separate Python environment from other applications installing the
same name. The existing Oomwoo simulator is not modified or connected.
