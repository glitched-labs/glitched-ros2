# glitched

An initial **observational** ROS 2 safety and security monitor for Jazzy / Ubuntu
24.04. `glitched_monitor` observes sensor freshness, commands and ROS publisher
names. A separate `glitched_scan` process invokes an installed Trivy executable
to check known package vulnerabilities. The two share local scan-state files.

The only application topic published is `/diagnostics`. This package does not
publish motion commands, request stops, change firmware, install tools, patch
packages or provide independent safety enforcement. ROS itself also publishes
its standard parameter events and logging traffic.

## Build and run on Ubuntu / ROS 2 Jazzy

Prerequisites: a working Jazzy installation, `colcon`, `rosdep`, Python 3.12,
setuptools and pytest. Install Trivy separately from its official distribution;
the executable must support `rootfs --pkg-types os` and JSON SchemaVersion 2
reports. Neither ROS nor Trivy is bundled. Initial database downloads and updates
normally need network access. A missing tool or failed database update is a
coverage failure, never an empty successful scan.

Clone this standalone package into a ROS workspace on your Ubuntu machine:

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

In another sourced terminal:

```bash
ros2 topic echo /diagnostics
```

The launch file starts two independent processes. The helper scans immediately,
then waits six hours after each completed cycle. Each target has a five-minute
timeout and is scanned sequentially. A file lock prevents another helper from
scanning into the **same state directory** concurrently. Run one helper per robot;
separate state directories do not coordinate scans. No administrator privileges
are requested. Run the observer and helper as the same unprivileged account.

By default storage is `$XDG_STATE_HOME/glitched`, falling back to
`~/.local/state/glitched`:

| File | Purpose |
| --- | --- |
| `scan-state.json` | Latest attempt and last successful findings for each target |
| `events.jsonl` | Finding activation, meaningful changes, resolution and coverage transitions |
| `events.jsonl.1`–`.3` | Rotated audit history; approximately 5 MiB per file |
| `scan.lock` | Cross-process helper lock |

Override the shared directory with `state_dir:=/absolute/path` on the launch
command. The helper's temporary reports are removed after each scan. Trivy uses
its own cache and vulnerability databases separately. Treat the state directory
as sensitive local operational data; diagnostics are visible to ROS subscribers
that your network/security policy allows.

## Configure the monitors

Copy `config/monitor.yaml` and `config/scanner.json` to writable configuration
locations. Launch with their absolute paths:

```bash
ros2 launch glitched glitched.launch.py \
  monitor_config:=/absolute/path/monitor.yaml \
  scanner_config:=/absolute/path/scanner.json \
  state_dir:=/absolute/path/glitched-state
```

All monitor parameters except ROS's `use_sim_time` are read-only after startup;
restart to apply changes. The launch `state_dir` argument takes precedence over
the monitor YAML value, ensuring both processes use the same directory.

| Monitor | Default / configuration |
| --- | --- |
| Scan freshness | Enabled, `sensor_msgs/LaserScan` on `/scan`; five-second initial grace, 0.6-second arrival and capture-age limits, 0.1-second future tolerance |
| Clock health | Monotonic arrival deadlines and a steady diagnostics timer; ROS time for capture-age comparisons. With `use_sim_time: true`, a clock that does not advance for one second makes scan coverage unavailable |
| Commands | Enabled, `geometry_msgs/Twist` on `/cmd_vel`; observe all six components for NaN/infinity. Coverage expires after one second without a command |
| Command limits | Disabled. Enable `command_limits_enabled` after setting `max_linear_speed_mps` and `max_angular_speed_radps`; norms include all three axes. Example 0.5 m/s and 1 rad/s values are not validated robot limits |
| Publishers | Disabled. Enable `publisher_check_enabled` with `publisher_allowlist`, a string list such as `["/cmd_vel=/control/controller"]`. Repeat the topic for multiple permitted nodes |
| Package results | Degraded without a successful report; reports become stale after `max_scan_age_s`, default 86400 seconds |

Publisher allowlists apply separately to each configured topic. Nodes not listed
on that topic produce an anomaly. Names are **not authenticated identities** and
can be spoofed. No publishers on a topic is not itself an unexpected-publisher
event; command/scan coverage reports missing observations separately. Configure
SROS2/DDS access control separately where appropriate.

The observer subscribes using best-effort, volatile sensor-data QoS, accepting
common best-effort and reliable publishers. A delivery problem or incompatible
topic type becomes missing coverage. `/cmd_vel` must be `Twist`; this draft does
not support `TwistStamped`. Configure the topics to match the robot.

Arrival timestamps use `time.monotonic()`, while sensor header stamps are compared
with the node's ROS clock. Drivers must use that same clock domain. Backwards
clock jumps, invalid/unavailable ROS time and stalled simulated time invalidate
old sensor observations; new valid observations are needed for recovery. A
paused simulation deliberately produces degraded coverage, with diagnostics
continuing at one-second intervals using a steady clock. There is no delayed
startup exemption for an invalid command or a bad scan already received.

## Configure and run the scanner independently

`config/scanner.json` contains:

```json
{
  "rootfs": "/",
  "project_dirs": [],
  "interval_s": 21600,
  "timeout_s": 300,
  "trivy_executable": "trivy"
}
```

`rootfs` selects OS-package scanning through `trivy rootfs --pkg-types os`.
Set it to `null` to disable OS scanning. `project_dirs` adds explicitly chosen
directories scanned through `trivy fs` for supported language dependencies.
At least one target is required. In a container, `/` means the **container's**
filesystem, not the robot host's; use an appropriate readable filesystem mount
and target path if host coverage is intended. This draft does not configure
mounts or access host containers for you.

Run one scan from a sourced ROS workspace:

```bash
ros2 run glitched glitched_scan --config /absolute/path/scanner.json \
  --state-dir /absolute/path/glitched-state --once
```

Or, without ROS installed, run the helper from this package directory:

```bash
python3 -m glitched.scanner --config config/scanner.json \
  --state-dir /absolute/path/glitched-state --once
```

Omit `--once` for periodic scanning. Exit codes for `--once` are 0 when all
targets completed with recognized coverage, 1 for a failed/unavailable/unsupported
target, and 2 for configuration, locking or state-file errors. Vulnerabilities
do **not** make a completed scan fail; their severity is reported separately.
Stopping the helper terminates its active Trivy process group.

Each target record stores attempt status and timestamps, last successful scan
time, coverage recognition, errors and normalized vulnerability details: ID,
package, installed/fixed versions, original severity and dependency target.
Updates replace the state file atomically. Failed, missing, malformed or
unsupported scans retain earlier successful findings. A target without
recognized dependency coverage does not receive a clean result merely because
Trivy returned no vulnerabilities. Scanner results use wall-clock UTC, not
simulation time; future-dated or older-than-24-hour successful results are stale.

The JSON files under `examples/` are synthetic Trivy-shaped fixtures; their
`GLITCHED-DEMO-*` identifiers are not real vulnerability advisories. They are
test data, not evidence about the installed robot.

## Diagnostics and audit semantics

Every check publishes two statuses once per second:

- `glitched/coverage/<monitor>`: enabled state and whether observations are current.
- `glitched/<monitor>`: the observed condition and supporting key/value evidence.

Monitor names are `scan`, `commands`, `publishers`, `audit`, and
`packages/<target-hash>` (with target path in the evidence). Before a valid
scanner state is available, `packages` reports unknown coverage. Key/value
values are JSON-encoded strings, using the standard `DiagnosticArray` message.
Disabled, unobserved and failed checks never report an OK condition. Command
finiteness can pass while command-limit **coverage** remains explicitly disabled.

Known HIGH/CRITICAL package findings produce ERROR; LOW/MEDIUM/UNKNOWN produce
WARN, retaining Trivy's source severity. Old known findings remain visible
alongside stale coverage. A current successful zero-finding report says only
that no known vulnerabilities were detected in the scanned dependencies.

Findings have stable IDs for their monitor and condition. Repeated observations
do not re-activate them; changing scan age alone does not flood the audit log.
An unavailable monitor cannot resolve its earlier findings. A fresh valid
observation can resolve them, even when a separate optional check remains
disabled. An unreadable updated report retains in-memory last-known findings
with stale coverage. On observer restart, current findings are activated again;
the event log persists, but active tracking is not restored from that log.
Audit disk errors appear as unavailable audit coverage on `/diagnostics`.

## Tests and verification limits

The core, parser, scanner and audit tests need only Python's standard library:

```bash
cd /path/to/glitched-ros2
python3 -m unittest discover -s test -v
```

The scanner tests execute a local synthetic scanner, testing process timeouts,
failure preservation, locking and atomic state replacement. They never download
Trivy, contact vulnerability services or scan the host. ROS smoke tests skip
explicitly when `rclpy` is absent.

On Ubuntu / Jazzy, after building and sourcing the workspace:

```bash
colcon test --packages-select glitched --event-handlers console_direct+
colcon test-result --verbose
```

The real ROS smoke tests publish synthetic `LaserScan` and `Twist` observations,
check healthy/fault/recovery diagnostics and unexpected publishers, verify the
observer reports while a separate synthetic scanner runs, and check continued
diagnostics during a paused `/clock`. Run these tests in an isolated ROS domain
without other `/clock` publishers. They do not operate a robot or contact Trivy.
Finally, run the helper against a controlled real Ubuntu target with real Trivy,
inspect the resulting coverage and package findings, and launch both processes
with your robot's topic and threshold configuration.

This draft was authored on a host without ROS 2, colcon or Trivy. ROS-independent
verification can run here; Linux/ROS execution and real vulnerability database
coverage must be verified on the target environment. Unit fixtures are not a
substitute for those checks.

## Troubleshooting and boundaries

- **Scan remains stale:** check topic type/QoS, publishing rate, header stamps,
  matching clock domains, `use_sim_time` and whether `/clock` is advancing.
- **Commands remain unknown:** the robot may publish commands only while moving,
  use a different topic or use `TwistStamped`. Silence is unknown coverage.
- **Scanner unavailable:** verify the configured executable, readable target,
  vulnerability database access, shared state path and directory permissions.
  After installing a missing scanner, restart the helper for an immediate retry.
- **Unsupported rootfs/project:** inspect Trivy's supported OS/package ecosystems
  and dependency files. An arbitrary directory or source tree may have no
  identifiable supported dependencies.
- **Audit unavailable:** check directory permissions and disk space. Rotation
  bounds retained history; export logs separately if longer retention is needed.

Coverage is limited to these rules and the dependencies recognized by Trivy and
its vulnerability data. This package does not establish comprehensive coverage
of custom/source-built ROS packages, firmware, active attacks, sensor content
correctness, collision risk, braking performance or authenticated publisher
identity. It has no host process/file intrusion detector in this initial version.
If Linux or ROS is compromised, this observer and its local results may also be
compromised. Essential physical protection belongs in independent safety hardware
and validated control logic. No safety certification is claimed.

The package manifest deliberately retains placeholder maintainer details and
`Proprietary` metadata; choose real maintainers and a distribution license before
inviting external reuse. A public repository does not itself grant a reuse license.
This package uses the Python import namespace `glitched`; use a separate Python
environment from other applications that install a package with the same name.
The existing Oomwoo simulator is not modified or connected.
