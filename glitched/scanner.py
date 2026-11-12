"""Independent, non-ROS Trivy helper. Never installs tools or changes packages."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading

from .core import positive
from .paths import state_directory
from .reports import parse_trivy, read_json, utc_now, validate_state


DEFAULTS = {"rootfs": "/", "project_dirs": [], "interval_s": 21600,
            "timeout_s": 300, "trivy_executable": "trivy"}


def load_config(path=None):
    config = dict(DEFAULTS)
    if path:
        supplied = read_json(path)
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS):
            raise ValueError("Scanner configuration contains unknown fields")
        config.update(supplied)
    for name in ("interval_s", "timeout_s"):
        config[name] = positive(config[name], name)
    if config["rootfs"] is not None and (
            not isinstance(config["rootfs"], str) or not config["rootfs"]):
        raise ValueError("rootfs must be a path or null")
    if not isinstance(config["project_dirs"], list) or any(
            not isinstance(path, str) or not path for path in config["project_dirs"]):
        raise ValueError("project_dirs must be a list of paths")
    if not isinstance(config["trivy_executable"], str) or not config["trivy_executable"]:
        raise ValueError("trivy_executable must be an executable name or path")
    if config["rootfs"] is None and not config["project_dirs"]:
        raise ValueError("Configure at least one scan target")
    return config


def configured_targets(config):
    targets = []
    if config["rootfs"] is not None:
        targets.append(("rootfs", str(Path(config["rootfs"]).expanduser().resolve())))
    targets.extend(("fs", str(Path(path).expanduser().resolve()))
                   for path in config["project_dirs"])
    return list(dict.fromkeys(targets))


def atomic_write(path, value):
    """Readers see either the previous complete state or the next complete state."""
    descriptor, temporary = tempfile.mkstemp(prefix=".scan-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def scanner_lock(directory):
    """Also prevent overlapping scans across multiple helper processes."""
    with open(directory / "scan.lock", "a", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another glitched scanner owns this state directory") from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


class Scanner:
    def __init__(self, config, directory):
        self.config = config
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "scan-state.json"
        self.child = None
        self.initial_state_error = None
        try:
            prior = validate_state(read_json(self.path))
        except FileNotFoundError:
            prior = {"targets": []}
        except (OSError, ValueError, TypeError, OverflowError) as error:
            prior = {"targets": []}
            self.initial_state_error = str(error)
        previous = {(item["kind"], item["path"]): item for item in prior["targets"]}
        self.state = {"schema_version": 1, "updated_at": utc_now(), "targets": []}
        for kind, path in configured_targets(config):
            target = dict(previous.get((kind, path), {}))
            target.update(kind=kind, path=path, attempt_status="pending", attempted_at=None,
                          completed_at=None, error="")
            target.setdefault("last_success_at", None)
            target.setdefault("supported", False)
            target.setdefault("findings", [])
            self.state["targets"].append(target)

    def save(self):
        self.state["updated_at"] = utc_now()
        atomic_write(self.path, self.state)

    def cancel(self):
        child = self.child
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _execute(self, kind, path):
        executable = shutil.which(self.config["trivy_executable"])
        if executable is None:
            raise FileNotFoundError("Trivy executable not found; install it separately")
        if not Path(path).is_dir():
            raise ValueError(f"Scan target is not a readable directory: {path}")
        with tempfile.TemporaryDirectory(prefix="scan-", dir=self.directory) as temporary:
            output = Path(temporary) / "report.json"
            command = [executable, kind, "--scanners", "vuln", "--format", "json",
                       "--exit-code", "0", "--timeout", f'{self.config["timeout_s"]}s',
                       "--output", str(output)]
            if kind == "rootfs":
                command.extend(["--pkg-types", "os"])
            command.append(path)
            with tempfile.TemporaryFile() as stderr:
                self.child = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                              stderr=stderr, start_new_session=True)
                try:
                    returncode = self.child.wait(timeout=self.config["timeout_s"])
                except subprocess.TimeoutExpired:
                    self.cancel()
                    self.child.wait()
                    raise
                finally:
                    self.child = None
                if returncode != 0:
                    stderr.seek(0, os.SEEK_END)
                    size = stderr.tell()
                    stderr.seek(max(0, size - 2000))
                    message = stderr.read().decode("utf-8", errors="replace").strip()
                    raise RuntimeError(f"Trivy exited {returncode}: {message}")
            return parse_trivy(read_json(output), kind=kind)

    def run_cycle(self, stop=None):
        all_success = True
        for target in self.state["targets"]:
            if stop is not None and stop.is_set():
                return False
            target.update(attempt_status="running", attempted_at=utc_now(),
                          completed_at=None, error="")
            self.save()
            try:
                findings, supported = self._execute(target["kind"], target["path"])
                if not supported:
                    target.update(attempt_status="unsupported",
                                  error="No supported dependency coverage detected for this target")
                else:
                    target.update(attempt_status="success", findings=findings,
                                  supported=True, last_success_at=utc_now())
            except FileNotFoundError as error:
                target.update(attempt_status="unavailable", error=str(error))
            except subprocess.TimeoutExpired:
                target.update(attempt_status="failed", error="Trivy scan timed out")
            except (OSError, ValueError, TypeError, OverflowError, RuntimeError) as error:
                target.update(attempt_status="failed", error=str(error)[:2000])
            target["completed_at"] = utc_now()
            all_success = all_success and target["attempt_status"] == "success"
            self.save()
        return all_success


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Scanner JSON configuration")
    parser.add_argument("--state-dir", help="Shared state directory (default: XDG state/glitched)")
    parser.add_argument("--once", action="store_true", help="Scan once and exit")
    args = parser.parse_args(argv)
    stop = threading.Event()
    scanner = None

    def shutdown(signum, frame):
        stop.set()
        if scanner is not None:
            scanner.cancel()

    old_handlers = {}
    try:
        config = load_config(args.config)
        directory = state_directory(args.state_dir)
        directory.mkdir(parents=True, exist_ok=True)
        for signum in (signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, shutdown)
        with scanner_lock(directory):
            scanner = Scanner(config, directory)
            if scanner.initial_state_error:
                print(f"Previous scanner state unavailable: {scanner.initial_state_error}",
                      file=sys.stderr)
            scanner.save()
            while not stop.is_set():
                success = scanner.run_cycle(stop)
                if args.once:
                    return 0 if success else 1
                stop.wait(config["interval_s"])
        return 0
    except (OSError, ValueError, TypeError, OverflowError, RuntimeError) as error:
        print(f"glitched_scan: {error}", file=sys.stderr)
        return 2
    finally:
        if scanner is not None:
            scanner.cancel()
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
