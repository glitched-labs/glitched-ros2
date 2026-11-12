import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from glitched.core import FindingTracker, OK, WARN, ERROR, STALE
from glitched.paths import state_directory
from glitched.reports import (ReportReader, parse_trivy, read_json, state_checks,
                             timestamp, validate_state)
from glitched.scanner import (Scanner, atomic_write, configured_targets,
                             load_config, scanner_lock)
from support import fake_trivy, report_fixture, scan_state


class ParserTests(unittest.TestCase):
    def test_realistic_rootfs_and_language_report_shapes(self):
        for name, kind, severity in (("trivy-rootfs.json", "rootfs", "HIGH"),
                                     ("trivy-project.json", "fs", "MEDIUM")):
            findings, supported = parse_trivy(report_fixture(name), kind=kind)
            self.assertTrue(supported)
            self.assertEqual(findings[0]["severity"], severity)

    def test_empty_and_null_vulnerabilities_with_known_coverage_are_clean(self):
        for value in (None, []):
            report = report_fixture()
            report["Results"][0]["Vulnerabilities"] = value
            self.assertEqual(parse_trivy(report, kind="rootfs"), ([], True))

    def test_unsupported_target_is_not_clean(self):
        report = report_fixture()
        report["Results"] = []
        self.assertEqual(parse_trivy(report, kind="rootfs"), ([], False))
        report = report_fixture()
        del report["Metadata"]
        self.assertFalse(parse_trivy(report, kind="rootfs")[1])

    def test_unknown_severity_preserves_source(self):
        report = report_fixture()
        report["Results"][0]["Vulnerabilities"][0]["Severity"] = "CUSTOM"
        findings, _ = parse_trivy(report, kind="rootfs")
        self.assertEqual(findings[0]["severity"], "UNKNOWN")
        self.assertEqual(findings[0]["source_severity"], "CUSTOM")

    def test_deduplicate_package_vulnerability_identity(self):
        report = report_fixture()
        report["Results"].append(copy.deepcopy(report["Results"][0]))
        self.assertEqual(len(parse_trivy(report, kind="rootfs")[0]), 1)

    def test_invalid_reports_rejected(self):
        cases = [None, {}, {"SchemaVersion": 2, "Results": {}},
                 {"SchemaVersion": 2, "Results": [None]}]
        missing_identity = report_fixture()
        del missing_identity["Results"][0]["Vulnerabilities"][0]["PkgName"]
        cases.append(missing_identity)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_trivy(value, kind="rootfs")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.state = scan_state()
        self.now = timestamp("2026-01-01T00:01:00+00:00")

    def test_high_and_lower_severity_mapping(self):
        self.assertEqual(state_checks(self.state, now=self.now)[0].level, ERROR)
        self.state["targets"][0]["findings"][0]["severity"] = "LOW"
        self.assertEqual(state_checks(self.state, now=self.now)[0].level, WARN)

    def test_clean_success(self):
        check = state_checks(scan_state(findings=False), now=self.now)[0]
        self.assertEqual((check.coverage, check.level), (OK, OK))

    def test_failed_attempt_keeps_known_findings(self):
        self.state["targets"][0]["attempt_status"] = "failed"
        check = state_checks(self.state, now=self.now)[0]
        self.assertEqual(check.coverage, STALE)
        self.assertEqual(check.level, ERROR)
        self.assertFalse(check.authoritative)
        self.assertEqual(len(check.findings), 1)

    def test_empty_failed_stale_future_pending_and_unsupported_never_clean(self):
        for status in ("failed", "pending", "unsupported", "unavailable", "running"):
            state = scan_state(findings=False)
            state["targets"][0]["attempt_status"] = status
            check = state_checks(state, now=self.now)[0]
            self.assertEqual(check.level, STALE)
            self.assertFalse(check.authoritative)
        for now in (self.now + 86400, self.now - 120):
            check = state_checks(scan_state(findings=False), now=now)[0]
            self.assertEqual(check.level, STALE)

    def test_empty_state_and_unsubstantiated_success_rejected(self):
        state = scan_state()
        state["targets"][0]["last_success_at"] = None
        for value in ({"schema_version": 1, "targets": []}, state):
            with self.assertRaises(ValueError):
                validate_state(value)

    def test_reader_handles_missing_and_corrupt_files_without_erasing_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scan-state.json"
            reader = ReportReader(path)
            self.assertEqual(reader.checks(now=self.now)[0].level, STALE)
            atomic_write(path, self.state)
            tracker = FindingTracker()
            tracker.update(reader.checks(now=self.now))
            path.write_text("not JSON")
            checks = reader.checks(now=self.now)
            self.assertEqual(checks[0].coverage, STALE)
            self.assertEqual(checks[0].level, ERROR)
            self.assertEqual(tracker.update(checks), [])
            self.assertEqual(len(tracker.active), 1)
            path.unlink()
            self.assertEqual(reader.checks(now=self.now)[0].level, ERROR)
            atomic_write(path, scan_state(findings=False))
            self.assertEqual(tracker.update(reader.checks(now=self.now))[0]["event"], "resolved")

    def test_reader_recalculates_freshness_without_file_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scan-state.json"
            atomic_write(path, scan_state(findings=False))
            reader = ReportReader(path)
            self.assertEqual(reader.checks(now=self.now)[0].level, OK)
            self.assertEqual(reader.checks(now=self.now + 86400)[0].level, STALE)

    def test_nonfinite_json_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            for literal in ("NaN", "Infinity", "-Infinity", "1e999"):
                path.write_text('{"value": ' + literal + '}')
                with self.subTest(literal=literal), self.assertRaises(ValueError):
                    read_json(path)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.executable = fake_trivy(self.directory)
        self.config = load_config()
        self.config.update(rootfs=str(self.directory), trivy_executable=str(self.executable),
                           timeout_s=1.0)
        self.scanner = Scanner(self.config, self.directory / "state")

    def test_successful_actual_child_process_and_clean_recovery(self):
        self.assertTrue(self.scanner.run_cycle())
        state = validate_state(read_json(self.scanner.path))
        self.assertEqual(state["targets"][0]["findings"][0]["id"], "GLITCHED-DEMO-001")
        with patch.dict(os.environ, {"GLITCHED_TEST_MODE": "clean"}):
            self.assertTrue(self.scanner.run_cycle())
        self.assertEqual(read_json(self.scanner.path)["targets"][0]["findings"], [])

    def test_failures_preserve_successful_results(self):
        self.assertTrue(self.scanner.run_cycle())
        previous = copy.deepcopy(self.scanner.state["targets"][0])
        for mode, status in (("failure", "failed"), ("malformed", "failed"),
                             ("unsupported", "unsupported"), ("timeout", "failed")):
            with self.subTest(mode=mode), patch.dict(os.environ, {"GLITCHED_TEST_MODE": mode}):
                self.assertFalse(self.scanner.run_cycle())
                target = read_json(self.scanner.path)["targets"][0]
                self.assertEqual(target["attempt_status"], status)
                self.assertEqual(target["findings"], previous["findings"])
                self.assertEqual(target["last_success_at"], previous["last_success_at"])

    def test_missing_executable(self):
        self.config["trivy_executable"] = str(self.directory / "missing-trivy")
        self.assertFalse(self.scanner.run_cycle())
        target = self.scanner.state["targets"][0]
        self.assertEqual(target["attempt_status"], "unavailable")
        self.assertIsNone(target["last_success_at"])

    def test_invalid_directory(self):
        self.config["rootfs"] = str(self.directory / "nonexistent")
        scanner = Scanner(self.config, self.directory / "other-state")
        self.assertFalse(scanner.run_cycle())
        self.assertEqual(scanner.state["targets"][0]["attempt_status"], "failed")

    def test_restart_preserves_findings_and_marks_pending(self):
        self.scanner.run_cycle()
        restarted = Scanner(self.config, self.scanner.directory)
        self.assertEqual(restarted.state["targets"][0]["attempt_status"], "pending")
        self.assertEqual(len(restarted.state["targets"][0]["findings"]), 1)

    def test_project_targets_and_deduplication(self):
        self.config["project_dirs"] = [str(self.directory)] * 2
        scanner = Scanner(self.config, self.directory / "project-state")
        self.assertEqual(len(configured_targets(self.config)), 2)
        self.assertTrue(scanner.run_cycle())
        self.assertEqual([target["kind"] for target in scanner.state["targets"]], ["rootfs", "fs"])

    def test_lock_prevents_second_helper(self):
        with scanner_lock(self.scanner.directory):
            with self.assertRaises(RuntimeError):
                with scanner_lock(self.scanner.directory):
                    self.fail("Second helper acquired the lock")

    def test_pending_state_cannot_appear_clean(self):
        self.scanner.save()
        checks = state_checks(read_json(self.scanner.path), now=time.time())
        self.assertEqual(checks[0].level, STALE)

    def test_atomic_state_is_always_complete_for_readers(self):
        path = self.directory / "atomic.json"
        atomic_write(path, {"sequence": 0})
        errors = []
        stop = threading.Event()

        def read_repeatedly():
            while not stop.is_set():
                try:
                    value = read_json(path)
                    if not isinstance(value.get("sequence"), int):
                        errors.append(value)
                except Exception as error:
                    errors.append(error)

        reader = threading.Thread(target=read_repeatedly)
        reader.start()
        try:
            for index in range(40):
                atomic_write(path, {"sequence": index})
        finally:
            stop.set()
            reader.join()
        self.assertEqual(errors, [])

    def test_once_cli_without_ros(self):
        config_path = self.directory / "config.json"
        config_path.write_text(json.dumps(self.config))
        process = subprocess.run(
            [sys.executable, "-m", "glitched.scanner", "--config", str(config_path),
             "--state-dir", str(self.directory / "cli-state"), "--once"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        state = read_json(self.directory / "cli-state" / "scan-state.json")
        self.assertEqual(state["targets"][0]["attempt_status"], "success")

    def test_bad_configuration_rejected(self):
        config_path = self.directory / "config.json"
        for supplied in ({"unknown": 1}, {"interval_s": 0}, {"timeout_s": True},
                         {"rootfs": None}, {"project_dirs": "/not-a-list"},
                         {"trivy_executable": ""}):
            config_path.write_text(json.dumps(supplied))
            with self.subTest(supplied=supplied), self.assertRaises(ValueError):
                load_config(config_path)

    def test_xdg_state_path(self):
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(self.directory)}):
            self.assertEqual(state_directory(), (self.directory / "glitched").resolve())


if __name__ == "__main__":
    unittest.main()
