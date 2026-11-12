"""Synthetic scanner fixtures shared by unit and optional ROS integration tests."""

import json
from pathlib import Path
import sys


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def report_fixture(name="trivy-rootfs.json"):
    return json.loads((EXAMPLES / name).read_text())


def fake_trivy(directory):
    """An actual child executable, without invoking or downloading real Trivy."""
    executable = Path(directory) / "fake-trivy"
    payload = repr(json.dumps(report_fixture()))
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys, time\n"
        "mode = os.environ.get('GLITCHED_TEST_MODE', 'success')\n"
        "time.sleep(float(os.environ.get('GLITCHED_TEST_DELAY', '0')))\n"
        "if mode == 'timeout': time.sleep(5)\n"
        "if mode == 'failure':\n"
        "    print('synthetic scanner error', file=sys.stderr)\n"
        "    sys.exit(2)\n"
        "output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])\n"
        f"report = json.loads({payload})\n"
        "if sys.argv[1] == 'fs':\n"
        "    report['Results'][0]['Class'] = 'lang-pkgs'\n"
        "    report['Results'][0]['Type'] = 'pip'\n"
        "if mode == 'clean': report['Results'][0]['Vulnerabilities'] = None\n"
        "if mode == 'unsupported': report['Results'] = []\n"
        "output.write_text('broken json' if mode == 'malformed' else json.dumps(report))\n"
    )
    executable.chmod(0o700)
    return executable


def scan_state(*, findings=True, success_at="2026-01-01T00:00:00+00:00"):
    from glitched.reports import parse_trivy
    normalized, _ = parse_trivy(report_fixture(), kind="rootfs")
    return {"schema_version": 1, "targets": [{
        "kind": "rootfs", "path": "/", "attempt_status": "success",
        "attempted_at": success_at, "completed_at": success_at,
        "last_success_at": success_at, "supported": True, "error": "",
        "findings": normalized if findings else [],
    }]}
