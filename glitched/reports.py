"""Validate Trivy results and expose scanner coverage independently of findings."""

from datetime import datetime, timezone
import hashlib
import json
import math

from .core import Check, Finding, OK, WARN, ERROR, STALE


MAX_REPORT_BYTES = 64 * 1024 * 1024
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Expected a timezone-aware ISO timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.timestamp()


def read_json(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds 64 MiB limit")
    return json.loads(data, parse_constant=_invalid_number, parse_float=_finite_float)


def _invalid_number(value):
    raise ValueError(f"Nonfinite JSON number: {value}")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        _invalid_number(value)
    return number


def target_id(kind, path):
    return hashlib.sha256(f"{kind}\0{path}".encode()).hexdigest()[:20]


def parse_trivy(report, *, kind):
    """Return normalized vulnerabilities and whether dependency coverage is known."""
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("Expected Trivy JSON SchemaVersion 2")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be an array")
    expected_class = "os-pkgs" if kind == "rootfs" else "lang-pkgs"
    supported = False
    findings = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("Invalid Trivy result entry")
        if result.get("Class") == expected_class and result.get("Type"):
            supported = True
        vulnerabilities = result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy Vulnerabilities must be an array or null")
        for item in vulnerabilities:
            if not isinstance(item, dict):
                raise ValueError("Invalid vulnerability entry")
            for key in ("VulnerabilityID", "PkgName", "InstalledVersion"):
                if not isinstance(item.get(key), str) or not item[key]:
                    raise ValueError(f"Vulnerability missing {key}")
            severity = item.get("Severity", "UNKNOWN")
            if not isinstance(severity, str):
                raise ValueError("Invalid vulnerability severity")
            source_severity = severity
            severity = severity.upper()
            normalized = {
                "id": item["VulnerabilityID"], "package": item["PkgName"],
                "installed_version": item["InstalledVersion"],
                "fixed_version": item.get("FixedVersion", ""),
                "severity": severity if severity in SEVERITIES else "UNKNOWN",
                "source_severity": source_severity,
                "target": result["Target"],
            }
            if not isinstance(normalized["fixed_version"], str):
                raise ValueError("Invalid fixed version")
            identity = (normalized["id"], normalized["package"],
                        normalized["installed_version"], normalized["target"])
            findings[identity] = normalized
    if kind == "rootfs":
        metadata = report.get("Metadata") or {}
        if not isinstance(metadata, dict):
            raise ValueError("Invalid Trivy metadata")
        operating_system = metadata.get("OS") or {}
        if not isinstance(operating_system, dict):
            raise ValueError("Invalid Trivy OS metadata")
        supported = supported and bool(operating_system.get("Family"))
    return sorted(findings.values(), key=lambda item: (
        item["target"], item["package"], item["id"], item["installed_version"])), supported


def validate_state(state):
    if (not isinstance(state, dict) or type(state.get("schema_version")) is not int
            or state["schema_version"] != 1):
        raise ValueError("Unknown glitched scan-state schema")
    targets = state.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("Scan state must contain at least one target")
    identities = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("Invalid scan target")
        if target.get("kind") not in ("rootfs", "fs"):
            raise ValueError("Unsupported scan target kind")
        if not isinstance(target.get("path"), str) or not target["path"].startswith("/"):
            raise ValueError("Scan target must be an absolute path")
        identity = (target["kind"], target["path"])
        if identity in identities:
            raise ValueError("Duplicate scan target")
        identities.add(identity)
        if target.get("attempt_status") not in (
                "pending", "running", "success", "failed", "unavailable", "unsupported"):
            raise ValueError("Invalid scan attempt status")
        for key in ("attempted_at", "completed_at", "last_success_at"):
            if target.get(key) is not None:
                timestamp(target[key])
        if not isinstance(target.get("supported"), bool):
            raise ValueError("Missing target coverage state")
        if not isinstance(target.get("error", ""), str):
            raise ValueError("Invalid scanner error text")
        findings = target.get("findings")
        if not isinstance(findings, list):
            raise ValueError("Missing vulnerability findings")
        for item in findings:
            if not isinstance(item, dict):
                raise ValueError("Invalid normalized finding")
            for key in ("id", "package", "installed_version", "target", "fixed_version",
                        "severity", "source_severity"):
                if not isinstance(item.get(key), str):
                    raise ValueError(f"Invalid normalized finding {key}")
            if not all(item[key] for key in ("id", "package", "installed_version", "target")):
                raise ValueError("Empty normalized finding identity")
            if item["severity"] not in SEVERITIES:
                raise ValueError("Invalid normalized severity")
        if target["attempt_status"] == "success":
            if not target.get("last_success_at") or not target["supported"]:
                raise ValueError("Successful scan requires timestamp and known coverage")
        if findings and not target.get("last_success_at"):
            raise ValueError("Findings require a successful scan timestamp")
    return state


def state_checks(state, *, now, max_age_s=86400.0):
    validate_state(state)
    checks = []
    for target in state["targets"]:
        group = "packages/" + target_id(target["kind"], target["path"])
        findings = []
        for item in target["findings"]:
            code = hashlib.sha256(json.dumps(
                [item[key] for key in ("id", "package", "installed_version", "target")]
            ).encode()).hexdigest()[:20]
            findings.append(Finding(group, code, item["severity"],
                                    f'{item["id"]} affects {item["package"]}', item))
        success = target.get("last_success_at")
        age = now - timestamp(success) if success else None
        current = (age is not None and 0 <= age <= max_age_s
                   and target["attempt_status"] == "success" and target["supported"])
        if current:
            coverage = OK
            coverage_message = "Latest scan completed; dependency coverage detected"
        elif age is not None and age > max_age_s:
            coverage = STALE
            coverage_message = "Last successful scan is stale"
        elif age is not None and age < 0:
            coverage = STALE
            coverage_message = "Scan timestamp is in the future; check host clock"
        else:
            coverage = WARN if target["attempt_status"] == "running" else STALE
            coverage_message = f'Scanner status: {target["attempt_status"]}'
        level = (ERROR if any(f.severity in ("HIGH", "CRITICAL") for f in findings)
                 else WARN if findings else OK if current else STALE)
        message = (f"{len(findings)} known vulnerability findings (last successful scan)"
                   if findings else "No known vulnerabilities detected in scanned dependencies"
                   if current else "No current vulnerability conclusion")
        counts = {severity: sum(f.severity == severity for f in findings)
                  for severity in sorted(SEVERITIES)}
        evidence = {"kind": target["kind"], "path": target["path"],
                    "attempt_status": target["attempt_status"],
                    "last_success_at": success, "scan_age_s": age,
                    "counts": counts, "error": target.get("error", ""),
                    "coverage_scope": "Supported OS packages" if target["kind"] == "rootfs"
                    else "Supported language dependencies in this directory"}
        checks.append(Check(group, coverage, coverage_message, level, message,
                            evidence, findings, authoritative=current))
    return checks


class ReportReader:
    """Cache parsing between atomic updates; freshness is still evaluated each tick."""

    def __init__(self, path, *, max_age_s=86400.0):
        self.path = path
        self.max_age = max_age_s
        self.signature = None
        self.state = None

    def checks(self, *, now):
        try:
            stat = self.path.stat()
            signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
            if signature != self.signature:
                state = validate_state(read_json(self.path))
                self.state, self.signature = state, signature
            if self.state is None or not math.isfinite(now):
                raise ValueError("Scan state or wall clock unavailable")
            return state_checks(self.state, now=now, max_age_s=self.max_age)
        except (OSError, ValueError, TypeError, OverflowError) as error:
            message = f"Scan report unavailable: {error}"
            if self.state is not None and math.isfinite(now):
                checks = state_checks(self.state, now=now, max_age_s=self.max_age)
                for check in checks:
                    check.coverage = STALE
                    check.coverage_message = message
                    check.authoritative = False
                    if not check.findings:
                        check.level = STALE
                        check.message = "No current vulnerability conclusion"
                return checks
            return [Check.unavailable("packages", message)]
