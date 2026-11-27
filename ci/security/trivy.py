"""Trivy filesystem and immutable-image scan adapters."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


TOOL_VERSION = "0.76.2"
SCANNERS = "vuln,misconfig,secret"
_IMAGE_DIGEST_RE = re.compile(r"\A[^\s@]+@sha256:[0-9a-f]{64}\Z")
_SEVERITY = {
    "UNKNOWN": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def build_fs_command(target: Path) -> list[str]:
    return [
        "trivy",
        "fs",
        "--scanners",
        SCANNERS,
        "--format",
        "json",
        "--exit-code",
        "0",
        "--config=",
        "--ignorefile=",
        "--secret-config=",
        "--no-progress",
        str(target),
    ]


def build_image_command(image_digest_ref: str) -> list[str]:
    if not isinstance(image_digest_ref, str) or not _IMAGE_DIGEST_RE.fullmatch(image_digest_ref):
        raise ValueError("image reference must end in an immutable sha256 digest")
    return [
        "trivy",
        "image",
        "--scanners",
        SCANNERS,
        "--format",
        "json",
        "--exit-code",
        "0",
        "--config=",
        "--ignorefile=",
        "--secret-config=",
        "--no-progress",
        image_digest_ref,
    ]


def run_filesystem_scan(
    target: Path,
    sha: str,
    *,
    timeout_seconds: int = 600,
    runner: Callable[..., Any] = subprocess.run,
) -> ScannerResult:
    try:
        completed = runner(
            build_fs_command(target),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("trivy", sha, ResultStatus.ERROR, error_code="scanner_timeout")
    except OSError:
        return ScannerResult("trivy", sha, ResultStatus.ERROR, error_code="scanner_unavailable")
    return parse_output(completed.stdout, sha, completed.returncode, tool="trivy")


def scan_image_digest(
    image_digest_ref: str,
    sha: str,
    *,
    timeout_seconds: int = 600,
    runner: Callable[..., Any] = subprocess.run,
) -> ScannerResult:
    try:
        command = build_image_command(image_digest_ref)
    except (TypeError, ValueError):
        return ScannerResult("trivy-image", sha, ResultStatus.ERROR, error_code="invalid_image_digest")
    try:
        completed = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("trivy-image", sha, ResultStatus.ERROR, error_code="scanner_timeout")
    except OSError:
        return ScannerResult("trivy-image", sha, ResultStatus.ERROR, error_code="scanner_unavailable")
    return parse_output(completed.stdout, sha, completed.returncode, tool="trivy-image")


def classify_image_target(
    sha: str,
    *,
    build_expected: bool,
    build_succeeded: bool | None = None,
) -> ScannerResult:
    if not build_expected:
        return ScannerResult(
            "trivy-image",
            sha,
            ResultStatus.NOT_APPLICABLE,
            not_applicable_target="repository container image build",
        )
    if build_succeeded is not True:
        return ScannerResult("trivy-image", sha, ResultStatus.ERROR, error_code="image_build_failed")
    return ScannerResult("trivy-image", sha, ResultStatus.ERROR, error_code="image_digest_required")


def parse_output(raw: str, sha: str, exit_code: int, *, tool: str = "trivy") -> ScannerResult:
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict) or "Results" not in payload:
            raise ValueError
        raw_results = payload["Results"]
        if raw_results is None:
            raw_results = []
        if not isinstance(raw_results, list):
            raise ValueError
        findings: list[Finding] = []
        coverage_errors: list[str] = []
        for index, item in enumerate(raw_results, start=1):
            if not isinstance(item, dict):
                raise ValueError
            target = item.get("Target")
            if item.get("Error"):
                coverage_errors.append(f"target_scan_error_{index}")
            _append_vulnerabilities(findings, item.get("Vulnerabilities", []), target)
            _append_misconfigurations(findings, item.get("Misconfigurations", []), target)
            _append_secrets(findings, item.get("Secrets", []), target)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ScannerResult(tool, sha, ResultStatus.ERROR, error_code="invalid_output")

    if coverage_errors or exit_code != 0:
        reason = coverage_errors or ["scanner_execution_error"]
        if findings:
            return ScannerResult(tool, sha, ResultStatus.PARTIAL, tuple(findings), tuple(reason))
        return ScannerResult(tool, sha, ResultStatus.ERROR, error_code=reason[0])
    return ScannerResult(tool, sha, ResultStatus.COMPLETED, tuple(findings))


def _append_vulnerabilities(findings: list[Finding], items: Any, target: Any) -> None:
    if items is None:
        return
    if not isinstance(items, list):
        raise ValueError
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        findings.append(
            Finding(
                rule_id=item.get("VulnerabilityID"),
                severity=_severity(item.get("Severity")),
                title="Trivy vulnerability finding",
                path=target,
                package=item.get("PkgName"),
                version=item.get("InstalledVersion"),
            )
        )


def _append_misconfigurations(findings: list[Finding], items: Any, target: Any) -> None:
    if items is None:
        return
    if not isinstance(items, list):
        raise ValueError
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        findings.append(
            Finding(
                rule_id=item.get("ID"),
                severity=_severity(item.get("Severity")),
                title="Trivy configuration finding",
                path=target,
            )
        )


def _append_secrets(findings: list[Finding], items: Any, target: Any) -> None:
    if items is None:
        return
    if not isinstance(items, list):
        raise ValueError
    for item in items:
        if not isinstance(item, dict):
            raise ValueError
        findings.append(
            Finding(
                rule_id=item.get("RuleID") or item.get("Category") or "trivy-secret",
                severity=_severity(item.get("Severity", "HIGH")),
                title="Trivy secret finding",
                path=target,
                line=item.get("StartLine"),
            )
        )


def _severity(value: Any) -> Severity:
    if not isinstance(value, str) or value.upper() not in _SEVERITY:
        raise ValueError
    return _SEVERITY[value.upper()]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--sha")
    parser.add_argument("--image-digest")
    parser.add_argument("target", nargs="?", type=Path)
    arguments = parser.parse_args()
    if arguments.version:
        print(TOOL_VERSION)
    elif arguments.sha and arguments.image_digest:
        print(scan_image_digest(arguments.image_digest, arguments.sha).to_json())
    elif arguments.sha and arguments.target:
        print(run_filesystem_scan(arguments.target, arguments.sha).to_json())
    else:
        parser.error("--sha and a target or --image-digest are required unless --version is used")
