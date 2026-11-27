"""Gitleaks adapter for commit history between a merge base and PR head."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


TOOL_VERSION = "8.30.1"
_SHA_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
DEFAULT_CONFIG = Path(__file__).with_name("gitleaks.toml")


def build_command(merge_base: str, head_sha: str, report_path: Path, config_path: Path = DEFAULT_CONFIG) -> list[str]:
    if not _SHA_RE.fullmatch(merge_base) or not _SHA_RE.fullmatch(head_sha):
        raise ValueError("commit range must use full hexadecimal SHAs")
    return [
        "gitleaks",
        "git",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--config",
        str(config_path),
        "--redact=100",
        "--no-banner",
        "--log-opts",
        f"{merge_base}..{head_sha}",
    ]


def run_gitleaks(
    repository: Path,
    merge_base: str,
    head_sha: str,
    *,
    report_path: Path,
    config_path: Path = DEFAULT_CONFIG,
    timeout_seconds: int = 600,
    runner: Callable[..., Any] = subprocess.run,
) -> ScannerResult:
    try:
        command = build_command(merge_base, head_sha, report_path, config_path)
    except (TypeError, ValueError):
        return ScannerResult("gitleaks", head_sha, ResultStatus.ERROR, error_code="invalid_commit_range")
    try:
        completed = runner(
            command,
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("gitleaks", head_sha, ResultStatus.ERROR, error_code="scanner_timeout")
    except OSError:
        return ScannerResult("gitleaks", head_sha, ResultStatus.ERROR, error_code="scanner_unavailable")
    try:
        raw = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ScannerResult("gitleaks", head_sha, ResultStatus.ERROR, error_code="report_unavailable")
    return parse_report(raw, head_sha, completed.returncode)


def parse_report(raw: str, sha: str, exit_code: int) -> ScannerResult:
    try:
        payload = json.loads(raw)
        if not isinstance(payload, list):
            raise ValueError
        findings = tuple(_parse_finding(item) for item in payload)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ScannerResult("gitleaks", sha, ResultStatus.ERROR, error_code="invalid_output")
    if exit_code not in (0, 1):
        if findings:
            return ScannerResult("gitleaks", sha, ResultStatus.PARTIAL, findings, ("scanner_execution_error",))
        return ScannerResult("gitleaks", sha, ResultStatus.ERROR, error_code="scanner_execution_error")
    return ScannerResult("gitleaks", sha, ResultStatus.COMPLETED, findings)


def _parse_finding(payload: Any) -> Finding:
    if not isinstance(payload, dict):
        raise ValueError
    secret = payload.get("Secret")
    path = payload.get("File")
    if isinstance(path, str):
        normalized_path = path.replace("\\", "/")
        if normalized_path.startswith("/") or ".." in normalized_path.split("/"):
            normalized_path = None
        elif isinstance(secret, str) and secret:
            normalized_path = normalized_path.replace(secret, "[redacted]")
        path = normalized_path
    else:
        path = None
    line = payload.get("StartLine")
    if type(line) is not int or line < 1:
        line = None
    rule_id = payload.get("RuleID")
    if not isinstance(rule_id, str) or not rule_id:
        rule_id = "gitleaks-detection"
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="Gitleaks detected a secret",
        path=path,
        line=line,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--sha")
    parser.add_argument("--merge-base")
    parser.add_argument("--head-sha")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("gitleaks-report.json"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    arguments = parser.parse_args()
    if arguments.version:
        print(TOOL_VERSION)
    elif arguments.sha and arguments.merge_base and arguments.head_sha:
        result = run_gitleaks(
            arguments.repository,
            arguments.merge_base,
            arguments.head_sha,
            report_path=arguments.report,
            config_path=arguments.config,
        )
        print(result.to_json())
    else:
        parser.error("--sha, --merge-base and --head-sha are required unless --version is used")
