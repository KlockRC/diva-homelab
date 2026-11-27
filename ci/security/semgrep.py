"""Semgrep CE adapter with a ruleset pinned in the trusted base revision."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable

from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


TOOL_VERSION = "1.187.0"
RULESET_VERSION = "diva-security-rules-v1"
SUPPORTED_SOURCE_SUFFIXES = frozenset(
    {
        ".c", ".cc", ".cpp", ".cs", ".dart", ".ex", ".exs", ".go", ".h", ".hpp",
        ".java", ".js", ".jsx", ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".scala",
        ".sol", ".swift", ".ts", ".tsx", ".vue",
    }
)
DEFAULT_RULES = Path(__file__).with_name("semgrep-rules.yml")


def build_command(target: Path, rules_path: Path = DEFAULT_RULES) -> list[str]:
    return [
        "semgrep",
        "scan",
        "--json",
        "--metrics=off",
        "--no-git-ignore",
        "--disable-nosem",
        "--config",
        str(rules_path),
        "--",
        str(target),
    ]


def find_supported_files(target: Path) -> tuple[Path, ...]:
    if target.is_file():
        return (target,) if target.suffix.lower() in SUPPORTED_SOURCE_SUFFIXES else ()
    if not target.is_dir():
        return ()
    return tuple(
        path
        for path in sorted(target.rglob("*"))
        if path.is_file() and path.suffix.lower() in SUPPORTED_SOURCE_SUFFIXES
    )


def run_semgrep(
    target: Path,
    sha: str,
    *,
    rules_path: Path = DEFAULT_RULES,
    timeout_seconds: int = 300,
    runner: Callable[..., Any] = subprocess.run,
) -> ScannerResult:
    if not find_supported_files(target):
        return ScannerResult(
            "semgrep",
            sha,
            ResultStatus.NOT_APPLICABLE,
            not_applicable_target="supported application source files",
        )
    try:
        completed = runner(
            build_command(target, rules_path),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ScannerResult("semgrep", sha, ResultStatus.ERROR, error_code="scanner_timeout")
    except OSError:
        return ScannerResult("semgrep", sha, ResultStatus.ERROR, error_code="scanner_unavailable")
    return parse_output(completed.stdout, sha, completed.returncode)


def parse_output(raw: str, sha: str, exit_code: int) -> ScannerResult:
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError
        raw_findings = payload.get("results")
        if not isinstance(raw_findings, list):
            raise ValueError
        findings = tuple(_parse_finding(item) for item in raw_findings)
        errors = payload.get("errors", [])
        if not isinstance(errors, list):
            raise ValueError
    except (TypeError, ValueError, json.JSONDecodeError):
        return ScannerResult("semgrep", sha, ResultStatus.ERROR, error_code="invalid_output")

    if errors:
        return ScannerResult(
            "semgrep",
            sha,
            ResultStatus.PARTIAL,
            findings,
            tuple(f"scanner_error_{index}" for index, _ in enumerate(errors, start=1)),
        )
    if exit_code not in (0, 1):
        if findings:
            return ScannerResult("semgrep", sha, ResultStatus.PARTIAL, findings, ("scanner_execution_error",))
        return ScannerResult("semgrep", sha, ResultStatus.ERROR, error_code="scanner_execution_error")
    return ScannerResult("semgrep", sha, ResultStatus.COMPLETED, findings)


def _parse_finding(payload: Any) -> Finding:
    if not isinstance(payload, dict):
        raise ValueError
    extra = payload.get("extra")
    if not isinstance(extra, dict):
        raise ValueError
    raw_severity = extra.get("severity")
    severity = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }.get(raw_severity)
    if severity is None:
        raise ValueError
    start = payload.get("start")
    line = start.get("line") if isinstance(start, dict) else None
    return Finding(
        rule_id=payload.get("check_id"),
        severity=severity,
        # Do not publish rule messages: some rules interpolate matched source.
        title="Semgrep rule finding",
        path=payload.get("path"),
        line=line,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--sha")
    parser.add_argument("target", nargs="?", type=Path)
    arguments = parser.parse_args()
    if arguments.version:
        print(TOOL_VERSION)
    elif arguments.sha and arguments.target:
        print(run_semgrep(arguments.target, arguments.sha).to_json())
    else:
        parser.error("--sha and target are required unless --version is used")
