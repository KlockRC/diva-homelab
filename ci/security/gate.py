"""Aggregate trusted scanner results into a High/Critical-only merge gate."""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ci.security.result import InvalidResult, ResultStatus, ScannerResult, Severity, parse_result_json


EXPECTED_TOOLS = ("semgrep", "trivy", "trivy-image", "gitleaks")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


@dataclass(frozen=True)
class BlockingFinding:
    tool: str
    severity: Severity
    rule_id: str
    path: str | None
    line: int | None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "tool": self.tool,
            "severity": self.severity.value,
            "rule_id": self.rule_id,
        }
        if self.path is not None:
            result["path"] = self.path
        if self.line is not None:
            result["line"] = self.line
        return result


@dataclass(frozen=True)
class GateDecision:
    sha: str
    status: str
    scanner_count: int
    blocking_findings: tuple[BlockingFinding, ...]
    warnings: tuple[str, ...]
    ignored_result_count: int
    finding_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "sha": self.sha,
            "status": self.status,
            "scanner_count": self.scanner_count,
            "blocking_count": len(self.blocking_findings),
            "blocking_findings": [finding.to_dict() for finding in self.blocking_findings],
            "warnings": list(self.warnings),
            "ignored_result_count": self.ignored_result_count,
            "finding_counts": dict(self.finding_counts),
        }


def evaluate(
    results: Sequence[ScannerResult],
    sha: str,
    *,
    expected_tools: Sequence[str] = EXPECTED_TOOLS,
    report_upload_succeeded: bool = True,
    quality_gate_passed: bool | None = None,
) -> GateDecision:
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise ValueError("invalid target SHA")
    current = tuple(result for result in results if result.sha == sha)
    ignored_count = len(results) - len(current)
    warnings: list[str] = []
    if ignored_count:
        warnings.append(f"stale_results_discarded:{ignored_count}")
    if not current:
        warnings.append("no_results_for_commit")
    seen_tools = {result.tool for result in current}
    warnings.extend(f"missing_result:{tool}" for tool in expected_tools if tool not in seen_tools)
    if not report_upload_succeeded:
        warnings.append("report_upload_failed")
    if quality_gate_passed is False:
        warnings.append("sonar_quality_gate_failed")

    counts = {severity.value: 0 for severity in Severity}
    blockers: list[BlockingFinding] = []
    for result in current:
        if result.status is ResultStatus.ERROR:
            warnings.append(f"{result.tool}:{result.error_code}")
        elif result.status is ResultStatus.PARTIAL:
            warnings.append(f"{result.tool}:partial_coverage")
        for finding in result.findings:
            counts[finding.severity.value] += 1
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                blockers.append(
                    BlockingFinding(
                        result.tool,
                        finding.severity,
                        finding.rule_id,
                        finding.path,
                        finding.line,
                    )
                )
    return GateDecision(
        sha=sha,
        status="blocked" if blockers else "passed",
        scanner_count=len(current),
        blocking_findings=tuple(blockers),
        warnings=tuple(dict.fromkeys(warnings)),
        ignored_result_count=ignored_count,
        finding_counts=counts,
    )


def normalize_sonar_impact(impact: str) -> Severity:
    mapping = {
        "BLOCKER": Severity.CRITICAL,
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MAJOR": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "MINOR": Severity.LOW,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "INFORMATIONAL": Severity.INFO,
    }
    try:
        return mapping[impact.upper()]
    except (AttributeError, KeyError):
        raise ValueError("unknown Sonar impact") from None


def markdown_summary(decision: GateDecision) -> str:
    label = "BLOCKED" if decision.status == "blocked" else "PASSED"
    lines = [
        "# Security gate",
        "",
        f"- Decision: **{label}**",
        f"- Commit SHA: `{decision.sha}`",
        f"- Scanners with results: {decision.scanner_count}",
        f"- High/Critical findings: {len(decision.blocking_findings)}",
    ]
    if decision.blocking_findings:
        lines.extend(["", "## Blocking findings", "", "| Scanner | Severity | Rule/CVE | Path | Line |", "| --- | --- | --- | --- | ---: |"])
        for finding in decision.blocking_findings:
            lines.append(
                "| "
                + " | ".join(
                    _escape(value)
                    for value in (
                        finding.tool,
                        finding.severity.value,
                        finding.rule_id,
                        finding.path or "—",
                        str(finding.line) if finding.line is not None else "—",
                    )
                )
                + " |"
            )
    if decision.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- `{_escape(warning)}`" for warning in decision.warnings)
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    escaped = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=True)
    for marker in ("#", "`", "*", "_", "[", "]", "(", ")", "|"):
        escaped = escaped.replace(marker, "&#" + str(ord(marker)) + ";")
    return escaped


def _read_result(tool: str, path: Path | None, sha: str) -> ScannerResult | None:
    if path is None:
        return None
    try:
        return parse_result_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, InvalidResult):
        return ScannerResult(tool, sha, ResultStatus.ERROR, error_code="invalid_output")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--trivy", type=Path)
    parser.add_argument("--trivy-image", type=Path)
    parser.add_argument("--gitleaks", type=Path)
    parser.add_argument("--report-upload-failed", action="store_true")
    parser.add_argument("--quality-gate-failed", action="store_true")
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--decision", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    paths = {
        "semgrep": args.semgrep,
        "trivy": args.trivy,
        "trivy-image": args.trivy_image,
        "gitleaks": args.gitleaks,
    }
    results = [result for tool, path in paths.items() if (result := _read_result(tool, path, args.sha)) is not None]
    decision = evaluate(
        results,
        args.sha,
        report_upload_succeeded=not args.report_upload_failed,
        quality_gate_passed=not args.quality_gate_failed,
    )
    serialized = json.dumps(decision.to_dict(), ensure_ascii=False, sort_keys=True)
    if args.summary:
        args.summary.write_text(markdown_summary(decision), encoding="utf-8")
    if args.decision:
        args.decision.write_text(serialized + "\n", encoding="utf-8")
    if args.github_output:
        args.github_output.write_text(
            f"decision={decision.status}\nblocking_count={len(decision.blocking_findings)}\nsha={decision.sha}\n",
            encoding="utf-8",
        )
    print(serialized)
    return 1 if decision.status == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
