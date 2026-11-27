"""Build a GitHub summary and sanitized JSON artifact from scanner results."""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from ci.security.result import Finding, ResultStatus, ScannerResult, Severity, parse_result_json


_REPOSITORY_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_BRANCHES = frozenset({"development", "homolog", "main"})
_SEVERITIES = tuple(Severity)


@dataclass(frozen=True)
class ReportContext:
    repository: str
    pull_request: int
    target_branch: str
    sha: str
    base_sha: str
    workflow_url: str
    application_scope: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise ValueError("invalid repository")
        if type(self.pull_request) is not int or self.pull_request < 1:
            raise ValueError("invalid pull request number")
        if self.target_branch not in _BRANCHES:
            raise ValueError("invalid target branch")
        if not isinstance(self.sha, str) or not _SHA_RE.fullmatch(self.sha):
            raise ValueError("invalid commit SHA")
        if not isinstance(self.base_sha, str) or not _SHA_RE.fullmatch(self.base_sha):
            raise ValueError("invalid base SHA")
        if not isinstance(self.workflow_url, str):
            raise ValueError("invalid workflow URL")
        if self.application_scope is not None and (
            not isinstance(self.application_scope, str) or not self.application_scope.strip() or len(self.application_scope) > 360
        ):
            raise ValueError("invalid application scope note")
        parsed = urlparse(self.workflow_url)
        expected_path = f"/{self.repository}/actions/runs/"
        if parsed.scheme != "https" or parsed.netloc != "github.com" or not parsed.path.startswith(expected_path):
            raise ValueError("invalid workflow URL")
        run_id = parsed.path.removeprefix(expected_path)
        if not run_id.isdecimal() or parsed.query or parsed.fragment:
            raise ValueError("invalid workflow URL")

    @classmethod
    def from_dict(cls, value: Any) -> "ReportContext":
        required = {"repository", "pull_request", "target_branch", "sha", "base_sha", "workflow_url"}
        allowed = required | {"application_scope"}
        if not isinstance(value, dict) or not required.issubset(value) or set(value) - allowed:
            raise ValueError("invalid report context fields")
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "repository": self.repository,
            "pull_request": self.pull_request,
            "target_branch": self.target_branch,
            "sha": self.sha,
            "base_sha": self.base_sha,
            "workflow_url": self.workflow_url,
        }
        if self.application_scope is not None:
            result["application_scope"] = self.application_scope
        return result


def build_report(context: ReportContext, results: Sequence[ScannerResult]) -> tuple[dict[str, Any], str]:
    if not results:
        raise ValueError("at least one scanner result is required")
    if any(result.sha != context.sha for result in results):
        raise ValueError("scanner result SHA does not match report context")

    scanner_rows = [_scanner_record(result) for result in results]
    counts = {severity.value: 0 for severity in _SEVERITIES}
    for result in results:
        for finding in result.findings:
            counts[finding.severity.value] += 1
    artifact = {
        "schema_version": 1,
        "context": context.to_dict(),
        "scanners": scanner_rows,
        "counts": counts,
    }
    return artifact, _markdown_summary(context, results, counts)


def _scanner_record(result: ScannerResult) -> dict[str, Any]:
    record: dict[str, Any] = {
        "tool": result.tool,
        "sha": result.sha,
        "status": result.status.value,
        "findings": [_finding_record(finding) for finding in result.findings],
    }
    if result.partial_coverage:
        record["partial_coverage"] = list(result.partial_coverage)
    if result.not_applicable_target is not None:
        record["not_applicable_target"] = result.not_applicable_target
    if result.error_code is not None:
        record["error_code"] = result.error_code
    return record


def _finding_record(finding: Finding) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "path": finding.path,
            "line": finding.line,
            "package": finding.package,
            "version": finding.version,
        }.items()
        if value is not None
    }


def _markdown_summary(context: ReportContext, results: Sequence[ScannerResult], counts: dict[str, int]) -> str:
    lines = [
        "# Pull request security scan",
        "",
        f"- Repository: `{_escape(context.repository)}`",
        f"- Pull request: #{context.pull_request}",
        f"- Target branch: `{_escape(context.target_branch)}`",
        f"- Commit SHA: `{context.sha}`",
        f"- Base SHA: `{context.base_sha}`",
        f"- Workflow run: [{_escape(context.workflow_url)}]({_escape_url(context.workflow_url)})",
        "",
        "| Scanner | State | Findings | Coverage note |",
        "| --- | --- | ---: | --- |",
    ]
    if context.application_scope is not None:
        lines.insert(8, f"- Application source coverage: {_escape(context.application_scope)}")
    for result in results:
        state = result.status.value
        notes = list(result.partial_coverage)
        if result.not_applicable_target:
            notes.append(f"not applicable: {result.not_applicable_target}")
        if result.error_code:
            notes.append(f"error: {result.error_code}")
        note_text = "; ".join(notes) if notes else "—"
        lines.append(
            f"| `{_escape(result.tool)}` | `{_escape(state)}` | {len(result.findings)} | {_escape(note_text)} |"
        )
    lines.extend(
        [
            "",
            "## Finding counts",
            "",
            "| Severity | Count |",
            "| --- | ---: |",
        ]
    )
    for severity, count in counts.items():
        lines.append(f"| {_escape(severity)} | {count} |")
    lines.extend(["", "## Findings", "", "| Scanner | Severity | Rule/CVE | Path | Line | Package | Version |", "| --- | --- | --- | --- | ---: | --- | --- |"])
    for result in results:
        for finding in result.findings:
            lines.append(
                "| "
                + " | ".join(
                    _escape(value)
                    for value in (
                        result.tool,
                        finding.severity.value,
                        finding.rule_id,
                        finding.path or "—",
                        str(finding.line) if finding.line is not None else "—",
                        finding.package or "—",
                        finding.version or "—",
                    )
                )
                + " |"
            )
    if not any(result.findings for result in results):
        lines.append("| — | — | No findings | — | — | — | — |")
    return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    single_line = str(value).replace("\r", " ").replace("\n", " ")
    escaped = html.escape(single_line, quote=True)
    for marker in ("#", "`", "*", "_", "[", "]", "(", ")", "|"):
        escaped = escaped.replace(marker, "&#" + str(ord(marker)) + ";")
    return escaped


def _escape_url(value: str) -> str:
    # URLs are constrained by ReportContext and contain no Markdown delimiters.
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    context = ReportContext.from_dict(json.loads(args.context.read_text(encoding="utf-8")))
    results = [parse_result_json(path.read_text(encoding="utf-8")) for path in args.result]
    artifact, summary = build_report(context, results)
    args.artifact.write_text(json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.summary.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
