"""Normalized, allowlisted results shared by the security scanners."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


_SHA_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_IDENTIFIER_RE = re.compile(r"\A[a-zA-Z0-9_.:/+-]{1,160}\Z")


class ResultStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Severity(str, Enum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvalidResult(ValueError):
    """A result file was malformed; messages never include its contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Finding:
    """Fields allowed in a report; snippets and matched values have no field."""

    rule_id: str
    severity: Severity
    title: str
    path: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.rule_id, "invalid_finding_rule")
        if not isinstance(self.severity, Severity):
            raise InvalidResult("invalid_finding_severity")
        _require_text(self.title, "invalid_finding_title", limit=240)
        if self.path is not None:
            _require_text(self.path, "invalid_finding_path", limit=500)
            if self.path.startswith(("/", "\\")) or ".." in self.path.replace("\\", "/").split("/"):
                raise InvalidResult("invalid_finding_path")
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise InvalidResult("invalid_finding_line")
        for value, code in ((self.package, "invalid_finding_package"), (self.version, "invalid_finding_version")):
            if value is not None:
                _require_text(value, code, limit=160)

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "rule_id": self.rule_id,
                "severity": self.severity.value,
                "title": self.title,
                "path": self.path,
                "line": self.line,
                "package": self.package,
                "version": self.version,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class ScannerResult:
    tool: str
    sha: str
    status: ResultStatus
    findings: tuple[Finding, ...] = ()
    partial_coverage: tuple[str, ...] = ()
    not_applicable_target: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.tool, "invalid_tool")
        if not isinstance(self.sha, str) or not _SHA_RE.fullmatch(self.sha):
            raise InvalidResult("invalid_sha")
        if not isinstance(self.status, ResultStatus):
            raise InvalidResult("invalid_status")
        if not isinstance(self.findings, tuple) or any(not isinstance(item, Finding) for item in self.findings):
            raise InvalidResult("invalid_findings")
        if not isinstance(self.partial_coverage, tuple) or any(
            not isinstance(item, str) or not item or len(item) > 240 for item in self.partial_coverage
        ):
            raise InvalidResult("invalid_partial_coverage")
        if self.not_applicable_target is not None:
            _require_text(self.not_applicable_target, "invalid_not_applicable_target", limit=240)
        if self.error_code is not None:
            _require_identifier(self.error_code, "invalid_error_code")
        if self.status is ResultStatus.NOT_APPLICABLE and not self.not_applicable_target:
            raise InvalidResult("missing_not_applicable_target")
        if self.status is not ResultStatus.NOT_APPLICABLE and self.not_applicable_target is not None:
            raise InvalidResult("unexpected_not_applicable_target")
        if self.status is ResultStatus.PARTIAL and not self.partial_coverage:
            raise InvalidResult("missing_partial_coverage")
        if self.status is not ResultStatus.PARTIAL and self.partial_coverage:
            raise InvalidResult("unexpected_partial_coverage")
        if self.status is ResultStatus.ERROR and not self.error_code:
            raise InvalidResult("missing_error_code")
        if self.status is not ResultStatus.ERROR and self.error_code is not None:
            raise InvalidResult("unexpected_error_code")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool": self.tool,
            "sha": self.sha,
            "status": self.status.value,
            "findings": [finding.to_dict() for finding in self.findings],
        }
        if self.partial_coverage:
            result["partial_coverage"] = list(self.partial_coverage)
        if self.not_applicable_target is not None:
            result["not_applicable_target"] = self.not_applicable_target
        if self.error_code is not None:
            result["error_code"] = self.error_code
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


def parse_result_json(raw: str) -> ScannerResult:
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        raise InvalidResult("invalid_json") from None
    if not isinstance(payload, dict):
        raise InvalidResult("invalid_result_shape")
    allowed = {"tool", "sha", "status", "findings", "partial_coverage", "not_applicable_target", "error_code"}
    if set(payload) - allowed:
        raise InvalidResult("unknown_result_fields")
    try:
        status = ResultStatus(payload.get("status"))
    except (TypeError, ValueError):
        raise InvalidResult("invalid_status") from None
    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list):
        raise InvalidResult("invalid_findings")
    findings = tuple(_parse_finding(item) for item in raw_findings)
    partial_coverage = payload.get("partial_coverage", [])
    if not isinstance(partial_coverage, list):
        raise InvalidResult("invalid_partial_coverage")
    return ScannerResult(
        tool=payload.get("tool"),
        sha=payload.get("sha"),
        status=status,
        findings=findings,
        partial_coverage=tuple(partial_coverage),
        not_applicable_target=payload.get("not_applicable_target"),
        error_code=payload.get("error_code"),
    )


def _parse_finding(payload: Any) -> Finding:
    if not isinstance(payload, dict):
        raise InvalidResult("invalid_finding_shape")
    allowed = {"rule_id", "severity", "title", "path", "line", "package", "version"}
    if set(payload) - allowed:
        raise InvalidResult("unknown_finding_fields")
    try:
        severity = Severity(payload.get("severity"))
    except (TypeError, ValueError):
        raise InvalidResult("invalid_finding_severity") from None
    return Finding(
        rule_id=payload.get("rule_id"),
        severity=severity,
        title=payload.get("title"),
        path=payload.get("path"),
        line=payload.get("line"),
        package=payload.get("package"),
        version=payload.get("version"),
    )


def _require_identifier(value: Any, code: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise InvalidResult(code)


def _require_text(value: Any, code: str, *, limit: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise InvalidResult(code)
