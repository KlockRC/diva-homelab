"""Collect sanitized SonarQube issues for one completed analysis."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from ci.security.gate import normalize_sonar_impact
from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


_TOKEN_RE = re.compile(r"\A[A-Za-z0-9._~+/=-]{8,512}\Z")
_TASK_ID_RE = re.compile(r"\A[A-Za-z0-9._-]{1,200}\Z")
_PROJECT_KEY_RE = re.compile(r"\A[a-zA-Z0-9_.:-]{1,400}\Z")
_RULE_RE = re.compile(r"\A[a-zA-Z0-9_.:/+-]{1,160}\Z")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_TERMINAL_TASK_STATES = {"SUCCESS", "FAILED", "CANCELED"}
_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024
_PAGE_SIZE = 500
_MAX_PAGES = 50


class SonarCollectorError(Exception):
    """Safe error code; never carries response bodies or credential data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SonarCollection:
    result: ScannerResult
    quality_gate_status: str

    @property
    def quality_gate_failed(self) -> bool:
        return self.quality_gate_status != "OK"


def _validate_host(host_url: str) -> str:
    if not isinstance(host_url, str) or not host_url.strip():
        raise SonarCollectorError("sonar_host_missing")
    parsed = urlsplit(host_url.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SonarCollectorError("sonar_host_invalid")
    if parsed.query or parsed.fragment:
        raise SonarCollectorError("sonar_host_invalid")
    if not parsed.hostname.lower().endswith(".ts.net") or parsed.path not in {"", "/"}:
        raise SonarCollectorError("sonar_host_not_tailscale_https")
    return f"{parsed.scheme}://{parsed.netloc}"


def validate_host_url(host_url: str) -> str:
    """Validate and return the private HTTPS endpoint used by CI."""
    return _validate_host(host_url)


def _validate_inputs(host_url: str, token: str, sha: str, project_key: str) -> str:
    base_url = _validate_host(host_url)
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise SonarCollectorError("sonar_token_missing_or_invalid")
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise SonarCollectorError("sonar_sha_invalid")
    if not isinstance(project_key, str) or not _PROJECT_KEY_RE.fullmatch(project_key):
        raise SonarCollectorError("sonar_project_key_invalid")
    return base_url


def _read_task_id(task_file: Path, base_url: str, project_key: str) -> str:
    try:
        raw = task_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise SonarCollectorError("sonar_task_file_missing") from None

    fields: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ceTaskUrl", "projectKey"}:
            fields[key] = value.strip()

    if fields.get("projectKey") != project_key:
        raise SonarCollectorError("sonar_task_project_mismatch")
    task_url = fields.get("ceTaskUrl", "")
    parsed = urlsplit(task_url)
    base = urlsplit(base_url)
    expected_path = f"{base.path.rstrip('/')}/api/ce/task"
    if (
        parsed.scheme != "https"
        or parsed.netloc.casefold() != base.netloc.casefold()
        or parsed.path != expected_path
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SonarCollectorError("sonar_task_url_invalid")
    query = parse_qs(parsed.query, keep_blank_values=True)
    task_ids = query.get("id", [])
    if len(task_ids) != 1 or not _TASK_ID_RE.fullmatch(task_ids[0]):
        raise SonarCollectorError("sonar_task_id_invalid")
    return task_ids[0]


def _request_json(
    base_url: str,
    token: str,
    endpoint: str,
    parameters: Mapping[str, str | int],
    *,
    timeout: float = 15.0,
) -> dict[str, Any]:
    query = urlencode(parameters)
    url = f"{base_url}{endpoint}?{query}"
    request = Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code == 400:
            raise SonarCollectorError("sonar_api_bad_request") from None
        if error.code in {401, 403}:
            raise SonarCollectorError("sonar_api_forbidden") from None
        raise SonarCollectorError("sonar_api_unavailable") from None
    except (HTTPException, URLError, TimeoutError, OSError):
        raise SonarCollectorError("sonar_api_unavailable") from None
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise SonarCollectorError("sonar_api_response_too_large")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise SonarCollectorError("sonar_api_invalid_json") from None
    if not isinstance(payload, dict):
        raise SonarCollectorError("sonar_api_invalid_response")
    return payload


def _poll_task(
    base_url: str,
    token: str,
    task_id: str,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float,
    request_json: Callable[..., dict[str, Any]],
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> str:
    deadline = clock() + timeout_seconds
    while True:
        payload = request_json(base_url, token, "/api/ce/task", {"id": task_id})
        task = payload.get("task")
        if not isinstance(task, dict):
            raise SonarCollectorError("sonar_ce_invalid_response")
        status = task.get("status")
        if status in _TERMINAL_TASK_STATES:
            if status != "SUCCESS":
                raise SonarCollectorError("sonar_ce_task_failed")
            analysis_id = task.get("analysisId")
            if not isinstance(analysis_id, str) or not _TASK_ID_RE.fullmatch(analysis_id):
                raise SonarCollectorError("sonar_analysis_id_invalid")
            return analysis_id
        if status not in {"PENDING", "IN_PROGRESS"}:
            raise SonarCollectorError("sonar_ce_invalid_status")
        remaining = deadline - clock()
        if remaining <= 0:
            raise SonarCollectorError("sonar_ce_timeout")
        sleep(min(poll_interval_seconds, remaining))


def _quality_gate_status(
    base_url: str,
    token: str,
    analysis_id: str,
    *,
    request_json: Callable[..., dict[str, Any]],
) -> str:
    try:
        payload = request_json(
            base_url,
            token,
            "/api/qualitygates/project_status",
            {"analysisId": analysis_id},
        )
    except SonarCollectorError:
        return "UNKNOWN"
    project_status = payload.get("projectStatus")
    if not isinstance(project_status, dict):
        return "UNKNOWN"
    status = project_status.get("status")
    if status not in {"OK", "ERROR", "WARN", "NONE"}:
        return "UNKNOWN"
    return status


def _safe_path(component: Any, project_key: str) -> str | None:
    if not isinstance(component, str) or not component.startswith(project_key + ":"):
        return None
    path = component[len(project_key) + 1 :]
    normalized = path.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in normalized.split("/")
        or "\n" in normalized
        or "\r" in normalized
    ):
        return None
    return normalized


def _issue_severity(issue: Mapping[str, Any]) -> Severity:
    impacts = issue.get("impacts")
    if isinstance(impacts, list) and impacts:
        severities: list[Severity] = []
        for impact in impacts:
            if not isinstance(impact, dict):
                continue
            severity = impact.get("severity")
            if isinstance(severity, str):
                severities.append(normalize_sonar_impact(severity))
        if not severities:
            raise ValueError("unknown Sonar issue impact")
        return max(severities, key=_SEVERITY_ORDER.__getitem__)
    return normalize_sonar_impact(issue.get("severity"))


def _issue_finding(issue: Any, project_key: str) -> Finding:
    if not isinstance(issue, dict):
        raise ValueError("invalid Sonar issue")
    severity = _issue_severity(issue)
    raw_rule = issue.get("rule")
    rule_id = raw_rule if isinstance(raw_rule, str) and _RULE_RE.fullmatch(raw_rule) else "sonar:unknown_rule"
    path = _safe_path(issue.get("component"), project_key)
    text_range = issue.get("textRange")
    raw_line = issue.get("line")
    if raw_line is None and isinstance(text_range, dict):
        raw_line = text_range.get("startLine")
    line = raw_line if type(raw_line) is int and raw_line >= 1 else None
    # Messages, code snippets, and matched values are deliberately excluded.
    return Finding(rule_id=rule_id, severity=severity, title="Sonar issue", path=path, line=line)


def _fetch_issues(
    base_url: str,
    token: str,
    project_key: str,
    *,
    branch: str | None,
    pull_request: str | None,
    request_json: Callable[..., dict[str, Any]],
) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    if bool(branch) == bool(pull_request):
        raise SonarCollectorError("sonar_scan_context_invalid")
    findings: list[Finding] = []
    coverage: list[str] = []
    page = 1
    total: int | None = None
    issue_status_filter = "issueStatuses"
    while page <= _MAX_PAGES:
        parameters: dict[str, str | int] = {
            "componentKeys": project_key,
            "ps": _PAGE_SIZE,
            "p": page,
        }
        if issue_status_filter == "issueStatuses":
            parameters["issueStatuses"] = "OPEN,CONFIRMED"
        else:
            parameters["resolved"] = "false"
        if branch and branch != "main":
            parameters["branch"] = branch
        if pull_request:
            parameters["pullRequest"] = pull_request
        try:
            payload = request_json(base_url, token, "/api/issues/search", parameters)
        except SonarCollectorError as error:
            # Older instances may expose only the deprecated resolved flag. A
            # 400 response is safe to retry without logging Sonar's raw body.
            if page == 1 and issue_status_filter == "issueStatuses" and error.code == "sonar_api_bad_request":
                issue_status_filter = "resolved"
                parameters.pop("issueStatuses", None)
                parameters["resolved"] = "false"
                payload = request_json(base_url, token, "/api/issues/search", parameters)
            else:
                raise
        issues = payload.get("issues")
        paging = payload.get("paging")
        if not isinstance(issues, list) or not isinstance(paging, dict):
            raise SonarCollectorError("sonar_issues_invalid_response")
        page_total = paging.get("total")
        if type(page_total) is not int or page_total < 0:
            raise SonarCollectorError("sonar_issues_invalid_paging")
        total = page_total
        for issue in issues:
            try:
                findings.append(_issue_finding(issue, project_key))
            except (TypeError, ValueError):
                coverage.append("sonar_issue_unrecognized")
        if page * _PAGE_SIZE >= page_total or not issues:
            break
        page += 1
    if total is not None and page == _MAX_PAGES and page * _PAGE_SIZE < total:
        coverage.append("sonar_issue_results_truncated")
    return tuple(findings), tuple(dict.fromkeys(coverage))


def collect(
    host_url: str,
    token: str,
    sha: str,
    project_key: str,
    task_file: Path,
    *,
    branch: str | None = None,
    pull_request: str | None = None,
    timeout_seconds: float = 300.0,
    poll_interval_seconds: float = 3.0,
    request_json: Callable[..., dict[str, Any]] = _request_json,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> SonarCollection:
    base_url = _validate_inputs(host_url, token, sha, project_key)
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise SonarCollectorError("sonar_timeout_invalid")
    if not isinstance(poll_interval_seconds, (int, float)) or poll_interval_seconds <= 0:
        raise SonarCollectorError("sonar_poll_interval_invalid")
    if bool(branch) == bool(pull_request):
        raise SonarCollectorError("sonar_scan_context_invalid")
    if pull_request and not re.fullmatch(r"[1-9][0-9]{0,9}", pull_request):
        raise SonarCollectorError("sonar_pull_request_invalid")
    if branch and (len(branch) > 250 or "\n" in branch or "\r" in branch):
        raise SonarCollectorError("sonar_branch_invalid")

    task_id = _read_task_id(task_file, base_url, project_key)
    analysis_id = _poll_task(
        base_url,
        token,
        task_id,
        timeout_seconds=float(timeout_seconds),
        poll_interval_seconds=float(poll_interval_seconds),
        request_json=request_json,
        clock=clock,
        sleep=sleep,
    )
    quality_gate_status = _quality_gate_status(
        base_url,
        token,
        analysis_id,
        request_json=request_json,
    )
    findings, partial_coverage = _fetch_issues(
        base_url,
        token,
        project_key,
        branch=branch,
        pull_request=pull_request,
        request_json=request_json,
    )
    if quality_gate_status == "UNKNOWN":
        partial_coverage = tuple(dict.fromkeys((*partial_coverage, "sonar_quality_gate_unavailable")))
    status = ResultStatus.PARTIAL if partial_coverage else ResultStatus.COMPLETED
    return SonarCollection(
        result=ScannerResult(
            tool="sonar",
            sha=sha,
            status=status,
            findings=findings,
            partial_coverage=partial_coverage,
        ),
        quality_gate_status=quality_gate_status,
    )


def error_collection(sha: str, error_code: str) -> SonarCollection:
    if not re.fullmatch(r"[a-z0-9_]{1,80}", error_code):
        error_code = "sonar_collection_failed"
    return SonarCollection(
        result=ScannerResult("sonar", sha, ResultStatus.ERROR, error_code=error_code),
        quality_gate_status="UNKNOWN",
    )


def _summary(collection: SonarCollection) -> str:
    result = collection.result
    lines = [
        "# Sonar analysis",
        "",
        f"- Commit SHA: `{result.sha}`",
        f"- Analysis status: `{result.status.value}`",
        f"- Quality Gate: `{collection.quality_gate_status}`",
        f"- Findings collected: {len(result.findings)}",
        f"- High/Critical findings: {sum(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in result.findings)}",
    ]
    if result.error_code:
        lines.extend(["", f"- Warning code: `{result.error_code}`"])
    if result.partial_coverage:
        lines.extend(["", "## Coverage warnings", ""])
        lines.extend(f"- `{item}`" for item in result.partial_coverage)
    if result.findings:
        lines.extend(["", "## Findings", "", "| Severity | Rule | Path | Line |", "| --- | --- | --- | ---: |"])
        for finding in result.findings:
            path = finding.path or "—"
            line = str(finding.line) if finding.line is not None else "—"
            safe_values = [finding.severity.value, finding.rule_id, path, line]
            escaped = [_escape_markdown(value) for value in safe_values]
            lines.append("| " + " | ".join(escaped) + " |")
    return "\n".join(lines) + "\n"


def _escape_markdown(value: str) -> str:
    escaped = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=True)
    for marker in ("#", "`", "*", "_", "[", "]", "(", ")", "|"):
        escaped = escaped.replace(marker, "&#" + str(ord(marker)) + ";")
    return escaped


def _write_outputs(
    collection: SonarCollection,
    *,
    result_path: Path,
    summary_path: Path | None,
    github_output: Path | None,
) -> None:
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(collection.result.to_json() + "\n", encoding="utf-8")
    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(_summary(collection), encoding="utf-8")
    if github_output:
        gate_failed = str(collection.quality_gate_failed).lower()
        with github_output.open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"quality_gate_status={collection.quality_gate_status}\n")
            output.write(f"quality_gate_failed={gate_failed}\n")
            output.write(f"result_status={collection.result.status.value}\n")
            output.write(f"blocking_count={sum(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in collection.result.findings)}\n")
            output.write(f"sha={collection.result.sha}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("SONAR_HOST_URL"))
    parser.add_argument("--token", default=os.environ.get("SONAR_TOKEN"))
    parser.add_argument("--project-key", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--task-file", type=Path, default=Path("source/.scannerwork/report-task.txt"))
    parser.add_argument("--branch")
    parser.add_argument("--pull-request")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--poll-interval-seconds", type=float, default=3.0)
    parser.add_argument("--error-code")
    parser.add_argument("--result", type=Path, default=Path("sonar-result.json"))
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    if args.error_code:
        collection = error_collection(args.sha, args.error_code)
    else:
        try:
            collection = collect(
                args.host or "",
                args.token or "",
                args.sha,
                args.project_key,
                args.task_file,
                branch=args.branch,
                pull_request=args.pull_request,
                timeout_seconds=args.timeout_seconds,
                poll_interval_seconds=args.poll_interval_seconds,
            )
        except SonarCollectorError as error:
            collection = error_collection(args.sha, error.code)
        except (OSError, TypeError, ValueError):
            collection = error_collection(args.sha, "sonar_collection_failed")
    _write_outputs(
        collection,
        result_path=args.result,
        summary_path=args.summary,
        github_output=args.github_output,
    )
    print(collection.result.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
