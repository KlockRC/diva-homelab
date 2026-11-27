import tempfile
import unittest
from pathlib import Path

from ci.security.gate import evaluate
from ci.security.result import Finding, ResultStatus, ScannerResult, Severity
from ci.security.sonar import SonarCollection, SonarCollectorError, _summary, collect, error_collection


SHA = "1" * 40
PROJECT = "diva-homelab"
HOST = "https://sonar.example.ts.net:9443"
TOKEN = "squ_test-token-value-1234567890"


def write_task_file(path: Path, *, host: str = HOST, project: str = PROJECT) -> None:
    path.write_text(
        f"serverUrl={host}\nprojectKey={project}\nceTaskUrl={host}/api/ce/task?id=task-123\n",
        encoding="utf-8",
    )


class SonarCollectorTests(unittest.TestCase):
    def test_polls_ce_and_sanitizes_mqr_findings_for_pull_request(self):
        calls = []
        task_responses = iter(
            [
                {"task": {"status": "IN_PROGRESS"}},
                {"task": {"status": "SUCCESS", "analysisId": "analysis-123"}},
            ]
        )

        def request_json(base_url, token, endpoint, parameters, **kwargs):
            calls.append((base_url, token, endpoint, parameters))
            if endpoint == "/api/ce/task":
                return next(task_responses)
            if endpoint == "/api/qualitygates/project_status":
                return {"projectStatus": {"status": "ERROR", "conditions": [{"message": "private gate details"}]}}
            if endpoint == "/api/issues/search":
                return {
                    "paging": {"total": 3},
                    "issues": [
                        {
                            "rule": "python:S2068",
                            "component": f"{PROJECT}:ci/security/example.py",
                            "textRange": {"startLine": 17, "endLine": 17},
                            "impacts": [
                                {"softwareQuality": "SECURITY", "severity": "HIGH"},
                                {"softwareQuality": "MAINTAINABILITY", "severity": "LOW"},
                            ],
                            "message": "synthetic private source snippet",
                        },
                        {
                            "rule": "python:S9999",
                            "component": f"{PROJECT}:ci/security/other.py",
                            "line": 21,
                            "impacts": [{"softwareQuality": "SECURITY", "severity": "BLOCKER"}],
                            "message": "synthetic matched value",
                        },
                        {
                            "rule": "python:S1000",
                            "component": f"{PROJECT}:ci/security/low.py",
                            "line": 3,
                            "impacts": [{"softwareQuality": "MAINTAINABILITY", "severity": "LOW"}],
                            "message": "must not escape into report",
                        },
                    ],
                }
            raise AssertionError(endpoint)

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / "report-task.txt"
            write_task_file(task_file)
            sleeps = []
            clock_values = iter([0.0, 0.1, 0.2])
            result = collect(
                HOST,
                TOKEN,
                SHA,
                PROJECT,
                task_file,
                pull_request="17",
                timeout_seconds=10,
                poll_interval_seconds=0.25,
                request_json=request_json,
                clock=lambda: next(clock_values, 0.3),
                sleep=sleeps.append,
            )

        self.assertEqual(result.result.status, ResultStatus.COMPLETED)
        self.assertEqual([finding.severity for finding in result.result.findings], [Severity.HIGH, Severity.CRITICAL, Severity.LOW])
        self.assertEqual(result.quality_gate_status, "ERROR")
        self.assertTrue(result.quality_gate_failed)
        self.assertEqual(sleeps, [0.25])
        issue_call = next(call for call in calls if call[2] == "/api/issues/search")
        self.assertEqual(issue_call[3]["pullRequest"], "17")
        self.assertEqual(issue_call[3]["issueStatuses"], "OPEN,CONFIRMED")
        self.assertNotIn("resolved", issue_call[3])
        self.assertNotIn("branch", issue_call[3])

        serialized = result.result.to_json()
        self.assertNotIn("synthetic", serialized)
        self.assertNotIn("private gate details", serialized)
        self.assertNotIn("message", serialized)

        decision = evaluate([result.result], SHA, expected_tools=(), quality_gate_passed=False)
        self.assertEqual(decision.status, "blocked")
        self.assertEqual(len(decision.blocking_findings), 2)
        self.assertIn("sonar_quality_gate_failed", decision.warnings)

    def test_standard_severity_scan_error_is_warning_only(self):
        def request_json(base_url, token, endpoint, parameters, **kwargs):
            if endpoint == "/api/ce/task":
                return {"task": {"status": "FAILED", "errorMessage": "private server detail"}}
            raise AssertionError(endpoint)

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / "report-task.txt"
            write_task_file(task_file)
            with self.assertRaises(SonarCollectorError) as caught:
                collect(
                    HOST,
                    TOKEN,
                    SHA,
                    PROJECT,
                    task_file,
                    branch="development",
                    request_json=request_json,
                    clock=lambda: 0.0,
                    sleep=lambda _: None,
                )

        self.assertEqual(caught.exception.code, "sonar_ce_task_failed")
        self.assertNotIn("private server detail", str(caught.exception))
        decision = evaluate([error_collection(SHA, caught.exception.code).result], SHA, expected_tools=())
        self.assertEqual(decision.status, "passed")
        self.assertIn("sonar:sonar_ce_task_failed", decision.warnings)

    def test_unknown_quality_gate_is_reported_as_warning_not_blocker(self):
        result = error_collection(SHA, "sonar_api_unavailable")

        self.assertEqual(result.quality_gate_status, "UNKNOWN")
        self.assertTrue(result.quality_gate_failed)
        decision = evaluate(
            [result.result],
            SHA,
            expected_tools=(),
            quality_gate_passed=not result.quality_gate_failed,
        )
        self.assertEqual(decision.status, "passed")
        self.assertIn("sonar_quality_gate_failed", decision.warnings)

    def test_foreign_ce_task_url_is_rejected_before_api_request(self):
        called = []

        def request_json(*args, **kwargs):
            called.append(True)
            raise AssertionError("must not send the token to a task URL from another host")

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / "report-task.txt"
            task_file.write_text(
                "serverUrl=https://sonar.example.ts.net:9443\n"
                f"projectKey={PROJECT}\n"
                "ceTaskUrl=https://evil.example/api/ce/task?id=task-123\n",
                encoding="utf-8",
            )
            with self.assertRaises(SonarCollectorError) as caught:
                collect(HOST, TOKEN, SHA, PROJECT, task_file, branch="main", request_json=request_json)

        self.assertEqual(caught.exception.code, "sonar_task_url_invalid")
        self.assertEqual(called, [])

    def test_old_issue_api_filter_falls_back_without_logging_response_body(self):
        calls = []

        def request_json(base_url, token, endpoint, parameters, **kwargs):
            calls.append(dict(parameters))
            if endpoint == "/api/ce/task":
                return {"task": {"status": "SUCCESS", "analysisId": "analysis-123"}}
            if endpoint == "/api/qualitygates/project_status":
                return {"projectStatus": {"status": "OK"}}
            if endpoint == "/api/issues/search" and "issueStatuses" in parameters:
                raise SonarCollectorError("sonar_api_bad_request")
            if endpoint == "/api/issues/search":
                return {"paging": {"total": 0}, "issues": []}
            raise AssertionError(endpoint)

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / "report-task.txt"
            write_task_file(task_file)
            result = collect(
                HOST,
                TOKEN,
                SHA,
                PROJECT,
                task_file,
                branch="development",
                request_json=request_json,
                clock=lambda: 0.0,
                sleep=lambda _: None,
            )

        issue_calls = [call for call in calls if "componentKeys" in call]
        self.assertEqual(issue_calls[0]["issueStatuses"], "OPEN,CONFIRMED")
        self.assertEqual(issue_calls[1]["resolved"], "false")
        self.assertEqual(result.result.status, ResultStatus.COMPLETED)

    def test_public_https_endpoint_is_rejected(self):
        with self.assertRaises(SonarCollectorError) as caught:
            collect(
                "https://sonar.example.com",
                TOKEN,
                SHA,
                PROJECT,
                Path("missing-report-task.txt"),
                branch="main",
            )

        self.assertEqual(caught.exception.code, "sonar_host_not_tailscale_https")

    def test_github_summary_escapes_issue_path_markup(self):
        sanitized = SonarCollection(
            result=ScannerResult(
                tool="sonar",
                sha=SHA,
                status=ResultStatus.COMPLETED,
                findings=(Finding("python:S2068", Severity.HIGH, "Sonar issue", path="<script>|[x]`&.py", line=1),),
            ),
            quality_gate_status="OK",
        )

        summary = _summary(sanitized)

        self.assertNotIn("<script>", summary)
        self.assertNotIn("|[x]`&.py", summary)
        self.assertIn("&lt;script&gt;&#124;&#91;x&#93;&#96;&amp;.py", summary)

    def test_invalid_response_preserves_only_safe_error_code(self):
        def request_json(base_url, token, endpoint, parameters, **kwargs):
            if endpoint == "/api/ce/task":
                return {"task": {"status": "SUCCESS", "analysisId": "analysis-123"}}
            if endpoint == "/api/qualitygates/project_status":
                return {"projectStatus": {"status": "OK"}}
            if endpoint == "/api/issues/search":
                return {"paging": {"total": 1}, "issues": [{"rule": "x", "message": "secret text"}]}
            raise AssertionError(endpoint)

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / "report-task.txt"
            write_task_file(task_file)
            result = collect(
                HOST,
                TOKEN,
                SHA,
                PROJECT,
                task_file,
                branch="main",
                request_json=request_json,
                clock=lambda: 0.0,
                sleep=lambda _: None,
            )

        self.assertEqual(result.result.status, ResultStatus.PARTIAL)
        self.assertEqual(result.result.partial_coverage, ("sonar_issue_unrecognized",))
        self.assertEqual(result.result.findings, ())
        self.assertNotIn("secret text", result.result.to_json())


if __name__ == "__main__":
    unittest.main()
