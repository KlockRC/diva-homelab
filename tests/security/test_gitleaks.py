import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ci.security.gitleaks import DEFAULT_CONFIG, DEFAULT_IGNORE, TOOL_VERSION, build_command, parse_report, run_gitleaks
from ci.security.result import ResultStatus, Severity


BASE = "a" * 40
HEAD = "b" * 40


class GitleaksAdapterTests(unittest.TestCase):
    def test_detected_marker_is_high_and_secret_is_removed_from_report(self):
        marker = "ghp_" + "A" * 36
        output = [
            {
                "RuleID": "github-pat",
                "File": "credentials.txt",
                "StartLine": 3,
                "Secret": marker,
                "Match": "token=" + marker,
                "Message": "commit " + marker,
            }
        ]

        result = parse_report(json.dumps(output), HEAD, 1)

        self.assertEqual(result.status, ResultStatus.COMPLETED)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        self.assertEqual(result.findings[0].path, "credentials.txt")
        self.assertNotIn(marker, result.to_json())

    def test_scan_command_covers_every_commit_after_the_merge_base(self):
        command = build_command(BASE, HEAD, Path("report.json"))

        self.assertEqual(command[0:2], ["gitleaks", "git"])
        self.assertEqual(command[-1], f"{BASE}..{HEAD}")
        self.assertIn("--redact=100", command)
        self.assertEqual(command[command.index("--config") + 1], str(DEFAULT_CONFIG))
        self.assertEqual(command[command.index("--gitleaks-ignore-path") + 1], str(DEFAULT_IGNORE))
        self.assertIn("--ignore-gitleaks-allow", command)
        self.assertEqual(TOOL_VERSION, "8.30.1")

    def test_invalid_report_is_an_error_without_echoing_content(self):
        result = parse_report('{"Match":"synthetic-secret-value"}', HEAD, 0)

        self.assertEqual(result.status, ResultStatus.ERROR)
        self.assertEqual(result.error_code, "invalid_output")
        self.assertNotIn("synthetic-secret-value", result.to_json())

    def test_invalid_commit_range_is_rejected_before_running_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            report.write_text("[]", encoding="utf-8")
            runner = Mock()

            result = run_gitleaks(Path(directory), "not-a-sha", HEAD, report_path=report, runner=runner)

        self.assertEqual(result.status, ResultStatus.ERROR)
        self.assertEqual(result.error_code, "invalid_commit_range")
        runner.assert_not_called()

    def test_relative_policy_paths_are_resolved_before_changing_scanner_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "source"
            repository.mkdir()
            report = Path(directory) / "report.json"
            observed = {}

            def fake_runner(command, **kwargs):
                observed["command"] = command
                observed["cwd"] = kwargs["cwd"]
                Path(command[command.index("--report-path") + 1]).write_text("[]", encoding="utf-8")
                return SimpleNamespace(returncode=0)

            result = run_gitleaks(
                repository,
                BASE,
                HEAD,
                report_path=report,
                config_path=Path("ci/security/gitleaks.toml"),
                runner=fake_runner,
            )

        self.assertEqual(result.status.value, "completed")
        self.assertEqual(observed["cwd"], repository.resolve())
        self.assertTrue(Path(observed["command"][observed["command"].index("--config") + 1]).is_absolute())
        self.assertTrue(Path(observed["command"][observed["command"].index("--gitleaks-ignore-path") + 1]).is_absolute())


if __name__ == "__main__":
    unittest.main()
