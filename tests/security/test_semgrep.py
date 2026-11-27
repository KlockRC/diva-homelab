import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ci.security.result import ResultStatus, Severity
from ci.security.semgrep import (
    DEFAULT_RULES,
    RULESET_VERSION,
    TOOL_VERSION,
    build_command,
    parse_output,
    run_semgrep,
)


SHA = "b" * 40


def semgrep_finding(severity="ERROR"):
    return {
        "check_id": "diva.python.eval",
        "path": "app.py",
        "start": {"line": 12},
        "extra": {"severity": severity, "message": "Unsafe value: synthetic-secret-value"},
    }


class SemgrepAdapterTests(unittest.TestCase):
    def test_semgrep_error_severity_normalizes_to_high_without_message(self):
        result = parse_output(json.dumps({"results": [semgrep_finding()], "errors": []}), SHA, 1)

        self.assertEqual(result.status, ResultStatus.COMPLETED)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        self.assertNotIn("synthetic-secret-value", result.to_json())

    def test_valid_zero_finding_output_is_completed(self):
        result = parse_output('{"results": [], "errors": []}', SHA, 0)

        self.assertEqual(result.status, ResultStatus.COMPLETED)
        self.assertEqual(result.findings, ())

    def test_no_supported_source_file_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "inventory.yaml"
            source.write_text("services: []\n", encoding="utf-8")
            runner = Mock()

            result = run_semgrep(source, SHA, runner=runner)

        self.assertEqual(result.status, ResultStatus.NOT_APPLICABLE)
        self.assertEqual(result.not_applicable_target, "supported application source files")
        runner.assert_not_called()

    def test_json_errors_are_partial_and_keep_findings(self):
        result = parse_output(json.dumps({"results": [semgrep_finding("WARNING")], "errors": [{"message": "ignored"}]}), SHA, 0)

        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(result.findings[0].severity, Severity.MEDIUM)
        self.assertEqual(result.partial_coverage, ("scanner_error_1",))

    def test_cli_and_local_ruleset_versions_are_fixed(self):
        command = build_command(Path("source"))

        self.assertEqual(TOOL_VERSION, "1.173.0")
        self.assertEqual(RULESET_VERSION, "diva-security-rules-v1")
        self.assertIn(str(DEFAULT_RULES), command)
        self.assertIn("--metrics=off", command)


if __name__ == "__main__":
    unittest.main()
