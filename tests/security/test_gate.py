import unittest

from ci.security.gate import evaluate, markdown_summary, normalize_sonar_impact
from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


SHA = "1" * 40
STALE = "2" * 40


class SecurityGateTests(unittest.TestCase):
    def test_high_finding_blocks(self):
        result = ScannerResult("trivy", SHA, ResultStatus.COMPLETED, (Finding("CVE-1", Severity.HIGH, "Finding"),))

        decision = evaluate([result], SHA, expected_tools=("trivy",))

        self.assertEqual(decision.status, "blocked")
        self.assertEqual(decision.blocking_findings[0].severity, Severity.HIGH)

    def test_critical_finding_blocks(self):
        result = ScannerResult("gitleaks", SHA, ResultStatus.COMPLETED, (Finding("github-pat", Severity.CRITICAL, "Finding"),))

        decision = evaluate([result], SHA, expected_tools=("gitleaks",))

        self.assertEqual(decision.status, "blocked")
        self.assertEqual(len(decision.blocking_findings), 1)

    def test_scanner_error_warns_without_blocking(self):
        result = ScannerResult("trivy", SHA, ResultStatus.ERROR, error_code="scanner_timeout")

        decision = evaluate([result], SHA, expected_tools=("trivy",))

        self.assertEqual(decision.status, "passed")
        self.assertIn("trivy:scanner_timeout", decision.warnings)

    def test_quality_gate_failure_warns_without_blocking(self):
        result = ScannerResult("semgrep", SHA, ResultStatus.COMPLETED)

        decision = evaluate([result], SHA, expected_tools=("semgrep",), quality_gate_passed=False)

        self.assertEqual(decision.status, "passed")
        self.assertIn("sonar_quality_gate_failed", decision.warnings)

    def test_old_sha_result_is_discarded_even_when_it_contains_high(self):
        result = ScannerResult("trivy", STALE, ResultStatus.COMPLETED, (Finding("CVE-1", Severity.HIGH, "Finding"),))

        decision = evaluate([result], SHA, expected_tools=())

        self.assertEqual(decision.status, "passed")
        self.assertEqual(decision.ignored_result_count, 1)
        self.assertIn("stale_results_discarded:1", decision.warnings)

    def test_confirmed_high_blocks_despite_other_error_and_upload_failure(self):
        results = [
            ScannerResult("semgrep", SHA, ResultStatus.COMPLETED, (Finding("rule-high", Severity.HIGH, "Finding"),)),
            ScannerResult("trivy", SHA, ResultStatus.ERROR, error_code="scanner_timeout"),
        ]

        decision = evaluate(results, SHA, expected_tools=(), report_upload_succeeded=False)

        self.assertEqual(decision.status, "blocked")
        self.assertIn("report_upload_failed", decision.warnings)
        self.assertIn("trivy:scanner_timeout", decision.warnings)

    def test_lower_severity_findings_do_not_block(self):
        result = ScannerResult("semgrep", SHA, ResultStatus.COMPLETED, (Finding("rule-low", Severity.LOW, "Finding"),))

        decision = evaluate([result], SHA, expected_tools=("semgrep",))

        self.assertEqual(decision.status, "passed")
        self.assertEqual(decision.finding_counts["low"], 1)

    def test_missing_scanner_result_is_a_warning(self):
        decision = evaluate([], SHA, expected_tools=("gitleaks",))

        self.assertEqual(decision.status, "passed")
        self.assertIn("no_results_for_commit", decision.warnings)
        self.assertIn("missing_result:gitleaks", decision.warnings)

    def test_sonar_mqr_high_and_blocker_are_normalized(self):
        self.assertEqual(normalize_sonar_impact("HIGH"), Severity.HIGH)
        self.assertEqual(normalize_sonar_impact("BLOCKER"), Severity.CRITICAL)

    def test_gate_summary_escapes_pr_controlled_finding_path(self):
        result = ScannerResult(
            "trivy",
            SHA,
            ResultStatus.COMPLETED,
            (Finding("CVE-1", Severity.CRITICAL, "Finding", path="folder/a|b.txt"),),
        )
        summary = markdown_summary(evaluate([result], SHA, expected_tools=("trivy",)))

        self.assertIn("a&#124;b.txt", summary)
        self.assertNotIn("a|b.txt", summary)


if __name__ == "__main__":
    unittest.main()
