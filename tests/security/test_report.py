import json
import unittest

from ci.security.gitleaks import parse_report
from ci.security.report import ReportContext, build_report
from ci.security.result import Finding, ResultStatus, ScannerResult, Severity


SHA = "e" * 40
BASE = "f" * 40


class SecurityReportTests(unittest.TestCase):
    def setUp(self):
        self.context = ReportContext(
            repository="KlockRC/diva-homelab",
            pull_request=42,
            target_branch="development",
            sha=SHA,
            base_sha=BASE,
            workflow_url="https://github.com/KlockRC/diva-homelab/actions/runs/123456",
            application_scope="No homelab application source was found; policy code is still scanned.",
        )

    def test_report_contains_required_identity_and_counts(self):
        results = [
            ScannerResult(
                "trivy",
                SHA,
                ResultStatus.COMPLETED,
                (Finding("CVE-2026-1234", Severity.MEDIUM, "Finding", path="package-lock.json", package="lib", version="1.0"),),
            ),
            ScannerResult("semgrep", SHA, ResultStatus.NOT_APPLICABLE, not_applicable_target="supported application source files"),
        ]

        artifact, summary = build_report(self.context, results)

        for expected in ("KlockRC/diva-homelab", "42", "development", SHA, BASE, "actions/runs/123456", "CVE-2026-1234"):
            self.assertIn(expected, summary)
        self.assertEqual(artifact["counts"]["medium"], 1)
        self.assertEqual(artifact["scanners"][1]["status"], "not_applicable")
        self.assertIn(self.context.application_scope, summary)
        self.assertEqual(artifact["context"]["application_scope"], self.context.application_scope)

    def test_detected_secret_is_absent_from_artifact_and_summary(self):
        marker = "synthetic-secret-value"
        scanner = parse_report(
            json.dumps([{"RuleID": "test-rule", "File": "token.txt", "StartLine": 1, "Secret": marker, "Match": "value=" + marker}]),
            SHA,
            1,
        )

        artifact, summary = build_report(self.context, [scanner])

        serialized = json.dumps(artifact)
        self.assertNotIn(marker, serialized)
        self.assertNotIn(marker, summary)
        self.assertNotIn("Match", serialized)
        self.assertNotIn("Secret", serialized)

    def test_markdown_cells_escape_markup_and_newlines(self):
        finding = Finding("rule-id", Severity.LOW, "unpublished title", path="folder/a|b.py", line=5)
        _, summary = build_report(self.context, [ScannerResult("semgrep", SHA, ResultStatus.COMPLETED, (finding,))])

        self.assertIn("a&#124;b.py", summary)
        self.assertNotIn("a|b.py", summary)
        self.assertNotIn("unpublished title", summary)

    def test_report_rejects_mismatched_scanner_sha(self):
        result = ScannerResult("trivy", BASE, ResultStatus.COMPLETED)

        with self.assertRaisesRegex(ValueError, "SHA"):
            build_report(self.context, [result])

    def test_context_rejects_untrusted_workflow_link(self):
        with self.assertRaisesRegex(ValueError, "workflow URL"):
            ReportContext(
                "KlockRC/diva-homelab",
                42,
                "main",
                SHA,
                BASE,
                "https://attacker.example/KlockRC/diva-homelab/actions/runs/123",
            )


if __name__ == "__main__":
    unittest.main()
