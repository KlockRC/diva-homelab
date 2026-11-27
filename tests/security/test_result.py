import unittest

from ci.security.result import (
    Finding,
    InvalidResult,
    ResultStatus,
    ScannerResult,
    Severity,
    parse_result_json,
)


SHA = "a" * 40


class ScannerResultTests(unittest.TestCase):
    def test_clean_scan_is_completed(self):
        result = ScannerResult("trivy", SHA, ResultStatus.COMPLETED)

        self.assertEqual(result.status, ResultStatus.COMPLETED)
        self.assertEqual(result.findings, ())
        self.assertEqual(parse_result_json(result.to_json()), result)

    def test_partial_scan_keeps_confirmed_findings(self):
        finding = Finding("CVE-2026-0001", Severity.HIGH, "Affected package", package="libx", version="1.0")
        result = ScannerResult("trivy", SHA, ResultStatus.PARTIAL, (finding,), ("image",))

        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(result.findings, (finding,))
        self.assertEqual(result.partial_coverage, ("image",))

    def test_unavailable_target_is_not_applicable(self):
        result = ScannerResult("trivy", SHA, ResultStatus.NOT_APPLICABLE, not_applicable_target="container image build")

        self.assertEqual(result.status, ResultStatus.NOT_APPLICABLE)
        self.assertEqual(result.not_applicable_target, "container image build")

    def test_execution_error_is_distinct(self):
        result = ScannerResult("gitleaks", SHA, ResultStatus.ERROR, error_code="scanner_timeout")

        self.assertEqual(result.status, ResultStatus.ERROR)
        self.assertEqual(result.error_code, "scanner_timeout")

    def test_invalid_output_is_classified_without_echoing_payload(self):
        with self.assertRaises(InvalidResult) as context:
            parse_result_json('{"secret":"synthetic-secret-value"}')

        self.assertEqual(context.exception.code, "unknown_result_fields")
        self.assertNotIn("synthetic-secret-value", str(context.exception))


if __name__ == "__main__":
    unittest.main()
