import json
import unittest
from pathlib import Path
from unittest.mock import Mock

from ci.security.result import ResultStatus, Severity
from ci.security.trivy import (
    TOOL_VERSION,
    build_fs_command,
    build_image_command,
    classify_image_target,
    parse_output,
    scan_image_digest,
)


SHA = "c" * 40
DIGEST_REF = "ghcr.io/diva/app@sha256:" + "d" * 64


class TrivyAdapterTests(unittest.TestCase):
    def test_manifest_vulnerability_is_normalized_without_raw_details(self):
        output = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-1234",
                            "PkgName": "some-package",
                            "InstalledVersion": "1.2.3",
                            "Severity": "HIGH",
                            "Description": "synthetic-secret-value",
                        }
                    ],
                }
            ]
        }

        result = parse_output(json.dumps(output), SHA, 0)

        self.assertEqual(result.status, ResultStatus.COMPLETED)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        self.assertEqual(result.findings[0].path, "package-lock.json")
        self.assertNotIn("synthetic-secret-value", result.to_json())

    def test_image_scan_uses_the_revision_digest(self):
        command = build_image_command(DIGEST_REF)

        self.assertEqual(command[-1], DIGEST_REF)
        self.assertIn("--scanners", command)
        self.assertEqual(TOOL_VERSION, "0.76.2")

    def test_image_is_not_applicable_when_repository_has_no_build(self):
        result = classify_image_target(SHA, build_expected=False)

        self.assertEqual(result.status, ResultStatus.NOT_APPLICABLE)
        self.assertEqual(result.not_applicable_target, "repository container image build")

    def test_expected_image_build_failure_is_an_error(self):
        result = classify_image_target(SHA, build_expected=True, build_succeeded=False)

        self.assertEqual(result.status, ResultStatus.ERROR)
        self.assertEqual(result.error_code, "image_build_failed")

    def test_image_reference_without_immutable_digest_is_rejected(self):
        runner = Mock()

        result = scan_image_digest("ghcr.io/diva/app:latest", SHA, runner=runner)

        self.assertEqual(result.status, ResultStatus.ERROR)
        self.assertEqual(result.error_code, "invalid_image_digest")
        runner.assert_not_called()

    def test_filesystem_scan_includes_dependency_iac_and_secret_scanners(self):
        command = build_fs_command(Path("source"))

        self.assertIn("vuln,misconfig,secret", command)
        self.assertIn("--format", command)
        self.assertIn("json", command)


if __name__ == "__main__":
    unittest.main()
