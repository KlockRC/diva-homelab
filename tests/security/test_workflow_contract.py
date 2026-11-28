from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "shared-security-preview.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"


def _job_block(content: str, job_id: str) -> str:
    lines = content.splitlines()
    marker = f"  {job_id}:"
    start = next((index for index, line in enumerate(lines) if line == marker), None)
    if start is None:
        return ""
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("  ") and not lines[index].startswith("    ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = WORKFLOW.read_text(encoding="utf-8")

    def test_consumer_invokes_public_reusable_workflow_at_full_sha(self):
        match = re.search(
            r"(?m)^    uses: KlockRC/ci-workflows/\.github/workflows/security\.yml@([0-9a-f]{40})$",
            self.content,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "0781cf3ab68f9e4dabbccea4e7821c6cc89f995c")

    def test_configured_branch_push_requests_sonar(self):
        self.assertIn("  push:\n    branches: [development, homolog, main]", self.content)
        self.assertIn("sonar-project-key: ${{ vars.SONAR_PROJECT_KEY || 'diva-homelab' }}", self.content)
        self.assertIn("tailscale-client-id: ${{", self.content)
        self.assertIn("tailscale-audience: ${{", self.content)
        self.assertIn("SONAR_TOKEN: ${{", self.content)
        self.assertIn("SONAR_HOST_URL: ${{", self.content)

    def test_pull_request_runs_all_free_scanners_through_the_shared_workflow(self):
        self.assertIn("pull_request_target:", self.content)
        self.assertIn("branches: [development, homolog, main]", self.content)
        self.assertIn("uses: KlockRC/ci-workflows/.github/workflows/security.yml@", self.content)
        self.assertIn("if: ${{ !cancelled() }}", _job_block(self.content, "shared_security"))

    def test_sonar_runs_for_configured_trusted_events(self):
        security = _job_block(self.content, "shared_security")
        trusted = "github.event_name != 'pull_request_target' || github.event.pull_request.head.repo.full_name == github.repository"
        for setting in ("tailscale-client-id:", "tailscale-audience:", "SONAR_TOKEN:", "SONAR_HOST_URL:"):
            self.assertIn(setting, security)
        self.assertGreaterEqual(security.count(trusted), 4)

    def test_fork_pull_request_has_no_privileged_credentials_or_coverage_execution(self):
        coverage = _job_block(self.content, "coverage")
        self.assertIn(
            "github.event.pull_request.head.repo.full_name == github.repository",
            coverage,
        )
        self.assertNotRegex(coverage, r"(?i)secrets\.|SONAR_TOKEN|SONAR_HOST_URL|TAILSCALE_|id-token:")

        security = _job_block(self.content, "shared_security")
        self.assertIn("&& secrets.SONAR_TOKEN || ''", security)
        self.assertIn("&& secrets.SONAR_HOST_URL || ''", security)
        self.assertIn("&& vars.TS_OAUTH_CLIENT_ID || ''", security)
        self.assertIn("&& vars.TS_AUDIENCE || ''", security)

    def test_missing_sonar_configuration_is_nonblocking(self):
        security = _job_block(self.content, "shared_security")
        self.assertIn("sonar-project-key:", security)
        self.assertIn("secrets.SONAR_TOKEN", security)
        self.assertIn("secrets.SONAR_HOST_URL", security)
        self.assertIn("tailscale-client-id:", security)
        self.assertIn("tailscale-audience:", security)

    def test_branch_override_replaces_defaults_for_both_events(self):
        self.assertEqual(
            self.content.count("branches: [development, homolog, main]"),
            2,
        )

    def test_coverage_manifest_and_artifact_id_match_this_run_and_source_sha(self):
        coverage = _job_block(self.content, "coverage")
        self.assertIn("artifact_id: ${{ steps.upload.outputs.artifact-id }}", coverage)
        self.assertIn("coverage-artifact-id: ${{ needs.coverage.outputs.artifact_id }}", self.content)
        self.assertIn('"version": 1', coverage)
        self.assertIn('"source_sha": os.environ["SOURCE_SHA"]', coverage)
        self.assertIn('"language": "python", "path": "python/coverage.xml"', coverage)
        self.assertIn("github.event.pull_request.head.sha", coverage)
        self.assertIn("github.sha", coverage)
        self.assertIn("shared-security-coverage-${{ github.run_id }}-${{ github.run_attempt }}", coverage)
        self.assertNotRegex(coverage, r"(?m)^\s+retention-days:")

    def test_coverage_job_has_read_only_contents_and_no_secrets_or_oidc(self):
        coverage = _job_block(self.content, "coverage")
        self.assertIn("permissions:\n      contents: read", coverage)
        self.assertNotIn("id-token: write", coverage)
        self.assertNotIn("secrets.", coverage)
        self.assertNotIn("vars.", coverage)
        self.assertIn("persist-credentials: false", coverage)

    def test_preview_gate_compares_central_decision_and_head_sha(self):
        gate = _job_block(self.content, "preview_gate")
        self.assertIn("name: security-gate-preview", gate)
        self.assertIn("needs: shared_security", gate)
        self.assertIn("always() && github.event_name == 'pull_request_target'", gate)
        self.assertIn("EXPECTED_SHA: ${{ github.event.pull_request.head.sha }}", gate)
        self.assertIn("SOURCE_SHA: ${{ needs.shared_security.outputs.source_sha }}", gate)
        self.assertIn("DECISION: ${{ needs.shared_security.outputs.decision }}", gate)
        self.assertIn("BLOCKING_COUNT: ${{ needs.shared_security.outputs.blocking_count }}", gate)

    def test_workflow_concurrency_is_scoped_to_repository_and_pull_or_ref(self):
        self.assertIn(
            "group: shared-security-preview-${{ github.repository }}-${{ github.event.pull_request.number || github.ref }}",
            self.content,
        )
        self.assertIn("cancel-in-progress: true", self.content)

    def test_dependabot_tracks_github_actions_and_preserves_sha_pins(self):
        config = DEPENDABOT.read_text(encoding="utf-8")
        self.assertIn("version: 2", config)
        self.assertIn("package-ecosystem: github-actions", config)
        self.assertIn('directory: "/"', config)
        self.assertIn("interval: weekly", config)
        self.assertIn("day: monday", config)

        references = re.findall(r"(?m)^\s*uses:\s+([^\s]+)", self.content)
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(reference, r"@[0-9a-f]{40}\Z", reference)
            self.assertNotRegex(reference, r"@(main|master|v?[0-9]+(?:\.[0-9]+)*)\Z", reference)


if __name__ == "__main__":
    unittest.main()
