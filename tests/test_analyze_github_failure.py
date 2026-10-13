import io
import unittest
import urllib.request
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from google.genai.errors import APIError
from scripts.analyze_github_failure import (
    AnalysisError,
    GitHubRedirectHandler,
    analyze_with_gemini,
    build_prompt,
    collect_optional_grafana_evidence,
    format_commit_diff,
    format_report,
    parse_failure_steps,
    parse_log_archive,
    redact_sensitive_values,
    truncate_text,
)


class GitHubFailureAnalysisTests(unittest.TestCase):
    def test_parse_failure_steps_includes_only_failed_steps(self):
        jobs = {
            "jobs": [
                {
                    "name": "Build and deploy",
                    "steps": [
                        {"name": "Build image", "conclusion": "success"},
                        {"name": "Rollout", "conclusion": "failure"},
                        {"name": "Diagnostics", "conclusion": "skipped"},
                    ],
                }
            ]
        }

        self.assertEqual(
            parse_failure_steps(jobs),
            ["Build and deploy / Rollout"],
        )

    def test_parse_log_archive_reads_text_without_extracting(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("deploy/2_Deploy.txt", "kubectl rollout failed")
            archive.writestr("deploy/image.bin", b"\x00\x01")

        logs = parse_log_archive(buffer.getvalue())

        self.assertIn("--- 2_Deploy.txt ---", logs)
        self.assertIn("kubectl rollout failed", logs)
        self.assertNotIn("image.bin", logs)

    def test_parse_log_archive_reports_no_log_content(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("deploy/2_Deploy.txt", "")

        with self.assertRaisesRegex(AnalysisError, "no readable text logs"):
            parse_log_archive(buffer.getvalue())

    def test_truncate_text_preserves_both_ends_and_marks_truncation(self):
        truncated = truncate_text("START" + ("x" * 100) + "END", 80)

        self.assertLessEqual(len(truncated), 80)
        self.assertIn("START", truncated)
        self.assertTrue(truncated.endswith("END"))
        self.assertIn("truncated", truncated)

    def test_redact_sensitive_values(self):
        text = (
            "password=hunter2\n"
            "Authorization: Bearer arbitrary-token-value\n"
            "https://user:secret@example.test/path"
        )

        redacted = redact_sensitive_values(text)

        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("arbitrary-token-value", redacted)
        self.assertNotIn("user:secret@", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_format_commit_diff_omits_credential_files(self):
        diff = format_commit_diff(
            [
                {"filename": "app/config.py", "patch": "+timeout = 30"},
                {"filename": "config/service-account.json", "patch": "+private key"},
                {"filename": ".env.production", "patch": "+TOKEN=secret"},
            ]
        )

        self.assertIn("app/config.py", diff)
        self.assertNotIn("service-account.json", diff)
        self.assertNotIn(".env.production", diff)
        self.assertIn("2 changed file(s)", diff)

    def test_format_report_includes_run_url_and_commit_sha(self):
        report = format_report(
            "## Root cause\nRollout timed out.",
            "https://github.com/example/project/actions/runs/123",
            "abc123",
        )

        self.assertIn("https://github.com/example/project/actions/runs/123", report)
        self.assertIn("`abc123`", report)
        self.assertIn("## Root cause", report)

    def test_cross_host_redirect_does_not_forward_github_token(self):
        request = urllib.request.Request(
            "https://api.github.com/repos/example/project/actions/runs/123/logs",
            headers={"Authorization": "Bearer sensitive-token"},
        )

        redirected = GitHubRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://signed-download.example.test/logs.zip",
        )

        self.assertIsNone(redirected.get_header("Authorization"))

    def test_gemini_quota_error_is_reported_without_api_error_details(self):
        api_error = APIError(
            code=429,
            response_json={"error": {"message": "quota exceeded"}},
        )
        with patch("scripts.analyze_github_failure.genai.Client", side_effect=api_error):
            with self.assertRaisesRegex(AnalysisError, "quota or rate limit"):
                analyze_with_gemini({}, "test-key", "test-model")

    def test_gemini_authentication_error_is_reported(self):
        api_error = APIError(
            code=403,
            response_json={"error": {"message": "permission denied"}},
        )
        with patch("scripts.analyze_github_failure.genai.Client", side_effect=api_error):
            with self.assertRaisesRegex(AnalysisError, "authentication failed"):
                analyze_with_gemini({}, "test-key", "test-model")

    def test_gemini_empty_response_is_reported(self):
        client = SimpleNamespace(
            models=SimpleNamespace(
                generate_content=lambda **kwargs: SimpleNamespace(text=" ")
            )
        )
        evidence = {
            "failed_steps": [],
            "commit_message": "test",
            "diff": "test",
            "logs": "test",
        }
        with patch("scripts.analyze_github_failure.genai.Client", return_value=client):
            with self.assertRaisesRegex(AnalysisError, "empty response"):
                analyze_with_gemini(evidence, "test-key", "test-model")

    @patch.dict("os.environ", {}, clear=True)
    def test_grafana_evidence_is_optional(self):
        evidence = collect_optional_grafana_evidence()
        self.assertEqual(evidence["status"], "unavailable")
        self.assertEqual(evidence["metrics"], [])
        self.assertIn("GRAFANA_TOKEN", evidence["diagnostics"][0])

    @patch("scripts.analyze_github_failure.collect_grafana_metrics")
    @patch.dict(
        "os.environ",
        {
            "GRAFANA_PROM_URL": "https://metrics.example.test/api/prom",
            "GRAFANA_USERNAME": "stack-user",
            "GRAFANA_TOKEN": "private-token",
            "GRAFANA_CLUSTER": "cluster-a",
        },
        clear=True,
    )
    def test_optional_grafana_context_is_scoped_and_filters_labels(self, collect):
        collect.return_value = {
            "cluster": "cluster-a",
            "cluster_metrics": [
                {
                    "metric": "container.cpu_usage",
                    "value": 0.2,
                    "unit": "cores",
                    "scope": "container",
                    "status": "available",
                    "observed_at": "2026-10-13T00:00:00Z",
                    "diagnostic": None,
                    "labels": {
                        "cluster_name": "cluster-a",
                        "pod": "demo-1",
                        "container": "app",
                        "credential": "must-not-be-included",
                    },
                }
            ],
            "diagnostics": [],
        }

        evidence = collect_optional_grafana_evidence()

        collect.assert_called_once()
        self.assertEqual(evidence["status"], "available")
        self.assertEqual(evidence["metrics"][0]["scope"], "container")
        self.assertNotIn("credential", evidence["metrics"][0]["labels"])
        self.assertNotIn("private-token", repr(evidence))
        prompt = build_prompt(
            {
                "failed_steps": [],
                "commit_message": "failed",
                "diff": "",
                "logs": "",
                "grafana_evidence": evidence,
            }
        )
        self.assertIn("Optional Grafana Cloud Prometheus evidence", prompt)


if __name__ == "__main__":
    unittest.main()
