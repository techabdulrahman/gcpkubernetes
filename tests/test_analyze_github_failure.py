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
    collect_optional_kubernetes_evidence,
    classify_failure,
    format_commit_diff,
    format_report,
    parse_failure_steps,
    parse_log_archive,
    redact_sensitive_values,
    rules_based_failure_analysis,
    truncate_text,
)


class GitHubFailureAnalysisTests(unittest.TestCase):
    @patch.dict("os.environ", {"KUBERNETES_EVIDENCE_ENABLED": "true"}, clear=True)
    @patch("collectors.logs_collector.get_pod_logs")
    @patch("collectors.kubernetes_collector.get_events")
    @patch("collectors.kubernetes_collector.get_deployments")
    @patch("collectors.kubernetes_collector.get_pods")
    @patch("collectors.kubernetes_collector.load_kubernetes_config")
    def test_optional_kubernetes_evidence_is_correlated_and_redacts_logs(
        self,
        load_config,
        get_pods,
        get_deployments,
        get_events,
        get_logs,
    ):
        commit_sha = "a" * 40
        get_pods.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo-abc123",
                "workload": "ai-k8s-demo",
                "phase": "Running",
                "ready": False,
                "restarts": 3,
                "images": [f"example/image:{commit_sha}"],
                "state_reasons": ["CrashLoopBackOff"],
                "last_termination_reason": "Error",
                "last_exit_code": 1,
                "containers": [{"name": "app"}],
            }
        ]
        get_deployments.return_value = [
            {"name": "ai-k8s-demo", "available_replicas": 1}
        ]
        get_events.return_value = [
            {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "type": "Warning",
                "reason": "BackOff",
                "object": "ai-k8s-demo-abc123",
                "message": "ERROR token=private-value",
            }
        ]
        get_logs.return_value = "ERROR token=private-value"

        evidence = collect_optional_kubernetes_evidence(commit_sha)

        load_config.assert_called_once()
        self.assertEqual(evidence["status"], "available")
        self.assertEqual(
            evidence["image_commit_correlation"],
            "image tag contains workflow commit SHA",
        )
        self.assertEqual(evidence["pods"][0]["log_markers"], ["error"])
        self.assertNotIn("private-value", repr(evidence))

    def test_failure_classification_distinguishes_build_registry_rollout_and_health(self):
        self.assertEqual(
            classify_failure(["Build image"], "docker build failed"),
            "container_build_failure",
        )
        self.assertEqual(
            classify_failure(["Push image"], "denied: permission denied"),
            "registry_image_push_failure",
        )
        self.assertEqual(
            classify_failure(["Verify rollout"], "rollout timed out"),
            "kubernetes_rollout_timeout",
        )
        self.assertEqual(
            classify_failure(["Health check"], "GET /health returned 500"),
            "post_deployment_health_check_failure",
        )
        self.assertEqual(
            classify_failure(["Run tests"], "pytest: test failed"),
            "application_test_failure",
        )

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

    @patch("scripts.analyze_github_failure.urllib.request.build_opener")
    def test_github_api_request_uses_supplied_token(self, build_opener):
        opener = build_opener.return_value
        opener.open.return_value.__enter__.return_value.read.return_value = b"{}"

        from scripts.analyze_github_failure import github_get

        github_get("https://api.github.com/repos/example/project", "test-token")

        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    def test_rules_based_ci_analysis_marks_uncertainty_and_missing_sources(self):
        report = rules_based_failure_analysis(
            {
                "failure_type": "kubernetes_rollout_timeout",
                "run_id": "123",
                "run_url": "https://github.com/example/repo/actions/runs/123",
                "commit_sha": "abc123",
                "failed_steps": ["Deploy / Verify deployment rollout"],
                "grafana_evidence": {"status": "unavailable"},
            },
            RuntimeError("Gemini unavailable"),
        )

        self.assertIn("Low confidence", report)
        self.assertIn("hypotheses", report.lower())
        self.assertIn("Kubernetes evidence status: `unavailable`", report)
        self.assertIn("No change was applied", report)

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
