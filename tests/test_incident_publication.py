import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts.investigate_kubernetes import collect_evidence, publish_incidents


class IncidentPublicationTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "version": 1,
            "observed_at": "2026-10-14T10:00:00+00:00",
            "incidents": [
                {
                    "incident_id": "inc-1234567890abcdef",
                    "category": "unready_pod",
                    "severity": "high",
                    "detected_at": "2026-10-14T10:00:00+00:00",
                    "namespace": "ai-troubleshooter",
                    "workload": "ai-k8s-demo",
                    "analysis_mode": "rules-based fallback",
                    "analysis": "No confirmed cause; inspect readiness events.",
                    "eligible_remediations": ["rollout_restart"],
                },
                {
                    "incident_id": "inc-abcdef1234567890",
                    "category": "image_pull_failure",
                    "severity": "high",
                    "detected_at": "2026-10-14T10:00:00+00:00",
                    "namespace": "ai-troubleshooter",
                    "workload": "ai-k8s-demo",
                    "analysis_mode": "rules-based fallback",
                    "analysis": "Check the image URI and pull identity.",
                    "eligible_remediations": [],
                },
            ],
        }

    @patch("scripts.investigate_kubernetes._github_request")
    def test_incidents_are_published_and_open_issue_is_updated_for_dedup(self, request):
        request.side_effect = [
            {"items": [{"title": "AI SRE incident inc-1234567890abcdef", "number": 9, "state": "open"}]},
            {},
            {"items": []},
            {"number": 10},
        ]

        results = publish_incidents(
            self.payload,
            "example/repo",
            "test-token",
            "12345",
        )

        self.assertEqual([result["issue_number"] for result in results], [9, 10])
        self.assertTrue(results[0]["deduplicated"])
        self.assertFalse(results[1]["deduplicated"])
        self.assertEqual(request.call_args_list[1].args[0], "PATCH")
        self.assertEqual(request.call_args_list[3].args[0], "POST")
        self.assertIn("No automated remediation is currently eligible", request.call_args_list[3].args[3]["body"])

    @patch("scripts.investigate_kubernetes._github_request")
    def test_report_contains_no_raw_log_payload(self, request):
        self.payload["incidents"] = self.payload["incidents"][:1]
        self.payload["incidents"][0]["logs"] = ["customer private log payload"]
        request.side_effect = [
            {"items": []},
            {"number": 11},
        ]

        publish_incidents(
            self.payload,
            "example/repo",
            "test-token",
            "12345",
        )

        body = request.call_args.args[3]["body"]
        self.assertNotIn("customer private log payload", body)

    @patch("scripts.investigate_kubernetes.analyze_incidents")
    @patch("scripts.investigate_kubernetes.build_observability_evidence")
    def test_durable_incident_evidence_omits_raw_pod_logs(self, build_evidence, analyze):
        build_evidence.return_value = {
            "cluster": "gke-ai-k8s-monitoring",
            "observed_at": "2026-10-14T10:00:00+00:00",
            "items": [],
            "cluster_metrics": [],
            "diagnostics": [],
            "github_actions": {"status": "unavailable"},
            "raw_log": "private raw log payload",
        }
        analyze.return_value = [
            SimpleNamespace(
                to_dict=lambda: {
                    "incident_id": "inc-1234567890abcdef",
                    "analysis": "Rules-based report without log text.",
                }
            )
        ]

        payload = collect_evidence()

        self.assertNotIn("private raw log payload", repr(payload))
        self.assertNotIn("raw_log", payload)


if __name__ == "__main__":
    unittest.main()
