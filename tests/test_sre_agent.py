import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from ai.sre_agent import analyze_incidents, detect_incidents, parse_gemini_response
from models.evidence import IncidentEvidence


def recent_timestamp():
    return datetime.now(timezone.utc).isoformat()


def stale_timestamp():
    return (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()


class SREAgentTests(unittest.TestCase):
    def test_gemini_json_response_is_validated_and_redacted(self):
        parsed = parse_gemini_response(
            """```json
{"likely_root_cause":"Probe configuration is a hypothesis; token=secret-value",
 "confidence":"medium",
 "alternative_hypotheses":["Transient dependency failure"]}
```"""
        )

        self.assertEqual(parsed["confidence"], "medium")
        self.assertEqual(
            parsed["likely_root_cause"],
            "Probe configuration is a hypothesis; token=[REDACTED]",
        )
        with self.assertRaisesRegex(ValueError, "required incident schema"):
            parse_gemini_response('{"likely_root_cause":"missing fields"}')

    def test_deduplicates_same_workload_and_correlates_image_to_commit(self):
        commit_sha = "a" * 40
        items = [
            IncidentEvidence(
                cluster="gke-ai-k8s-monitoring",
                namespace="ai-troubleshooter",
                workload="ai-k8s-demo",
                pod=f"ai-k8s-demo-{suffix}",
                status="Running",
                ready=False,
                restarts=0,
                events=[],
                logs=[],
                images=[f"asia-south1-docker.pkg.dev/example/ai-k8s-repo/ai-k8s-demo:{commit_sha}"],
                observed_at=recent_timestamp(),
                source_status={"kubernetes": "available", "grafana": "available"},
            )
            for suffix in ("one", "two")
        ]
        bundle = {
            "cluster": "gke-ai-k8s-monitoring",
            "observed_at": recent_timestamp(),
            "items": items,
            "deployments": [],
            "cluster_metrics": [],
            "github_actions": {
                "status": "available",
                "run": {
                    "run_id": 25,
                    "commit_sha": commit_sha,
                    "updated_at": recent_timestamp(),
                },
            },
        }

        incidents = detect_incidents(bundle)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(len(incidents[0].pods), 2)
        self.assertTrue(
            any("matches the latest workflow commit" in fact for fact in incidents[0].facts)
        )
        self.assertEqual(incidents[0].source_status["github_actions"], "available")

    def test_image_pull_and_oom_signals_are_distinct(self):
        image_pull = IncidentEvidence(
            namespace="ai-troubleshooter",
            workload="ai-k8s-demo",
            pod="pod-image",
            status="Pending",
            ready=False,
            restarts=0,
            events=[],
            logs=[],
            state_reasons=["ImagePullBackOff"],
        )
        oom = IncidentEvidence(
            namespace="ai-troubleshooter",
            workload="ai-k8s-demo",
            pod="pod-oom",
            status="Running",
            ready=True,
            restarts=1,
            events=[],
            logs=[],
            state_reasons=["OOMKilled"],
        )
        bundle = {
            "observed_at": recent_timestamp(),
            "items": [image_pull, oom],
            "deployments": [],
            "cluster_metrics": [],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incidents = detect_incidents(bundle)

        self.assertEqual(
            {incident.category for incident in incidents},
            {"image_pull_failure", "resource_exhaustion"},
        )
        self.assertTrue(
            all(incident.source_status["github_actions"] == "unavailable" for incident in incidents)
        )

    def test_stale_github_and_grafana_data_are_reported_unavailable(self):
        item = IncidentEvidence(
            namespace="ai-troubleshooter",
            workload="ai-k8s-demo",
            pod="demo-pod",
            status="Running",
            ready=False,
            restarts=0,
            events=[],
            logs=[],
            metrics=[
                {
                    "metric": "application.error_rate",
                    "value": 4,
                    "unit": "requests/second",
                    "scope": "application",
                    "status": "available",
                    "observed_at": stale_timestamp(),
                }
            ],
        )
        bundle = {
            "observed_at": recent_timestamp(),
            "items": [item],
            "deployments": [],
            "cluster_metrics": [],
            "github_actions": {
                "status": "available",
                "run": {
                    "run_id": 5,
                    "commit_sha": "abc",
                    "updated_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                },
            },
        }

        incident = detect_incidents(bundle)[0]

        self.assertIn("latest GitHub Actions deployment history is stale".lower(), " ".join(incident.missing_evidence).lower())
        self.assertEqual(incident.source_status["github_actions"], "stale")

    @patch.dict("os.environ", {}, clear=True)
    def test_gemini_unavailable_uses_explicit_rules_fallback_without_log_content(self):
        item = IncidentEvidence(
            cluster="cluster",
            namespace="ai-troubleshooter",
            workload="ai-k8s-demo",
            pod="demo-pod",
            status="Running",
            ready=False,
            restarts=0,
            events=["[time] Unhealthy: Authorization: Bearer abcdefghijklmnopqrstuvwxyz"],
            logs=["customer private log payload"],
        )
        bundle = {
            "cluster": "cluster",
            "observed_at": recent_timestamp(),
            "items": [item],
            "deployments": [],
            "cluster_metrics": [],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incident = analyze_incidents(bundle)[0]

        self.assertEqual(incident.analysis_mode, "rules-based fallback")
        self.assertIn("## 1. Incident summary", incident.analysis)
        self.assertIn("Analysis mode: rules-based fallback", incident.analysis)
        self.assertIn("## 11. Post-remediation verification", incident.analysis)
        self.assertNotIn("customer private log payload", incident.analysis)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", incident.analysis)

    @patch.dict(
        "os.environ",
        {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "test-model"},
        clear=True,
    )
    @patch("ai.sre_agent.genai.Client")
    def test_invalid_gemini_json_uses_rules_fallback(self, genai_client):
        genai_client.return_value.models.generate_content.return_value.text = (
            "not valid structured output"
        )
        item = IncidentEvidence(
            namespace="ai-troubleshooter",
            workload="ai-k8s-demo",
            pod="demo-pod",
            status="Running",
            ready=False,
            restarts=0,
            events=[],
            logs=[],
        )
        bundle = {
            "observed_at": recent_timestamp(),
            "items": [item],
            "deployments": [],
            "cluster_metrics": [],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incident = analyze_incidents(bundle)[0]

        self.assertEqual(incident.analysis_mode, "rules-based fallback")
        self.assertTrue(
            any("Gemini analysis unavailable" in value for value in incident.missing_evidence)
        )

    def test_deployment_unavailable_replicas_create_workload_incident(self):
        bundle = {
            "observed_at": recent_timestamp(),
            "items": [],
            "deployments": [
                {
                    "namespace": "ai-troubleshooter",
                    "name": "ai-k8s-demo",
                    "desired_replicas": 2,
                    "available_replicas": 1,
                    "conditions": [],
                }
            ],
            "cluster_metrics": [],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incidents = detect_incidents(bundle)

        self.assertEqual(incidents[0].category, "failed_rollout")
        self.assertIn("rollout_restart", incidents[0].eligible_remediations)

    def test_application_health_and_scrape_failures_create_incidents(self):
        bundle = {
            "observed_at": recent_timestamp(),
            "items": [],
            "deployments": [],
            "cluster_metrics": [
                {
                    "metric": "application.health_status",
                    "value": 0,
                    "scope": "application",
                    "status": "available",
                    "observed_at": recent_timestamp(),
                },
                {
                    "metric": "application.scrape_up",
                    "value": 0,
                    "scope": "application",
                    "status": "available",
                    "observed_at": recent_timestamp(),
                },
            ],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incidents = detect_incidents(bundle)

        self.assertEqual(
            {incident.category for incident in incidents},
            {"application_health_failure", "grafana_scrape_failure"},
        )


if __name__ == "__main__":
    unittest.main()
