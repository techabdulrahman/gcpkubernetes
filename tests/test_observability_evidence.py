import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ai.analyzer import KubernetesAnalyzer
from collectors.evidence_collector import build_observability_evidence
from models.evidence import IncidentEvidence


class ObservabilityEvidenceTests(unittest.TestCase):
    @patch("collectors.evidence_collector.collect_grafana_metrics")
    @patch("collectors.evidence_collector.get_deployments")
    @patch("collectors.evidence_collector.get_all_pod_logs")
    @patch("collectors.evidence_collector.get_events")
    @patch("collectors.evidence_collector.get_pods")
    @patch("collectors.evidence_collector.load_kubernetes_config")
    def test_builder_keeps_node_metrics_out_of_pod_evidence(
        self,
        load_config,
        get_pods,
        get_events,
        get_logs,
        get_deployments,
        collect_metrics,
    ):
        get_pods.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo-123",
                "node": "node-a",
                "workload": "ai-k8s-demo",
                "workload_kind": "ReplicaSet",
                "phase": "Running",
                "ready": True,
                "restarts": 1,
                "containers": [{"name": "app", "ready": True}],
                "last_termination_reason": None,
                "last_exit_code": None,
                "last_termination_message": None,
            }
        ]
        get_events.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "object": "ai-k8s-demo-123",
                "reason": "BackOff",
                "message": "container restarting",
            }
        ]
        get_logs.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "pod": "ai-k8s-demo-123",
                "container": "app",
                "logs": "ERROR startup failed",
            }
        ]
        get_deployments.return_value = []
        collect_metrics.return_value = {
            "cluster": "verified-cluster",
            "cluster_metrics": [
                {
                    "metric": "node.cpu_usage",
                    "value": 3.0,
                    "unit": "cores",
                    "scope": "node",
                    "status": "available",
                }
            ],
            "pod_metrics": {
                "ai-k8s-demo-123": [
                    {
                        "metric": "container.cpu_usage",
                        "value": 0.25,
                        "unit": "cores",
                        "scope": "container",
                        "status": "available",
                    }
                ]
            },
            "diagnostics": [],
        }

        bundle = build_observability_evidence()
        item = bundle["items"][0]

        self.assertEqual(bundle["cluster"], "verified-cluster")
        self.assertEqual(item.cluster, "verified-cluster")
        self.assertEqual(item.node, "node-a")
        self.assertEqual(
            item.events,
            ["[time unavailable] BackOff: container restarting"],
        )
        self.assertEqual(item.logs, ["app: ERROR startup failed"])
        self.assertEqual(item.metrics[0]["scope"], "container")
        self.assertTrue(
            all(metric["scope"] != "node" for metric in item.metrics)
        )
        self.assertEqual(bundle["cluster_metrics"][0]["scope"], "node")

    def test_gemini_input_redacts_untrusted_logs_and_keeps_metric_scopes(self):
        evidence = IncidentEvidence(
            cluster="verified-cluster",
            namespace="ai-troubleshooter",
            pod="demo-123",
            status="Running",
            restarts=0,
            events=["ProbeFailed: token=do-not-send"],
            logs=["ERROR password=do-not-send"],
            metrics=[
                {
                    "metric": "container.cpu_usage",
                    "value": 0.2,
                    "unit": "cores",
                    "scope": "container",
                    "status": "available",
                }
            ],
        )
        response = SimpleNamespace(text="Evidence is insufficient.")
        client = SimpleNamespace(
            models=SimpleNamespace(
                generate_content=lambda **kwargs: (
                    self._capture_prompt(kwargs["contents"], response)
                )
            )
        )
        with patch("ai.analyzer.genai.Client", return_value=client):
            analyzer = KubernetesAnalyzer()
            analyzer.api_key = "test-key"
            analyzer.model = "test-model"
            analyzer._analyze_with_gemini(
                evidence,
                cluster_metrics=[
                    {
                        "metric": "node.cpu_usage",
                        "value": 4.0,
                        "unit": "cores",
                        "scope": "node",
                        "status": "available",
                    }
                ],
                github_failure={
                    "run_url": "https://github.example/run/1",
                    "log": "failure",
                },
            )

        payload = json.loads(self.captured_prompt.split("Evidence JSON", 1)[1].split("\n", 1)[1])
        self.assertNotIn("do-not-send", self.captured_prompt)
        self.assertIn('"scope": "container"', self.captured_prompt)
        self.assertIn('"scope": "node"', self.captured_prompt)
        self.assertEqual(
            payload["cluster_and_workload_metrics"][0]["scope"],
            "node",
        )
        self.assertIn("untrusted data", self.captured_prompt)
        self.assertIn("Do not claim any fix was applied", self.captured_prompt)

    def _capture_prompt(self, prompt, response):
        self.captured_prompt = prompt
        return response


if __name__ == "__main__":
    unittest.main()
