import os
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

from ai.safety import redact_sensitive_values
from collectors.grafana_metrics_collector import (
    GrafanaConfig,
    GrafanaPrometheusError,
    collect_grafana_metrics,
    query_prometheus,
    resolve_cluster_label,
)
from scripts import test_grafana_metrics


class GrafanaMetricsTests(unittest.TestCase):
    def setUp(self):
        self.config = GrafanaConfig(
            url="https://prometheus.example.test/api/prom",
            username="stack-user",
            token="test-token",
            cluster="ai-k8s-cluster",
        )

    @patch.dict(
        os.environ,
        {
            "GRAFANA_PROM_URL": "https://prometheus.example.test/api/prom",
            "GRAFANA_USERNAME": "stack-user",
            "GRAFANA_TOKEN": "test-token",
            "GRAFANA_CLUSTER": "gke-production",
        },
        clear=True,
    )
    def test_config_builds_grafana_cloud_query_endpoint(self):
        from collectors.grafana_metrics_collector import load_grafana_config

        config = load_grafana_config()
        self.assertEqual(
            config.query_url,
            "https://prometheus.example.test/api/prom/api/v1/query",
        )

    @patch("collectors.grafana_metrics_collector.requests.get")
    def test_query_uses_basic_auth_timeout_and_parses_result(self, get):
        response = Mock(ok=True)
        response.status_code = 200
        response.json.return_value = {
            "status": "success",
            "data": {"result": [{"metric": {"cluster_name": "gke-production"}}]},
        }
        get.return_value = response

        result = query_prometheus("up", self.config)

        self.assertEqual(result[0]["metric"]["cluster_name"], "gke-production")
        get.assert_called_once()
        self.assertEqual(
            get.call_args.kwargs["auth"],
            ("stack-user", "test-token"),
        )
        self.assertEqual(get.call_args.kwargs["timeout"], 20)
        self.assertEqual(
            get.call_args.args[0],
            "https://prometheus.example.test/api/prom/api/v1/query",
        )
        self.assertEqual(get.call_args.kwargs["params"], {"query": "up"})

    @patch("collectors.grafana_metrics_collector.requests.get")
    def test_authentication_and_transport_errors_do_not_leak_credentials(self, get):
        response = Mock(ok=False, status_code=401)
        get.return_value = response
        with self.assertRaisesRegex(GrafanaPrometheusError, "HTTP 401"):
            query_prometheus("up", self.config)

        get.side_effect = requests.Timeout("https://user:token@example.test")
        with self.assertRaisesRegex(GrafanaPrometheusError, "check the API URL"):
            query_prometheus("up", self.config)

    @patch("collectors.grafana_metrics_collector.requests.get")
    def test_invalid_json_and_bad_response_shape_are_rejected(self, get):
        response = Mock(ok=True, status_code=200)
        response.json.side_effect = ValueError("invalid")
        get.return_value = response
        with self.assertRaisesRegex(GrafanaPrometheusError, "invalid JSON"):
            query_prometheus("up", self.config)

        response.json.side_effect = None
        response.json.return_value = {"status": "success", "data": None}
        with self.assertRaisesRegex(GrafanaPrometheusError, "invalid result"):
            query_prometheus("up", self.config)

    def test_cluster_label_is_discovered_and_mismatch_is_reported(self):
        results = [
            {"metric": {"cluster_name": "gke-production", "job": "node"}},
            {"metric": {"cluster_name": "gke-production", "job": "kubelet"}},
        ]
        self.assertEqual(resolve_cluster_label(results, "gke-production"), "cluster_name")

        with self.assertRaisesRegex(GrafanaPrometheusError, "GRAFANA_CLUSTER"):
            resolve_cluster_label(results, "different-cluster")

    @patch("collectors.grafana_metrics_collector.query_prometheus")
    def test_collected_metrics_keep_node_and_pod_scopes_separate(self, query):
        def query_response(promql, config):
            if promql == "up":
                return [
                    {
                        "metric": {
                            "cluster_name": self.config.cluster,
                            "job": "node",
                        }
                    }
                ]
            if "node_cpu_seconds_total" in promql and 'mode="idle"' in promql:
                return [{"metric": {"instance": "node-a"}, "value": [1, "4"]}]
            if "node_cpu_seconds_total" in promql:
                return [{"metric": {"instance": "node-a"}, "value": [1, "1"]}]
            if "node_memory_MemTotal_bytes" in promql:
                return [{"metric": {"instance": "node-a"}, "value": [1, "1000"]}]
            if "node_memory_MemAvailable_bytes" in promql:
                return [{"metric": {"instance": "node-a"}, "value": [1, "250"]}]
            if "container_cpu_usage_seconds_total" in promql:
                return [
                    {
                        "metric": {
                            "namespace": "ai-troubleshooter",
                            "pod": "demo-123",
                            "container": "app",
                        },
                        "value": [1, "0.25"],
                    }
                ]
            if "container_memory_working_set_bytes" in promql:
                return [
                    {
                        "metric": {
                            "namespace": "ai-troubleshooter",
                            "pod": "demo-123",
                            "container": "app",
                        },
                        "value": [1, "256"],
                    }
                ]
            return []

        query.side_effect = query_response
        evidence = collect_grafana_metrics(
            [{"name": "demo-123"}],
            "ai-troubleshooter",
            "ai-k8s-demo",
            self.config,
        )

        node_cpu = next(
            item for item in evidence["cluster_metrics"]
            if item["metric"] == "node.cpu_usage"
        )
        node_utilization = next(
            item for item in evidence["cluster_metrics"]
            if item["metric"] == "node.cpu_utilization_percent"
        )
        pod_metrics = evidence["pod_metrics"]["demo-123"]
        container_cpu = next(
            item for item in pod_metrics
            if item["metric"] == "container.cpu_usage"
        )

        self.assertEqual(node_cpu["scope"], "node")
        self.assertEqual(node_cpu["value"], 1.0)
        self.assertEqual(node_utilization["value"], 25.0)
        self.assertEqual(node_utilization["unit"], "percent")
        self.assertEqual(container_cpu["scope"], "container")
        self.assertEqual(container_cpu["value"], 0.25)
        self.assertNotIn(node_cpu, pod_metrics)

    @patch("collectors.grafana_metrics_collector.query_prometheus")
    def test_empty_metric_vector_is_unavailable_not_zero(self, query):
        query.side_effect = lambda promql, config: (
            [{"metric": {"cluster_name": self.config.cluster}}]
            if promql == "up"
            else []
        )
        evidence = collect_grafana_metrics(
            [{"name": "demo-123"}],
            "ai-troubleshooter",
            "ai-k8s-demo",
            self.config,
        )

        unavailable = next(
            item for item in evidence["cluster_metrics"]
            if item["metric"] == "node.cpu_usage"
        )
        self.assertIsNone(unavailable["value"])
        self.assertEqual(unavailable["status"], "unavailable")
        self.assertIn("scrape configuration", unavailable["diagnostic"])
        self.assertTrue(
            all(
                item["status"] == "unavailable"
                for item in evidence["pod_metrics"]["demo-123"]
            )
        )

    def test_missing_credentials_return_diagnostic_not_zero_metrics(self):
        with patch(
            "collectors.grafana_metrics_collector.load_grafana_config",
            side_effect=GrafanaPrometheusError(
                "Missing required environment variable(s): GRAFANA_TOKEN"
            ),
        ):
            evidence = collect_grafana_metrics(
                [{"name": "demo-123"}],
                "ai-troubleshooter",
                "ai-k8s-demo",
            )
        self.assertEqual(evidence["cluster_metrics"][0]["status"], "unavailable")
        self.assertIn("GRAFANA_TOKEN", evidence["diagnostics"][0])

    @patch("scripts.test_grafana_metrics.load_grafana_config")
    @patch("scripts.test_grafana_metrics.query_prometheus")
    def test_connectivity_check_verifies_cluster_and_gke_series(
        self,
        query,
        load_config,
    ):
        load_config.return_value = self.config
        def query_response(promql, config=None):
            if promql == "up":
                return [{"metric": {"cluster_name": self.config.cluster}}]
            if "kube_node_status_capacity" in promql:
                return [{"metric": {"node": "node-a"}}]
            if "container_cpu_usage_seconds_total" in promql:
                if "namespace=" in promql:
                    return [{"metric": {"pod": "ai-k8s-demo-123", "container": "app"}}]
                return [{"metric": {"instance": "node-a"}}]
            if "container_memory_working_set_bytes" in promql:
                if "namespace=" in promql:
                    return [{"metric": {"pod": "ai-k8s-demo-123", "container": "app"}}]
                return [{"metric": {"instance": "node-a"}}]
            if "kube_pod_info" in promql:
                return [{"metric": {"pod": "ai-k8s-demo-123"}}]
            return []

        query.side_effect = query_response
        output = io.StringIO()
        with redirect_stdout(output):
            result = test_grafana_metrics.main()

        self.assertEqual(result, 0)
        self.assertEqual(query.call_count, 8)
        self.assertIn("matched returned label 'cluster_name'", output.getvalue())
        self.assertIn("node CPU usage", output.getvalue())
        self.assertIn("application pod CPU", output.getvalue())
        self.assertIn("application pod memory", output.getvalue())

    @patch("scripts.test_grafana_metrics.load_grafana_config")
    @patch("scripts.test_grafana_metrics.query_prometheus", return_value=[])
    def test_connectivity_check_reports_empty_up_series(
        self,
        _query,
        load_config,
    ):
        load_config.return_value = self.config
        output = io.StringIO()
        with redirect_stdout(output):
            result = test_grafana_metrics.main()

        self.assertEqual(result, 1)
        self.assertIn("no `up` series", output.getvalue())
        self.assertIn("metrics:read", output.getvalue())

    @patch("scripts.test_grafana_metrics.load_grafana_config")
    @patch("scripts.test_grafana_metrics.query_prometheus")
    def test_connectivity_check_redacts_tokens_from_auth_errors(
        self,
        query,
        load_config,
    ):
        load_config.return_value = self.config
        exposed_token = "glc_" + "a" * 48
        query.side_effect = GrafanaPrometheusError(
            f"Authentication failed using {exposed_token}"
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = test_grafana_metrics.main()

        self.assertEqual(result, 1)
        self.assertNotIn(exposed_token, output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())

    def test_grafana_cloud_access_policy_token_is_redacted(self):
        exposed_token = "glc_" + "x" * 48
        self.assertNotIn(exposed_token, redact_sensitive_values(exposed_token))


if __name__ == "__main__":
    unittest.main()
