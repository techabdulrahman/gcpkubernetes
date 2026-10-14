import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from kubernetes.client.rest import ApiException

from collectors.kubernetes_collector import get_deployments, get_pods


class KubernetesCollectorTests(unittest.TestCase):
    @patch("collectors.kubernetes_collector.client.CoreV1Api")
    def test_pod_workload_prefers_app_label_over_replicaset_owner(self, core_api):
        pod = SimpleNamespace(
            metadata=SimpleNamespace(
                namespace="ai-troubleshooter",
                name="ai-k8s-demo-abc123-def45",
                labels={"app": "ai-k8s-demo"},
                owner_references=[
                    SimpleNamespace(kind="ReplicaSet", name="ai-k8s-demo-abc123")
                ],
            ),
            spec=SimpleNamespace(
                containers=[],
                node_name="node-a",
            ),
            status=SimpleNamespace(
                container_statuses=[],
                conditions=[],
                phase="Running",
            ),
        )
        core_api.return_value.list_namespaced_pod.return_value.items = [pod]

        result = get_pods("ai-troubleshooter")

        self.assertEqual(result[0]["workload"], "ai-k8s-demo")
        self.assertEqual(result[0]["workload_kind"], "ReplicaSet")

    @patch("collectors.kubernetes_collector.client.CoreV1Api")
    def test_pod_api_errors_are_surfaced_without_raw_server_details(self, core_api):
        core_api.return_value.list_namespaced_pod.side_effect = ApiException(
            status=403,
            reason="forbidden secret response body",
        )

        with self.assertRaisesRegex(RuntimeError, "Kubernetes HTTP 403") as raised:
            get_pods("ai-troubleshooter")

        self.assertNotIn("secret response body", str(raised.exception))

    @patch("collectors.kubernetes_collector.client.AppsV1Api")
    def test_deployment_rollout_fields_and_images_are_collected(self, apps_api):
        condition = SimpleNamespace(
            type="Progressing",
            status="False",
            reason="ProgressDeadlineExceeded",
            last_update_time=None,
        )
        container = SimpleNamespace(image="example/image:abc123")
        deployment = SimpleNamespace(
            metadata=SimpleNamespace(
                namespace="ai-troubleshooter",
                name="ai-k8s-demo",
                generation=3,
            ),
            status=SimpleNamespace(
                observed_generation=2,
                ready_replicas=1,
                available_replicas=1,
                unavailable_replicas=1,
                conditions=[condition],
            ),
            spec=SimpleNamespace(
                replicas=2,
                template=SimpleNamespace(
                    spec=SimpleNamespace(containers=[container])
                ),
            ),
        )
        apps_api.return_value.list_namespaced_deployment.return_value.items = [
            deployment
        ]

        result = get_deployments("ai-troubleshooter")

        self.assertEqual(result[0]["desired_replicas"], 2)
        self.assertEqual(result[0]["available_replicas"], 1)
        self.assertEqual(result[0]["images"], ["example/image:abc123"])
        self.assertEqual(result[0]["conditions"][0]["reason"], "ProgressDeadlineExceeded")

    @patch("collectors.kubernetes_collector.client.AppsV1Api")
    def test_deployment_api_errors_are_reported(self, apps_api):
        apps_api.return_value.list_namespaced_deployment.side_effect = ApiException(
            status=403
        )

        with self.assertRaisesRegex(RuntimeError, "Kubernetes HTTP 403"):
            get_deployments("ai-troubleshooter")


if __name__ == "__main__":
    unittest.main()
