import unittest
from unittest.mock import Mock, patch

from collectors.gke_node_identity_collector import (
    GKENodeIdentityError,
    get_node_pool_service_accounts,
)


class GKENodeIdentityCollectorTests(unittest.TestCase):
    @patch("collectors.gke_node_identity_collector._run_gcloud")
    def test_returns_verified_distinct_node_pool_identities(self, run_gcloud):
        run_gcloud.return_value = [
            {
                "name": "pool-a",
                "config": {"serviceAccount": "nodes@example.iam.gserviceaccount.com"},
            },
            {
                "name": "pool-b",
                "config": {"serviceAccount": "nodes@example.iam.gserviceaccount.com"},
            },
        ]

        result = get_node_pool_service_accounts(
            "example-project",
            "asia-south1",
            "example-cluster",
        )

        self.assertEqual(result["status"], "available")
        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(run_gcloud.call_count, 1)

    @patch("collectors.gke_node_identity_collector._project_number", return_value="123456")
    @patch("collectors.gke_node_identity_collector._run_gcloud")
    def test_resolves_google_default_compute_service_account(
        self,
        run_gcloud,
        _project_number,
    ):
        run_gcloud.return_value = [
            {"name": "pool-a", "config": {"serviceAccount": "default"}}
        ]

        result = get_node_pool_service_accounts(
            "example-project",
            "asia-south1",
            "example-cluster",
        )

        self.assertEqual(
            result["items"][0]["service_account"],
            "123456-compute@developer.gserviceaccount.com",
        )

    @patch("collectors.gke_node_identity_collector._run_gcloud", return_value=[])
    def test_fails_closed_when_no_pools_are_returned(self, _run_gcloud):
        with self.assertRaisesRegex(GKENodeIdentityError, "no node pools"):
            get_node_pool_service_accounts(
                "example-project",
                "asia-south1",
                "example-cluster",
            )

    @patch("collectors.gke_node_identity_collector._run_gcloud")
    def test_rejects_unverifiable_service_account(self, run_gcloud):
        run_gcloud.return_value = [{"name": "pool-a", "config": {}}]
        with patch(
            "collectors.gke_node_identity_collector._project_number",
            side_effect=GKENodeIdentityError("project lookup denied"),
        ):
            with self.assertRaisesRegex(GKENodeIdentityError, "project lookup denied"):
                get_node_pool_service_accounts(
                    "example-project",
                    "asia-south1",
                    "example-cluster",
                )


if __name__ == "__main__":
    unittest.main()
