import json
import subprocess
import unittest
from unittest.mock import patch

from collectors.artifact_registry_collector import collect_image_evidence


IMAGE = (
    "asia-south1-docker.pkg.dev/abdulproject-510307/"
    "ai-k8s-repo/ai-k8s-demo:0bc79c5864a94ac2a72b80c11e90804810a1c46f"
)
DIGEST = "sha256:" + ("a" * 64)


class ArtifactRegistryCollectorTests(unittest.TestCase):
    @patch("collectors.artifact_registry_collector.subprocess.run")
    def test_exact_tag_and_digest_are_reported(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"name":"ai-k8s-repo"}', ""),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps([
                    {
                        "uri": IMAGE.rsplit(":", 1)[0] + "@" + DIGEST,
                        "tags": [IMAGE.rsplit(":", 1)[1]],
                        "version": DIGEST,
                    }
                ]),
                "",
            ),
        ]

        result = collect_image_evidence(IMAGE)

        self.assertEqual(result["status"], "available")
        self.assertTrue(result["repository_exists"])
        self.assertTrue(result["image_exists"])
        self.assertTrue(result["tag_exists"])
        self.assertEqual(result["digest"], DIGEST)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("collectors.artifact_registry_collector.subprocess.run")
    def test_missing_repository_is_distinguished_from_api_denial(self, run):
        run.return_value = subprocess.CompletedProcess(
            [],
            1,
            "",
            "NOT_FOUND: repository does not exist",
        )

        result = collect_image_evidence(IMAGE)

        self.assertEqual(result["status"], "available")
        self.assertFalse(result["repository_exists"])
        self.assertFalse(result["tag_exists"])
        run.assert_called_once()

    @patch("collectors.artifact_registry_collector.subprocess.run")
    def test_existing_repository_with_missing_tag_is_explicit(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"name":"ai-k8s-repo"}', ""),
            subprocess.CompletedProcess([], 0, "[]", ""),
        ]

        result = collect_image_evidence(IMAGE)

        self.assertTrue(result["repository_exists"])
        self.assertFalse(result["image_exists"])
        self.assertFalse(result["tag_exists"])

    @patch("collectors.artifact_registry_collector.subprocess.run")
    def test_permission_error_and_timeout_remain_unavailable(self, run):
        run.return_value = subprocess.CompletedProcess(
            [],
            1,
            "",
            "PERMISSION_DENIED",
        )
        denied = collect_image_evidence(IMAGE)
        self.assertEqual(denied["status"], "unavailable")
        self.assertIsNone(denied["repository_exists"])

        run.side_effect = subprocess.TimeoutExpired("gcloud", 20)
        timed_out = collect_image_evidence(IMAGE)
        self.assertEqual(timed_out["status"], "unavailable")
        self.assertIn("timeout", timed_out["diagnostic"])

    @patch("collectors.artifact_registry_collector.subprocess.run")
    def test_digest_only_image_reference_is_supported(self, run):
        uri = IMAGE.rsplit(":", 1)[0] + "@" + DIGEST
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '{"name":"ai-k8s-repo"}', ""),
            subprocess.CompletedProcess(
                [],
                0,
                json.dumps([{"uri": uri, "tags": [], "version": DIGEST}]),
                "",
            ),
        ]

        result = collect_image_evidence(uri)

        self.assertTrue(result["tag_exists"])
        self.assertEqual(result["digest"], DIGEST)


if __name__ == "__main__":
    unittest.main()
