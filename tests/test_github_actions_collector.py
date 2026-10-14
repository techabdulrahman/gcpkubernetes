import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from collectors.github_actions_collector import collect_latest_deployment


class GitHubActionsCollectorTests(unittest.TestCase):
    @patch("collectors.github_actions_collector.urllib.request.build_opener")
    def test_latest_run_metadata_is_returned_with_repository_commit_and_branch(self, build_opener):
        recent = datetime.now(timezone.utc).isoformat()
        payload = {
            "workflow_runs": [
                {
                    "name": "Deploy AI Kubernetes Demo to GKE",
                    "id": 123,
                    "html_url": "https://github.com/example/repo/actions/runs/123",
                    "head_branch": "master",
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": recent,
                    "updated_at": recent,
                }
            ]
        }
        opener = build_opener.return_value
        opener.open.return_value.__enter__.return_value.read.return_value = (
            json.dumps(payload).encode("utf-8")
        )

        result = collect_latest_deployment("example/repo", "test-token")

        self.assertEqual(result["status"], "available")
        self.assertEqual(result["run"]["repository"], "example/repo")
        self.assertEqual(result["run"]["commit_sha"], "abc123")
        self.assertEqual(result["run"]["branch"], "master")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    @patch("collectors.github_actions_collector.urllib.request.build_opener")
    def test_stale_deployment_history_is_explicit(self, build_opener):
        stale = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        build_opener.return_value.open.return_value.__enter__.return_value.read.return_value = (
            json.dumps({"workflow_runs": [{"updated_at": stale}]}).encode("utf-8")
        )

        result = collect_latest_deployment("example/repo", "test-token")

        self.assertEqual(result["status"], "stale")
        self.assertIsNotNone(result["diagnostic"])

    def test_missing_read_credentials_fail_closed_without_request(self):
        with patch("collectors.github_actions_collector.urllib.request.build_opener") as build_opener:
            result = collect_latest_deployment("example/repo", "")

        self.assertEqual(result["status"], "unavailable")
        build_opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
