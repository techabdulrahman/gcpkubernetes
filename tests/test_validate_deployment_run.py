import unittest
from datetime import datetime, timedelta, timezone

from scripts.validate_deployment_run import validate_deployment_run


NOW = datetime(2026, 10, 16, 9, 10, tzinfo=timezone.utc)
EXPECTED_REPOSITORY = "techabdulrahman/gcpkubernetes"
RUN_ID = 38883830171


def valid_runs():
    source = {
        "id": RUN_ID,
        "repository": {"full_name": EXPECTED_REPOSITORY},
        "head_repository": {"full_name": EXPECTED_REPOSITORY},
        "head_branch": "master",
        "event": "push",
        "status": "completed",
        "conclusion": "failure",
    }
    api_run = {
        **source,
        "path": ".github/workflows/deploy.yml@refs/heads/master",
        "created_at": (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
    }
    return source, api_run


class DeploymentRunValidationTests(unittest.TestCase):
    def validate(self, source, api_run):
        return validate_deployment_run(
            source,
            api_run,
            EXPECTED_REPOSITORY,
            now=NOW,
        )

    def test_exact_recent_failed_master_deployment_is_accepted(self):
        source, api_run = valid_runs()
        failures, _ = self.validate(source, api_run)
        self.assertEqual(failures, [])

    def test_api_path_without_ref_is_accepted(self):
        source, api_run = valid_runs()
        api_run["path"] = ".github/workflows/deploy.yml"
        failures, _ = self.validate(source, api_run)
        self.assertEqual(failures, [])

    def test_wrong_workflow_path_or_ref_is_rejected(self):
        for path in (
            ".github/workflows/other.yml@refs/heads/master",
            ".github/workflows/deploy.yml@refs/heads/untrusted",
        ):
            with self.subTest(path=path):
                source, api_run = valid_runs()
                api_run["path"] = path
                failures, _ = self.validate(source, api_run)
                self.assertIn("api_run.path", failures)

    def test_wrong_repository_or_branch_is_rejected(self):
        for field in ("repository", "head_repository"):
            source, api_run = valid_runs()
            source[field] = {"full_name": "untrusted/example"}
            failures, _ = self.validate(source, api_run)
            self.assertIn(f"source.{field}", failures)

            source, api_run = valid_runs()
            api_run[field] = {"full_name": "untrusted/example"}
            failures, _ = self.validate(source, api_run)
            self.assertIn(f"api_run.{field}", failures)

        source, api_run = valid_runs()
        source["head_branch"] = "feature/untrusted"
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.head_branch", failures)

        source, api_run = valid_runs()
        api_run["head_branch"] = "feature/untrusted"
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.head_branch", failures)

    def test_wrong_event_status_or_conclusion_is_rejected(self):
        for field, value in (
            ("event", "workflow_dispatch"),
            ("status", "in_progress"),
            ("conclusion", "success"),
            ("event", {"unexpected": "object"}),
        ):
            source, api_run = valid_runs()
            source[field] = value
            failures, _ = self.validate(source, api_run)
            self.assertIn(f"source.{field}", failures)

            source, api_run = valid_runs()
            api_run[field] = value
            failures, _ = self.validate(source, api_run)
            self.assertIn(f"api_run.{field}", failures)

    def test_missing_metadata_and_mismatched_run_id_are_rejected(self):
        source, api_run = valid_runs()
        del source["head_repository"]
        del api_run["path"]
        del api_run["created_at"]
        api_run["id"] += 1
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.head_repository", failures)
        self.assertIn("api_run.path", failures)
        self.assertIn("api_run.created_at", failures)
        self.assertIn("api_run.age", failures)
        self.assertIn("api_run.id", failures)

    def test_invalid_timezone_free_and_expired_timestamps_are_rejected(self):
        for timestamp in (
            "not-a-timestamp",
            "2026-10-16T09:00:00",
            (NOW - timedelta(minutes=30, seconds=1)).isoformat(),
        ):
            with self.subTest(timestamp=timestamp):
                source, api_run = valid_runs()
                api_run["created_at"] = timestamp
                failures, _ = self.validate(source, api_run)
                self.assertIn("api_run.age", failures)


if __name__ == "__main__":
    unittest.main()
