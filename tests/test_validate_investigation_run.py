import unittest
from datetime import datetime, timedelta, timezone

from scripts.validate_investigation_run import validate_investigation_run


NOW = datetime(2026, 10, 16, 9, 10, tzinfo=timezone.utc)
EXPECTED_REPOSITORY = "techabdulrahman/gcpkubernetes"
RUN_ID = 38862707972
DEFAULT_CREATED_AT = object()


def valid_runs(event="workflow_dispatch", created_at=DEFAULT_CREATED_AT):
    if created_at is DEFAULT_CREATED_AT:
        created_at = (NOW - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    source = {
        "id": RUN_ID,
        "repository": {"full_name": EXPECTED_REPOSITORY},
        "head_repository": {"full_name": EXPECTED_REPOSITORY},
        "head_branch": "master",
        "event": event,
        "status": "completed",
        "conclusion": "success",
    }
    api_run = {
        **source,
        "path": ".github/workflows/kubernetes-investigation.yml@refs/heads/master",
        "created_at": created_at,
    }
    return source, api_run


class InvestigationRunValidationTests(unittest.TestCase):
    def validate(self, source, api_run):
        return validate_investigation_run(
            source,
            api_run,
            EXPECTED_REPOSITORY,
            now=NOW,
        )

    def test_successful_schedule_and_dispatch_runs_are_accepted(self):
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                source, api_run = valid_runs(event)
                failures, _ = self.validate(source, api_run)
                self.assertEqual(failures, [])

    def test_expected_workflow_path_accepts_api_ref_suffix_or_no_suffix(self):
        source, api_run = valid_runs()
        api_run["path"] = ".github/workflows/kubernetes-investigation.yml"
        failures, _ = self.validate(source, api_run)
        self.assertEqual(failures, [])

    def test_wrong_workflow_path_or_workflow_ref_is_rejected(self):
        for path in (
            ".github/workflows/another-workflow.yml@refs/heads/master",
            ".github/workflows/kubernetes-investigation.yml@refs/heads/untrusted",
        ):
            with self.subTest(path=path):
                source, api_run = valid_runs()
                api_run["path"] = path
                failures, _ = self.validate(source, api_run)
                self.assertIn("api_run.path", failures)

    def test_wrong_repository_or_head_repository_is_rejected(self):
        cases = (
            ("source.repository", "source", "repository"),
            ("source.head_repository", "source", "head_repository"),
            ("api_run.repository", "api_run", "repository"),
            ("api_run.head_repository", "api_run", "head_repository"),
        )
        for expected_failure, run_name, field in cases:
            with self.subTest(field=field, run=run_name):
                source, api_run = valid_runs()
                selected = source if run_name == "source" else api_run
                selected[field] = {"full_name": "untrusted/example"}
                failures, _ = self.validate(source, api_run)
                self.assertIn(expected_failure, failures)

    def test_wrong_branch_is_rejected(self):
        source, api_run = valid_runs()
        source["head_branch"] = "feature/untrusted"
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.head_branch", failures)

        source, api_run = valid_runs()
        api_run["head_branch"] = "feature/untrusted"
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.head_branch", failures)

    def test_failed_conclusion_is_rejected(self):
        source, api_run = valid_runs()
        api_run["conclusion"] = "failure"
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.conclusion", failures)

        source, api_run = valid_runs()
        source["conclusion"] = "failure"
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.conclusion", failures)

    def test_non_completed_status_is_rejected(self):
        source, api_run = valid_runs()
        source["status"] = "in_progress"
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.status", failures)

        source, api_run = valid_runs()
        api_run["status"] = "in_progress"
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.status", failures)

    def test_disallowed_or_mismatched_event_is_rejected(self):
        source, api_run = valid_runs()
        source["event"] = "push"
        api_run["event"] = "push"
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.event", failures)
        self.assertIn("api_run.event", failures)

        source, api_run = valid_runs()
        api_run["event"] = "schedule"
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.event_matches_source", failures)

    def test_missing_run_metadata_is_rejected(self):
        source, api_run = valid_runs()
        del source["head_repository"]
        del api_run["path"]
        del api_run["created_at"]
        failures, _ = self.validate(source, api_run)
        self.assertIn("source.head_repository", failures)
        self.assertIn("api_run.path", failures)
        self.assertIn("api_run.created_at", failures)
        self.assertIn("api_run.age", failures)

    def test_invalid_and_timezone_free_timestamps_are_rejected(self):
        for timestamp in ("not-a-timestamp", "2026-10-16T09:00:00", None):
            with self.subTest(timestamp=timestamp):
                source, api_run = valid_runs(created_at=timestamp)
                failures, _ = self.validate(source, api_run)
                self.assertIn("api_run.created_at", failures)
                self.assertIn("api_run.age", failures)

    def test_expired_and_future_dated_runs_are_rejected(self):
        expired = (NOW - timedelta(minutes=30, seconds=1)).isoformat()
        future = (NOW + timedelta(seconds=1)).isoformat()
        for timestamp in (expired, future):
            with self.subTest(timestamp=timestamp):
                source, api_run = valid_runs(created_at=timestamp)
                failures, metadata = self.validate(source, api_run)
                self.assertIn("api_run.age", failures)
                self.assertIsNotNone(metadata["age_seconds"])

    def test_queued_run_failure_is_only_the_freshness_predicate(self):
        validation_time = datetime(2026, 10, 16, 9, 6, 24, tzinfo=timezone.utc)
        source, api_run = valid_runs(
            created_at="2026-10-16T06:42:13Z",
        )
        failures, metadata = validate_investigation_run(
            source,
            api_run,
            EXPECTED_REPOSITORY,
            now=validation_time,
        )
        self.assertEqual(failures, ["api_run.age"])
        self.assertEqual(metadata["age_seconds"], 2 * 60 * 60 + 24 * 60 + 11)

    def test_run_at_exact_maximum_age_is_accepted(self):
        timestamp = (NOW - timedelta(minutes=30)).isoformat()
        source, api_run = valid_runs(created_at=timestamp)
        failures, _ = self.validate(source, api_run)
        self.assertEqual(failures, [])

    def test_api_run_id_must_match_source_run_id(self):
        source, api_run = valid_runs()
        api_run["id"] += 1
        failures, _ = self.validate(source, api_run)
        self.assertIn("api_run.id", failures)


if __name__ == "__main__":
    unittest.main()
