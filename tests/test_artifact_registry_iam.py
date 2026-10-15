import unittest
from unittest.mock import Mock, patch

from collectors.artifact_registry_iam import (
    READER_ROLE,
    add_repository_reader,
    get_repository_policy,
    has_unconditional_reader,
)


MEMBER = "serviceAccount:nodes@example.iam.gserviceaccount.com"


class ArtifactRegistryIAMTests(unittest.TestCase):
    @patch("collectors.artifact_registry_iam._run_gcloud")
    def test_reads_repository_policy_read_only(self, run_gcloud):
        run_gcloud.return_value = '{"bindings": []}'

        policy = get_repository_policy("example-project", "asia-south1", "repo")

        self.assertEqual(policy, {"bindings": []})
        self.assertEqual(
            run_gcloud.call_args.args[0][:4],
            ["artifacts", "repositories", "get-iam-policy", "repo"],
        )

    def test_unconditional_reader_is_distinguished_from_conditional_binding(self):
        self.assertFalse(
            has_unconditional_reader(
                {
                    "bindings": [
                        {
                            "role": READER_ROLE,
                            "members": [MEMBER],
                            "condition": {"title": "temporary"},
                        }
                    ]
                },
                MEMBER,
            )
        )
        self.assertTrue(
            has_unconditional_reader(
                {"bindings": [{"role": READER_ROLE, "members": [MEMBER]}]},
                MEMBER,
            )
        )
        self.assertFalse(
            has_unconditional_reader(
                {
                    "bindings": [
                        {"role": READER_ROLE, "members": None},
                        {"role": READER_ROLE, "members": MEMBER},
                    ]
                },
                MEMBER,
            )
        )

    @patch("collectors.artifact_registry_iam._run_gcloud")
    def test_adds_only_the_exact_repository_reader_binding(self, run_gcloud):
        add_repository_reader("example-project", "asia-south1", "repo", MEMBER)

        run_gcloud.assert_called_once_with([
            "artifacts",
            "repositories",
            "add-iam-policy-binding",
            "repo",
            "--project=example-project",
            "--location=asia-south1",
            f"--member={MEMBER}",
            f"--role={READER_ROLE}",
            "--quiet",
        ])

    def test_rejects_invalid_member_before_calling_gcloud(self):
        run_gcloud = Mock()
        with patch("collectors.artifact_registry_iam._run_gcloud", run_gcloud):
            with self.assertRaisesRegex(RuntimeError, "member is invalid"):
                add_repository_reader(
                    "example-project",
                    "asia-south1",
                    "repo",
                    "allUsers",
                )
        run_gcloud.assert_not_called()


if __name__ == "__main__":
    unittest.main()
