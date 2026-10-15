import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.remediate_incident import (
    ALLOWED_ACTION,
    ARTIFACT_REGISTRY_READER_ACTION,
    ARTIFACT_REGISTRY_READER_ROLE,
    ALLOWED_ACTIONS,
    RemediationValidationError,
    _live_incident_is_active,
    _pod_image_digests_match,
    _verify_application_health,
    _wait_for_rollout,
    _write_plan,
    execute_plan,
    validate_plan,
    verify_approval,
)

EXPECTED_IMAGE = "asia-south1-docker.pkg.dev/example/repo/demo:abc123"
NODE_SERVICE_ACCOUNT = "nodes@example.iam.gserviceaccount.com"


def valid_evidence():
    return {
        "version": 1,
        "evidence_run_id": "12345",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "incidents": [
            {
                "incident_id": "inc-1234567890abcdef",
                "namespace": "ai-troubleshooter",
                "workload": "ai-k8s-demo",
                "eligible_remediations": [ALLOWED_ACTION],
                "source_status": {"kubernetes": "available"},
                "analysis_mode": "rules-based fallback",
                "diagnosis": {"images": [EXPECTED_IMAGE]},
            }
        ],
    }


def valid_iam_evidence():
    evidence = valid_evidence()
    incident = evidence["incidents"][0]
    incident["category"] = "image_pull_failure"
    incident["eligible_remediations"] = [
        ARTIFACT_REGISTRY_READER_ACTION
    ]
    incident["diagnosis"] = {
        "images": [EXPECTED_IMAGE],
        "deployed_images": [EXPECTED_IMAGE],
        "image_digests": {},
        "registry_pull_error_status": 403,
        "root_cause": (
            "Kubernetes received an explicit registry authentication or "
            "authorization rejection."
        ),
        "artifact_registry": [
            {
                "image_uri": EXPECTED_IMAGE,
                "status": "available",
                "repository_exists": True,
                "tag_exists": True,
            }
        ],
    }
    return evidence


class RemediateIncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        json.dump(valid_evidence(), self.temp_file)
        self.temp_file.close()
        self.addCleanup(lambda: os.unlink(self.temp_file.name))

    def get_plan(self, action=ALLOWED_ACTION):
        return validate_plan(
            self.temp_file.name,
            "inc-1234567890abcdef",
            action,
            "12345",
        )[0]

    def get_iam_plan(self):
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(valid_iam_evidence(), evidence_file)
        with patch.dict(
            os.environ,
            {
                "PROJECT_ID": "example",
                "REGION": "asia-south1",
                "GAR_REPOSITORY": "repo",
                "CLUSTER_NAME": "example-cluster",
            },
            clear=True,
        ), patch(
            "scripts.remediate_incident._current_node_pool_identities",
            return_value=[
                {"pool": "pool-a", "service_account": NODE_SERVICE_ACCOUNT}
            ],
        ):
            return validate_plan(
                self.temp_file.name,
                "inc-1234567890abcdef",
                ARTIFACT_REGISTRY_READER_ACTION,
                "12345",
            )[0]

    def test_valid_plan_binds_evidence_action_and_target(self):
        plan = self.get_plan()

        self.assertEqual(plan["action"], "rollout_restart")
        self.assertEqual(plan["namespace"], "ai-troubleshooter")
        self.assertEqual(plan["target"], "ai-k8s-demo")
        self.assertEqual(plan["expected_images"], [EXPECTED_IMAGE])
        self.assertEqual(len(plan["approval_digest"]), 64)

    def test_rejects_arbitrary_shell_command_and_untrusted_action(self):
        with self.assertRaisesRegex(RemediationValidationError, "not allowlisted"):
            self.get_plan("kubectl delete pods --all")

    def test_workflow_operations_match_python_allowlist(self):
        workflow_path = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "kubernetes-remediation.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")
        operation_input = workflow.split("      operation:\n", 1)[1].split(
            "\npermissions:", 1
        )[0]
        options = re.search(
            r"\n        options:\n((?:          - [a-z_]+\n)+)",
            operation_input,
        )
        self.assertIsNotNone(options)
        workflow_operations = {
            value.strip()[2:]
            for value in options.group(1).splitlines()
        }
        self.assertEqual(workflow_operations, ALLOWED_ACTIONS)

    def test_evidence_run_id_must_match_selected_workflow_run(self):
        with self.assertRaisesRegex(RemediationValidationError, "run ID does not match"):
            validate_plan(
                self.temp_file.name,
                "inc-1234567890abcdef",
                ALLOWED_ACTION,
                "54321",
            )

        evidence = valid_evidence()
        del evidence["evidence_run_id"]
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(evidence, evidence_file)
        with self.assertRaisesRegex(RemediationValidationError, "run ID does not match"):
            validate_plan(
                self.temp_file.name,
                "inc-1234567890abcdef",
                ALLOWED_ACTION,
                "12345",
            )

    def test_rejects_missing_incident_and_stale_evidence(self):
        with self.assertRaisesRegex(RemediationValidationError, "not present"):
            validate_plan(self.temp_file.name, "inc-not-in-evidence", ALLOWED_ACTION, "12345")

        data = valid_evidence()
        data["observed_at"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(data, evidence_file)
        with self.assertRaisesRegex(RemediationValidationError, "stale"):
            self.get_plan()

    def test_rejects_unavailable_required_evidence(self):
        data = valid_evidence()
        data["incidents"][0]["source_status"]["kubernetes"] = "unavailable"
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(data, evidence_file)
        with self.assertRaisesRegex(RemediationValidationError, "unavailable"):
            self.get_plan()

    def test_missing_approval_blocks_before_any_cluster_api_call(self):
        apps_api = Mock()
        core_api = Mock()
        with patch.dict(
            os.environ,
            {"GITHUB_ACTIONS": "true"},
            clear=True,
        ):
            with self.assertRaisesRegex(RemediationValidationError, "post-approval"):
                execute_plan(
                    self.get_plan(),
                    "0" * 64,
                    live_incident_check=Mock(),
                    apps_api=apps_api,
                    core_api=core_api,
                )
        apps_api.patch_namespaced_deployment.assert_not_called()
        core_api.connect_get_namespaced_service_proxy_with_path.assert_not_called()

    def test_mismatched_approval_digest_is_rejected(self):
        plan = self.get_plan()
        with self.assertRaisesRegex(RemediationValidationError, "does not match"):
            verify_approval(plan, "0" * 64)

    def test_reader_grant_plan_binds_repository_and_verified_node_identity(self):
        plan = self.get_iam_plan()

        self.assertEqual(plan["action"], ARTIFACT_REGISTRY_READER_ACTION)
        self.assertEqual(
            plan["iam_target"]["resource"],
            "projects/example/locations/asia-south1/repositories/repo",
        )
        self.assertEqual(
            plan["parameters"]["role"],
            ARTIFACT_REGISTRY_READER_ROLE,
        )
        self.assertEqual(
            plan["parameters"]["node_pool_service_accounts"],
            [{"pool": "pool-a", "service_account": NODE_SERVICE_ACCOUNT}],
        )
        self.assertEqual(
            plan["operation_target"],
            "projects/example/locations/asia-south1/repositories/repo",
        )
        self.assertEqual(plan["evidence_run_id"], "12345")
        self.assertEqual(plan["proposal"]["incident_id"], plan["incident_id"])
        self.assertTrue(plan["proposal"]["human_approval_required"])
        self.assertTrue(verify_approval(plan, plan["approval_digest"]))

    def test_human_plan_displays_exact_evidence_and_verification_criteria(self):
        plan = self.get_iam_plan()
        summary_path = self.temp_file.name + ".summary"
        self.addCleanup(
            lambda: os.path.exists(summary_path) and os.unlink(summary_path)
        )

        _write_plan(plan, valid_iam_evidence(), summary_path=summary_path)

        with open(summary_path, encoding="utf-8") as summary:
            content = summary.read()
        self.assertIn("Evidence SHA-256:", content)
        self.assertIn("Evidence confidence:", content)
        self.assertIn("Node-pool service accounts:", content)
        self.assertIn(NODE_SERVICE_ACCOUNT, content)
        self.assertIn("Human approval required: **yes**", content)
        self.assertIn("Post-change verification:", content)

    @patch("collectors.evidence_collector.build_observability_evidence")
    @patch("ai.sre_agent.detect_incidents")
    def test_live_iam_eligibility_ignores_stale_replicaset_digests(
        self,
        detect_incidents_mock,
        build_evidence,
    ):
        old_image = "asia-south1-docker.pkg.dev/example/repo/demo:old"
        expected_digest = "sha256:" + ("a" * 64)
        build_evidence.return_value = {
            "github_actions": {},
            "deployments": [
                {
                    "namespace": "ai-troubleshooter",
                    "name": "ai-k8s-demo",
                    "images": [EXPECTED_IMAGE],
                }
            ],
        }
        detect_incidents_mock.return_value = [
            SimpleNamespace(
                incident_id="inc-1234567890abcdef",
                eligible_remediations=[ARTIFACT_REGISTRY_READER_ACTION],
                diagnosis={
                    "image_digests": {
                        EXPECTED_IMAGE: expected_digest,
                        old_image: "sha256:" + ("b" * 64),
                    }
                },
            )
        ]

        self.assertTrue(
            _live_incident_is_active(
                "inc-1234567890abcdef",
                [EXPECTED_IMAGE],
                {EXPECTED_IMAGE: expected_digest},
                ARTIFACT_REGISTRY_READER_ACTION,
            )
        )

    def test_reader_grant_rejects_ineligible_or_missing_registry_evidence(self):
        evidence = valid_iam_evidence()
        evidence["incidents"][0]["diagnosis"]["registry_pull_error_status"] = 401
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(evidence, evidence_file)
        with self.assertRaisesRegex(RemediationValidationError, "confirmed HTTP 403"):
            validate_plan(
                self.temp_file.name,
                "inc-1234567890abcdef",
                ARTIFACT_REGISTRY_READER_ACTION,
                "12345",
            )

        evidence = valid_iam_evidence()
        evidence["incidents"][0]["diagnosis"]["artifact_registry"][0][
            "tag_exists"
        ] = False
        with open(self.temp_file.name, "w", encoding="utf-8") as evidence_file:
            json.dump(evidence, evidence_file)
        with self.assertRaisesRegex(RemediationValidationError, "tag must be confirmed"):
            validate_plan(
                self.temp_file.name,
                "inc-1234567890abcdef",
                ARTIFACT_REGISTRY_READER_ACTION,
                "12345",
            )

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true"},
        clear=True,
    )
    @patch("collectors.artifact_registry_iam.add_repository_reader")
    def test_reader_grant_is_blocked_without_environment_approval(self, add_reader):
        plan = self.get_iam_plan()
        with self.assertRaisesRegex(RemediationValidationError, "post-approval"):
            execute_plan(
                plan,
                plan["approval_digest"],
                live_incident_check=Mock(),
                apps_api=Mock(),
                core_api=Mock(),
            )
        add_reader.assert_not_called()

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "REMEDIATION_APPROVAL_GRANTED": "true",
            "PROJECT_ID": "example",
            "REGION": "asia-south1",
            "GAR_REPOSITORY": "repo",
            "CLUSTER_NAME": "example-cluster",
        },
        clear=True,
    )
    @patch("scripts.remediate_incident._collect_post_change_grafana", return_value={
        "grafana_metrics": "unavailable",
        "grafana_observations": [],
    })
    @patch("scripts.remediate_incident._verify_application_health", return_value=True)
    @patch("scripts.remediate_incident._wait_for_rollout", return_value={
        "ready_replicas": 2,
        "images": [EXPECTED_IMAGE],
        "image_digests": {},
        "image_ids": ["containerd://sha256:" + ("d" * 64)],
    })
    @patch("scripts.remediate_incident._current_node_pool_identities")
    @patch("collectors.artifact_registry_iam.add_repository_reader")
    @patch("collectors.artifact_registry_iam.get_repository_policy")
    def test_approved_reader_grant_updates_exact_repository_then_verifies_rollout(
        self,
        get_policy,
        add_reader,
        current_identities,
        wait_for_rollout,
        _verify_health,
        _grafana,
    ):
        current_identities.return_value = [
            {"pool": "pool-a", "service_account": NODE_SERVICE_ACCOUNT}
        ]
        member = f"serviceAccount:{NODE_SERVICE_ACCOUNT}"
        get_policy.side_effect = [
            {"bindings": []},
            {"bindings": [{"role": ARTIFACT_REGISTRY_READER_ROLE, "members": [member]}]},
        ]
        apps_api = Mock()
        core_api = Mock()
        plan = self.get_iam_plan()

        result = execute_plan(
            plan,
            plan["approval_digest"],
            live_incident_check=lambda incident_id: True,
            apps_api=apps_api,
            core_api=core_api,
        )

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["ready_replicas"], 2)
        self.assertEqual(result["granted_members"], [member])
        add_reader.assert_called_once_with("example", "asia-south1", "repo", member)
        wait_for_rollout.assert_called_once()
        self.assertEqual(
            wait_for_rollout.call_args.kwargs["timeout_seconds"],
            360,
        )
        apps_api.patch_namespaced_deployment.assert_not_called()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "REMEDIATION_APPROVAL_GRANTED": "true"},
        clear=True,
    )
    def test_incident_must_still_be_active_after_approval(self):
        apps_api = Mock()
        core_api = Mock()
        with self.assertRaisesRegex(RemediationValidationError, "no longer active"):
            execute_plan(
                self.get_plan(),
                self.get_plan()["approval_digest"],
                live_incident_check=lambda incident_id: False,
                apps_api=apps_api,
                core_api=core_api,
            )
        apps_api.patch_namespaced_deployment.assert_not_called()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "REMEDIATION_APPROVAL_GRANTED": "true"},
        clear=True,
    )
    @patch("collectors.grafana_metrics_collector.collect_grafana_metrics")
    @patch("collectors.kubernetes_collector.get_pods", return_value=[])
    def test_approved_operation_patches_only_restart_annotation_and_verifies(
        self,
        _get_pods,
        collect_metrics,
    ):
        deployment = Mock()
        deployment.status.observed_generation = 4
        deployment.status.updated_replicas = 1
        deployment.status.available_replicas = 1
        deployment.status.unavailable_replicas = 0
        deployment.spec.replicas = 1
        deployment.spec.template.spec.containers = [Mock(image=EXPECTED_IMAGE)]
        deployment.metadata.generation = 4
        pod = Mock()
        pod.status.conditions = [Mock(type="Ready", status="True")]
        pod.spec.containers = [Mock(image=EXPECTED_IMAGE)]
        pod.status.container_statuses = [
            Mock(ready=True, image_id="containerd://sha256:abc")
        ]
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = deployment
        core_api = Mock()
        core_api.list_namespaced_pod.return_value.items = [pod]
        core_api.connect_get_namespaced_service_proxy_with_path.return_value = (
            '{"status":"healthy"}'
        )
        collect_metrics.return_value = {
            "cluster_metrics": [
                {
                    "metric": "application.error_rate",
                    "value": 0,
                    "scope": "cluster",
                    "status": "available",
                    "observed_at": "now",
                }
            ]
        }

        result = execute_plan(
            self.get_plan(),
            self.get_plan()["approval_digest"],
            live_incident_check=lambda incident_id: True,
            apps_api=apps_api,
            core_api=core_api,
        )

        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["verified_images"], [EXPECTED_IMAGE])
        self.assertEqual(result["image_ids"], ["containerd://sha256:abc"])
        apps_api.patch_namespaced_deployment.assert_called_once()
        self.assertEqual(
            apps_api.patch_namespaced_deployment.call_args.kwargs["body"].keys(),
            {"spec"},
        )
        self.assertEqual(result["grafana_metrics"], "available")
        self.assertEqual(
            result["grafana_observations"][0]["metric"],
            "application.error_rate",
        )
        core_api.connect_get_namespaced_service_proxy_with_path.assert_called_once()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "REMEDIATION_APPROVAL_GRANTED": "true"},
        clear=True,
    )
    @patch("scripts.remediate_incident._fresh_failure_diagnosis")
    @patch(
        "scripts.remediate_incident._wait_for_rollout",
        side_effect=RemediationValidationError("Deployment rollout timed out."),
    )
    def test_failed_verification_collects_fresh_evidence_without_retrying_action(
        self,
        _wait_for_rollout_mock,
        fresh_diagnosis,
    ):
        fresh_diagnosis.return_value = (
            "Fresh evidence: the image is still unavailable."
        )
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = Mock()
        core_api = Mock()

        with self.assertRaisesRegex(
            RemediationValidationError,
            "Fresh evidence: the image is still unavailable",
        ):
            execute_plan(
                self.get_plan(),
                self.get_plan()["approval_digest"],
                live_incident_check=lambda incident_id: True,
                apps_api=apps_api,
                core_api=core_api,
            )

        apps_api.patch_namespaced_deployment.assert_called_once()
        fresh_diagnosis.assert_called_once_with("inc-1234567890abcdef")
        _wait_for_rollout_mock.assert_called_once()

    def test_rollout_verification_checks_expected_image_digest(self):
        expected_digest = "sha256:" + ("a" * 64)
        pod = Mock()
        container = Mock()
        container.name = "app"
        container.image = EXPECTED_IMAGE
        status = Mock()
        status.name = "app"
        status.image_id = "containerd://" + expected_digest
        pod.spec.containers = [container]
        pod.status.container_statuses = [status]

        self.assertTrue(
            _pod_image_digests_match(
                pod,
                {EXPECTED_IMAGE: expected_digest},
            )
        )
        status.image_id = (
            "containerd://sha256:" + ("b" * 64)
        )
        self.assertFalse(
            _pod_image_digests_match(
                pod,
                {EXPECTED_IMAGE: expected_digest},
            )
        )

    def test_rollout_verification_requires_ready_replicas(self):
        deployment = Mock()
        deployment.status.observed_generation = 4
        deployment.status.updated_replicas = 2
        deployment.status.available_replicas = 2
        deployment.status.unavailable_replicas = 0
        deployment.spec.replicas = 2
        deployment.spec.template.spec.containers = [Mock(image=EXPECTED_IMAGE)]
        deployment.metadata.generation = 4
        pod = Mock()
        pod.status.conditions = [Mock(type="Ready", status="True")]
        pod.spec.containers = [Mock(image=EXPECTED_IMAGE)]
        pod.status.container_statuses = [
            Mock(ready=True, image_id="containerd://sha256:abc")
        ]
        core_api = Mock()
        core_api.list_namespaced_pod.return_value.items = [pod, pod]
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = deployment

        self.assertEqual(
            _wait_for_rollout(apps_api, core_api, [EXPECTED_IMAGE]),
            {
                "ready_replicas": 2,
                "images": [EXPECTED_IMAGE],
                "image_digests": {},
                "image_ids": ["containerd://sha256:abc"],
            },
        )

    def test_application_health_verification_requires_healthy_response(self):
        core_api = Mock()
        core_api.connect_get_namespaced_service_proxy_with_path.return_value = (
            '{"status":"healthy"}'
        )
        self.assertTrue(_verify_application_health(core_api))
        core_api.connect_get_namespaced_service_proxy_with_path.return_value = (
            '{"status":"unhealthy"}'
        )
        with self.assertRaisesRegex(RemediationValidationError, "did not report healthy"):
            _verify_application_health(core_api)


if __name__ == "__main__":
    unittest.main()
