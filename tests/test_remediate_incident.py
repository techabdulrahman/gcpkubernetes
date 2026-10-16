import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.remediate_incident import (
    ALLOWED_ACTIONS,
    MAX_ROLLOUT_ATTEMPTS,
    ROLLOUT_TIMEOUT_SECONDS,
    RemediationValidationError,
    _plan_digest,
    _pod_image_digests_match,
    _wait_for_rollout,
    execute_plan,
    select_automatic_action,
    validate_plan,
)

EXPECTED_IMAGE = "asia-south1-docker.pkg.dev/example/repo/demo:abc123"
INCIDENT_ID = "inc-1234567890abcdef"
RUN_ID = "12345"
IMAGE_DIGEST = "sha256:" + "a" * 64


def valid_evidence():
    observed = datetime.now(timezone.utc).isoformat()
    return {
        "version": 1,
        "evidence_run_id": RUN_ID,
        "observed_at": observed,
        "deployments": [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo",
                "generation": 3,
                "observed_generation": 3,
                "desired_replicas": 2,
                "available_replicas": 1,
                "unavailable_replicas": 1,
                "images": [EXPECTED_IMAGE],
                "strategy_type": "RollingUpdate",
                "max_unavailable": "25%",
                "max_surge": "25%",
            }
        ],
        "pods": [
            {
                "namespace": "ai-troubleshooter",
                "workload": "ai-k8s-demo",
                "pod": "ai-k8s-demo-ready",
                "ready": True,
                "containers": [
                    {
                        "image": EXPECTED_IMAGE,
                        "image_id": "containerd://" + IMAGE_DIGEST,
                    }
                ],
            },
            {
                "namespace": "ai-troubleshooter",
                "workload": "ai-k8s-demo",
                "pod": "ai-k8s-demo-abc",
                "ready": False,
                "state_reasons": [],
                "containers": [],
                "events": ["[Warning] NodeNotReady: node is not ready"],
                "source_status": {"container_logs": "available"},
            }
        ],
        "cluster_metrics": [
            {
                "metric": "application.health_status",
                "value": 1,
                "status": "available",
                "observed_at": observed,
            },
            {
                "metric": "application.error_rate",
                "value": 0,
                "status": "available",
                "observed_at": observed,
            },
        ],
        "incidents": [
            {
                "incident_id": INCIDENT_ID,
                "category": "failed_rollout",
                "namespace": "ai-troubleshooter",
                "workload": "ai-k8s-demo",
                "eligible_remediations": ["rollout_restart"],
                "source_status": {
                    "kubernetes": "available",
                    "grafana": "available",
                },
                "analysis_mode": "rules-based fallback",
                "diagnosis": {
                    "images": [EXPECTED_IMAGE],
                    "deployed_images": [EXPECTED_IMAGE],
                    "image_digests": {EXPECTED_IMAGE: IMAGE_DIGEST},
                },
            }
        ],
    }


class RemediateIncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
        )
        json.dump(valid_evidence(), self.temp_file)
        self.temp_file.close()
        self.addCleanup(lambda: os.unlink(self.temp_file.name))

    def get_plan(self, action="rollout_restart"):
        return validate_plan(
            self.temp_file.name,
            INCIDENT_ID,
            action,
            RUN_ID,
        )[0]

    def write_evidence(self, evidence):
        with open(self.temp_file.name, "w", encoding="utf-8") as target:
            json.dump(evidence, target)

    def test_plan_binds_run_evidence_action_and_exact_target(self):
        plan = self.get_plan()
        self.assertEqual(plan["action"], "rollout_restart")
        self.assertEqual(plan["namespace"], "ai-troubleshooter")
        self.assertEqual(plan["target"], "ai-k8s-demo")
        self.assertEqual(plan["expected_images"], [EXPECTED_IMAGE])
        self.assertEqual(len(plan["evidence_sha256"]), 64)
        self.assertEqual(ALLOWED_ACTIONS, {"rollout_restart"})
        self.assertEqual(MAX_ROLLOUT_ATTEMPTS, 1)

    def test_rejects_unallowlisted_action_and_iam_operation(self):
        for action in ("kubectl delete pods --all", "grant_artifact_registry_reader"):
            with self.subTest(action=action):
                with self.assertRaisesRegex(
                    RemediationValidationError,
                    "not allowlisted",
                ):
                    self.get_plan(action)

    def test_evidence_run_must_match_source_workflow(self):
        with self.assertRaisesRegex(RemediationValidationError, "run ID does not match"):
            validate_plan(self.temp_file.name, INCIDENT_ID, "rollout_restart", "54321")

    def test_evidence_timestamp_and_incident_membership_are_required(self):
        with self.assertRaisesRegex(RemediationValidationError, "not present"):
            validate_plan(
                self.temp_file.name,
                "inc-aaaaaaaaaaaaaaaa",
                "rollout_restart",
                RUN_ID,
            )
        evidence = valid_evidence()
        evidence["observed_at"] = "not-a-timestamp"
        self.write_evidence(evidence)
        with self.assertRaisesRegex(RemediationValidationError, "valid timestamp"):
            self.get_plan()

    def test_uncertain_or_incomplete_evidence_is_report_only(self):
        mutations = [
            lambda data: data["incidents"][0]["source_status"].update(
                {"grafana": "unavailable"}
            ),
            lambda data: data["deployments"][0].update({"available_replicas": 0}),
            lambda data: data["deployments"][0].update({"strategy_type": "Recreate"}),
            lambda data: data["pods"][1]["events"].clear(),
            lambda data: data["pods"][1]["source_status"].update(
                {"container_logs": "unavailable"}
            ),
            lambda data: data["cluster_metrics"][0].update(
                {"observed_at": "2026-02-01T12:00:00"}
            ),
            lambda data: data["deployments"][0].update(
                {"max_unavailable": True}
            ),
        ]
        for mutate in mutations:
            evidence = valid_evidence()
            mutate(evidence)
            self.write_evidence(evidence)
            with self.assertRaisesRegex(
                RemediationValidationError,
                "automatic rollout-restart policy",
            ):
                self.get_plan()

    def test_rejects_crashes_probe_or_image_pull_conditions(self):
        for reason in ("CrashLoopBackOff", "ImagePullBackOff", "OOMKilled"):
            evidence = valid_evidence()
            evidence["pods"][1]["state_reasons"] = [reason]
            self.write_evidence(evidence)
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                    RemediationValidationError,
                    "automatic rollout-restart policy",
                ):
                    self.get_plan()

    def test_selects_only_one_policy_eligible_incident(self):
        selection = select_automatic_action(self.temp_file.name, RUN_ID)
        self.assertEqual(
            selection,
            {"incident_id": INCIDENT_ID, "action": "rollout_restart"},
        )
        evidence = valid_evidence()
        evidence["incidents"].append({
            **evidence["incidents"][0],
            "incident_id": "inc-abcdef1234567890",
        })
        self.write_evidence(evidence)
        self.assertIsNone(select_automatic_action(self.temp_file.name, RUN_ID))

    def test_workflow_handoff_uses_source_run_artifact_and_no_environment_gate(self):
        workflow_path = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "kubernetes-remediation.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")
        self.assertIn("workflow_run:", workflow)
        self.assertIn("github.event.workflow_run.id", workflow)
        self.assertIn("run.path", workflow)
        self.assertIn("run.status !== \"completed\"", workflow)
        self.assertIn("run.conclusion !== \"success\"", workflow)
        self.assertIn("run.head_branch !== \"master\"", workflow)
        self.assertIn("group: ai-sre-automatic-remediation", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes: 15", workflow)
        self.assertIn("ai-sre-remediation-attempt:", workflow)
        self.assertIn("createComment", workflow)
        self.assertIn("issues: read", workflow)
        self.assertIn("issues: write", workflow)
        self.assertNotIn("environment:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("inputs.evidence_run_id", workflow)
        self.assertEqual(ALLOWED_ACTIONS, {"rollout_restart"})

    def test_investigation_and_report_publisher_have_separate_permissions(self):
        workflow_path = (
            Path(__file__).resolve().parents[1]
            / ".github"
            / "workflows"
            / "kubernetes-investigation.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")
        investigator = workflow.split("  investigate:\n", 1)[1].split(
            "\n  publish:\n", 1
        )[0]
        publisher = workflow.split("  publish:\n", 1)[1]
        self.assertIn("id-token: write", investigator)
        self.assertNotIn("issues: write", investigator)
        self.assertIn("issues: write", publisher)
        self.assertIn("continue-on-error: true", publisher)

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "AUTO_REMEDIATION_SELECTED": "true"},
        clear=True,
    )
    @patch("scripts.remediate_incident._collect_post_action_events", return_value={
        "status": "available",
        "events": [],
        "blocking_warnings": [],
    })
    @patch("scripts.remediate_incident._collect_post_change_grafana", return_value={
        "grafana_metrics": "available",
        "grafana_observations": [
            {"metric": "application.health_status", "value": 1, "status": "available"}
        ],
    })
    @patch("scripts.remediate_incident._verify_application_health", return_value=True)
    @patch("scripts.remediate_incident._wait_for_rollout", return_value={
        "ready_replicas": 2,
        "images": [EXPECTED_IMAGE],
        "image_digests": {},
        "image_ids": ["containerd://sha256:abc"],
    })
    def test_executes_one_restart_then_verifies_rollout_health_events_and_grafana(
        self,
        _wait_for_rollout,
        _verify_health,
        _grafana,
        _events,
    ):
        plan = self.get_plan()
        apps_api = Mock()
        result = execute_plan(
            plan,
            _plan_digest(plan),
            live_incident_check=Mock(return_value=True),
            apps_api=apps_api,
            core_api=Mock(),
        )
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["ready_replicas"], 2)
        self.assertEqual(result["grafana_metrics"], "available")
        apps_api.patch_namespaced_deployment.assert_called_once()
        args = apps_api.patch_namespaced_deployment.call_args.kwargs
        self.assertEqual(args["name"], "ai-k8s-demo")
        self.assertEqual(args["namespace"], "ai-troubleshooter")
        self.assertEqual(
            set(args["body"]["spec"]["template"]["metadata"]["annotations"]),
            {"kubectl.kubernetes.io/restartedAt"},
        )
        _wait_for_rollout.assert_called_once()
        _verify_health.assert_called_once()
        _events.assert_called_once()
        _grafana.assert_called_once()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "AUTO_REMEDIATION_SELECTED": "true"},
        clear=True,
    )
    def test_digest_mismatch_and_missing_policy_authorization_block_mutation(self):
        plan = self.get_plan()
        apps_api = Mock()
        with self.assertRaisesRegex(RemediationValidationError, "digest"):
            execute_plan(
                plan,
                "0" * 64,
                live_incident_check=Mock(return_value=True),
                apps_api=apps_api,
                core_api=Mock(),
            )
        apps_api.patch_namespaced_deployment.assert_not_called()

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True)
    def test_policy_selection_is_required_before_any_cluster_change(self):
        apps_api = Mock()
        with self.assertRaisesRegex(RemediationValidationError, "policy-selected"):
            execute_plan(
                self.get_plan(),
                _plan_digest(self.get_plan()),
                live_incident_check=Mock(return_value=True),
                apps_api=apps_api,
                core_api=Mock(),
            )
        apps_api.patch_namespaced_deployment.assert_not_called()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "AUTO_REMEDIATION_SELECTED": "true"},
        clear=True,
    )
    def test_stale_live_incident_blocks_action(self):
        apps_api = Mock()
        with self.assertRaisesRegex(RemediationValidationError, "no longer active"):
            execute_plan(
                self.get_plan(),
                _plan_digest(self.get_plan()),
                live_incident_check=Mock(return_value=False),
                apps_api=apps_api,
                core_api=Mock(),
            )
        apps_api.patch_namespaced_deployment.assert_not_called()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "AUTO_REMEDIATION_SELECTED": "true"},
        clear=True,
    )
    @patch("scripts.remediate_incident._fresh_failure_diagnosis", return_value="Fresh evidence unavailable.")
    @patch(
        "scripts.remediate_incident._wait_for_rollout",
        side_effect=RemediationValidationError("Deployment rollout timed out."),
    )
    def test_failed_recovery_stops_after_one_patch_without_retry(
        self,
        wait_for_rollout,
        _fresh_diagnosis,
    ):
        apps_api = Mock()
        with self.assertRaisesRegex(RemediationValidationError, "stop and do not retry"):
            execute_plan(
                self.get_plan(),
                _plan_digest(self.get_plan()),
                live_incident_check=Mock(return_value=True),
                apps_api=apps_api,
                core_api=Mock(),
            )
        apps_api.patch_namespaced_deployment.assert_called_once()
        wait_for_rollout.assert_called_once()

    @patch.dict(
        os.environ,
        {"GITHUB_ACTIONS": "true", "AUTO_REMEDIATION_SELECTED": "true"},
        clear=True,
    )
    @patch("scripts.remediate_incident._fresh_failure_diagnosis", return_value="Inspect current events.")
    @patch("scripts.remediate_incident._collect_post_action_events", return_value={
        "status": "available",
        "events": [{"reason": "Unhealthy", "pod": "ai-k8s-demo-abc"}],
        "blocking_warnings": [{"reason": "Unhealthy"}],
    })
    @patch("scripts.remediate_incident._verify_application_health", return_value=True)
    @patch("scripts.remediate_incident._wait_for_rollout", return_value={
        "ready_replicas": 2,
        "images": [EXPECTED_IMAGE],
        "image_digests": {},
        "image_ids": ["containerd://sha256:abc"],
    })
    def test_post_action_warning_events_prevent_recovery_claim(
        self,
        _wait,
        _health,
        _events,
        _fresh,
    ):
        apps_api = Mock()
        with self.assertRaisesRegex(
            RemediationValidationError,
            "Post-action Kubernetes events still report",
        ):
            execute_plan(
                self.get_plan(),
                _plan_digest(self.get_plan()),
                live_incident_check=Mock(return_value=True),
                apps_api=apps_api,
                core_api=Mock(),
            )
        apps_api.patch_namespaced_deployment.assert_called_once()

    def test_rollout_verification_requires_ready_replicas_and_expected_image(self):
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
        core_api = Mock()
        core_api.list_namespaced_pod.return_value.items = [pod]
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = deployment
        result = _wait_for_rollout(
            apps_api,
            core_api,
            [EXPECTED_IMAGE],
            timeout_seconds=ROLLOUT_TIMEOUT_SECONDS,
        )
        self.assertEqual(result["ready_replicas"], 1)

    def test_runtime_image_digest_must_match_evidence(self):
        pod = Mock()
        container = Mock(image=EXPECTED_IMAGE)
        container.name = "app"
        status = Mock(image_id="containerd://sha256:" + "a" * 64)
        status.name = "app"
        pod.spec.containers = [container]
        pod.status.container_statuses = [status]
        expected = {EXPECTED_IMAGE: "sha256:" + "a" * 64}
        self.assertTrue(_pod_image_digests_match(pod, expected))
        expected[EXPECTED_IMAGE] = "sha256:" + "b" * 64
        self.assertFalse(_pod_image_digests_match(pod, expected))


if __name__ == "__main__":
    unittest.main()
