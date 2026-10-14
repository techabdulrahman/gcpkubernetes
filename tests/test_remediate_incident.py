import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from scripts.remediate_incident import (
    ALLOWED_ACTION,
    RemediationValidationError,
    _verify_application_health,
    _wait_for_rollout,
    execute_plan,
    validate_plan,
    verify_approval,
)


def valid_evidence():
    return {
        "version": 1,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "incidents": [
            {
                "incident_id": "inc-1234567890abcdef",
                "namespace": "ai-troubleshooter",
                "workload": "ai-k8s-demo",
                "eligible_remediations": [ALLOWED_ACTION],
                "source_status": {"kubernetes": "available"},
                "analysis_mode": "rules-based fallback",
            }
        ],
    }


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

    def test_valid_plan_binds_evidence_action_and_target(self):
        plan = self.get_plan()

        self.assertEqual(plan["action"], "rollout_restart")
        self.assertEqual(plan["namespace"], "ai-troubleshooter")
        self.assertEqual(plan["target"], "ai-k8s-demo")
        self.assertEqual(len(plan["approval_digest"]), 64)

    def test_rejects_arbitrary_shell_command_and_untrusted_action(self):
        with self.assertRaisesRegex(RemediationValidationError, "not allowlisted"):
            self.get_plan("kubectl delete pods --all")

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
        deployment.metadata.generation = 4
        pod = Mock()
        pod.status.conditions = [Mock(type="Ready", status="True")]
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = deployment
        core_api = Mock()
        core_api.list_namespaced_pod.return_value.items = [pod]
        core_api.connect_get_namespaced_service_proxy_with_path.return_value = (
            '{"status":"healthy"}'
        )
        collect_metrics.return_value = {"cluster_metrics": []}

        result = execute_plan(
            self.get_plan(),
            self.get_plan()["approval_digest"],
            live_incident_check=lambda incident_id: True,
            apps_api=apps_api,
            core_api=core_api,
        )

        self.assertEqual(result["status"], "succeeded")
        apps_api.patch_namespaced_deployment.assert_called_once()
        self.assertEqual(
            apps_api.patch_namespaced_deployment.call_args.kwargs["body"].keys(),
            {"spec"},
        )
        self.assertEqual(result["grafana_metrics"], "unavailable")
        core_api.connect_get_namespaced_service_proxy_with_path.assert_called_once()

    def test_rollout_verification_requires_ready_replicas(self):
        deployment = Mock()
        deployment.status.observed_generation = 4
        deployment.status.updated_replicas = 2
        deployment.status.available_replicas = 2
        deployment.status.unavailable_replicas = 0
        deployment.spec.replicas = 2
        deployment.metadata.generation = 4
        pod = Mock()
        pod.status.conditions = [Mock(type="Ready", status="True")]
        core_api = Mock()
        core_api.list_namespaced_pod.return_value.items = [pod, pod]
        apps_api = Mock()
        apps_api.read_namespaced_deployment.return_value = deployment

        self.assertEqual(_wait_for_rollout(apps_api, core_api), 2)

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
