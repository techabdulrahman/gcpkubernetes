import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from ai.sre_agent import (
    ARTIFACT_REGISTRY_READER_REMEDIATION,
    build_remediation_proposal,
    detect_incidents,
)
from collectors.evidence_collector import build_observability_evidence
from models.evidence import IncidentEvidence


IMAGE = (
    "asia-south1-docker.pkg.dev/abdulproject-510307/"
    "ai-k8s-repo/ai-k8s-demo:" + ("a" * 40)
)


def image_pull_item(message="failed to pull and unpack image"):
    return IncidentEvidence(
        cluster="ai-k8s-cluster",
        namespace="ai-troubleshooter",
        workload="ai-k8s-demo",
        pod="ai-k8s-demo-abc123",
        status="Pending",
        ready=False,
        restarts=0,
        events=[],
        logs=[],
        images=[IMAGE],
        state_reasons=["ImagePullBackOff"],
        containers=[
            {
                "name": "app",
                "state": "waiting",
                "state_reason": "ImagePullBackOff",
                "state_message": message,
            }
        ],
        observed_at=datetime.now(timezone.utc).isoformat(),
        source_status={"kubernetes": "available", "grafana": "unavailable"},
    )


def incident_for(message, registry=None, github_run=None, diagnostics=None):
    bundle = {
        "cluster": "ai-k8s-cluster",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "items": [image_pull_item(message)],
        "deployments": [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo",
                "images": [IMAGE],
                "desired_replicas": 2,
                "available_replicas": 0,
            }
        ],
        "replicasets": [],
        "cluster_metrics": [],
        "artifact_registry": registry or [],
        "diagnostics": diagnostics or [],
        "github_actions": {
            "status": "available" if github_run else "unavailable",
            "run": github_run,
        },
    }
    incidents = detect_incidents(bundle)
    return next(item for item in incidents if item.category == "image_pull_failure")


class CrossSystemRCATests(unittest.TestCase):
    def test_registry_missing_tag_is_confirmed_without_grafana(self):
        incident = incident_for(
            "manifest unknown: tag not found",
            registry=[
                {
                    "image_uri": IMAGE,
                    "status": "available",
                    "repository_exists": True,
                    "image_exists": True,
                    "tag_exists": False,
                    "digest": None,
                    "repository_resource": "projects/p/locations/r/repositories/repo",
                }
            ],
            diagnostics=[
                "GRAFANA_CLUSTER did not match a supported label in returned Prometheus series."
            ],
        )

        self.assertIn("absent", incident.diagnosis["root_cause"])
        self.assertEqual(incident.diagnosis["confidence"], "high")
        self.assertEqual(incident.eligible_remediations, [])
        self.assertIn(
            "Grafana metrics are unavailable",
            " ".join(incident.diagnosis["missing_evidence"]),
        )

    def test_missing_image_proposal_requires_exact_verified_commit_and_run_uri(self):
        commit = "a" * 40
        run = {
            "run_id": 99,
            "commit_sha": commit,
            "image_uri": IMAGE,
            "image_push_status": "failed",
            "failed_steps": ["Build and deploy / Build and push Docker image"],
            "image_push_error_category": "network",
        }
        incident = incident_for(
            "manifest unknown: tag not found",
            registry=[
                {
                    "image_uri": IMAGE,
                    "status": "available",
                    "repository_exists": True,
                    "tag_exists": False,
                }
            ],
            github_run=run,
        )

        proposal = build_remediation_proposal(incident.to_dict(), "98765")

        self.assertEqual(proposal["incident_id"], incident.incident_id)
        self.assertEqual(proposal["evidence_run_id"], "98765")
        self.assertIsNone(proposal["proposed_action"]["operation"])
        self.assertFalse(
            proposal["proposed_action"]["executable_by_remediation_workflow"]
        )
        self.assertEqual(proposal["exact_target"]["verified_commit"], commit)
        self.assertTrue(proposal["human_approval_required"])

    def test_failed_push_proposal_never_recommends_unverified_retry(self):
        run = {
            "run_id": 38563234519,
            "run_url": "https://github.com/example/repo/actions/runs/38563234519",
            "commit_sha": "a" * 40,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "failed_jobs": ["Build and deploy"],
            "failed_steps": ["Build and deploy / Build and push Docker image"],
            "image_push_status": "failed",
            "image_push_error_category": "network",
            "image_uri": IMAGE,
            "steps": [{"name": "Build and push Docker image", "conclusion": "failure"}],
        }
        incident = incident_for(
            "connection timed out",
            registry=[
                {
                    "image_uri": IMAGE,
                    "status": "available",
                    "repository_exists": True,
                    "tag_exists": True,
                }
            ],
            github_run=run,
        )

        proposal = build_remediation_proposal(incident.to_dict(), "98765")

        self.assertEqual(
            proposal["retry_assessment"]["safe_to_retry"],
            False,
        )
        self.assertIn("idempotent", proposal["retry_assessment"]["reason"])
        self.assertIsNone(proposal["proposed_action"]["operation"])

    def test_verified_successful_workflow_image_mismatch_is_manual_review_only(self):
        commit = "b" * 40
        verified_image = (
            "asia-south1-docker.pkg.dev/abdulproject-510307/"
            "ai-k8s-repo/ai-k8s-demo:" + commit
        )
        run = {
            "run_id": 123,
            "commit_sha": commit,
            "image_uri": verified_image,
            "image_push_status": "succeeded",
            "steps": [{"name": "Build and push Docker image", "conclusion": "success"}],
            "log_excerpt": "push complete",
        }
        registry = [
            {
                "image_uri": IMAGE,
                "status": "available",
                "repository_exists": True,
                "tag_exists": True,
            },
            {
                "image_uri": verified_image,
                "status": "available",
                "repository_exists": True,
                "tag_exists": True,
                "digest": "sha256:" + ("d" * 64),
            },
        ]

        incident = incident_for("failed to pull image", registry=registry, github_run=run)
        proposal = build_remediation_proposal(incident.to_dict(), "98765")

        self.assertIn("differs from", incident.diagnosis["root_cause"])
        self.assertEqual(proposal["exact_target"]["verified_image_uri"], verified_image)
        self.assertIsNone(proposal["proposed_action"]["operation"])
        self.assertFalse(
            proposal["proposed_action"]["executable_by_remediation_workflow"]
        )
        self.assertTrue(proposal["human_approval_required"])

    def test_failed_push_is_correlated_with_exact_run_and_steps(self):
        run = {
            "run_id": 38563234519,
            "run_url": "https://github.com/example/repo/actions/runs/38563234519",
            "commit_sha": "a" * 40,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "failed_jobs": ["Build and deploy"],
            "failed_steps": ["Build and deploy / Build and push Docker image"],
            "image_push_status": "failed",
            "image_uri": IMAGE,
            "steps": [{"name": "Build and push Docker image", "conclusion": "failure"}],
        }
        incident = incident_for("denied: requested access", github_run=run)

        self.assertIn("failed image push", incident.diagnosis["root_cause"])
        self.assertEqual(incident.diagnosis["github_actions"]["run_id"], 38563234519)
        self.assertTrue(any("failed steps" in fact for fact in incident.facts))
        self.assertNotIn("rollout_restart", incident.eligible_remediations)

    def test_registry_authorization_and_transient_network_errors_are_distinct(self):
        denied = incident_for("unauthorized: authentication required")
        self.assertIn("authorization rejection", denied.diagnosis["root_cause"])
        self.assertIn("node-pool identities", denied.remediation_plan["operation"])

        transient = incident_for("registry returned HTTP 429: too many requests")
        self.assertIn("rate-limit", transient.diagnosis["root_cause"])
        self.assertEqual(transient.diagnosis["confidence"], "medium")
        self.assertIn("quota", transient.diagnosis["next_steps"][0])

    def test_confirmed_registry_403_and_existing_tag_offer_approved_reader_grant(self):
        incident = incident_for(
            "failed to authorize: registry returned HTTP 403 Forbidden",
            registry=[
                {
                    "image_uri": IMAGE,
                    "status": "available",
                    "repository_exists": True,
                    "image_exists": True,
                    "tag_exists": True,
                    "digest": "sha256:" + ("c" * 64),
                }
            ],
        )

        self.assertEqual(incident.diagnosis["registry_pull_error_status"], 403)
        self.assertIn(
            ARTIFACT_REGISTRY_READER_REMEDIATION,
            incident.eligible_remediations,
        )
        self.assertIn("must be displayed and approved", incident.remediation_plan["operation"])

    def test_inconclusive_evidence_reports_missing_sources_and_next_steps(self):
        incident = incident_for("image pull failed")

        self.assertIsNone(incident.diagnosis["root_cause"])
        self.assertTrue(incident.diagnosis["hypotheses"])
        self.assertTrue(incident.diagnosis["missing_evidence"])
        self.assertTrue(incident.diagnosis["next_steps"])
        self.assertIn(
            "No production change is recommended",
            incident.remediation_plan["operation"],
        )

    def test_current_crashloop_state_is_not_misclassified_by_old_pull_event(self):
        item = image_pull_item()
        item.state_reasons = ["CrashLoopBackOff"]
        item.status = "Running"
        item.events = ["[old] Warning: ImagePullBackOff"]
        item.containers = [
            {
                "name": "app",
                "state": "waiting",
                "state_reason": "CrashLoopBackOff",
                "state_message": "process exited after image start",
                "image_id": "containerd://sha256:" + ("c" * 64),
            }
        ]
        bundle = {
            "cluster": "ai-k8s-cluster",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "items": [item],
            "deployments": [],
            "replicasets": [],
            "cluster_metrics": [],
            "artifact_registry": [],
            "github_actions": {"status": "unavailable", "run": None},
        }

        incidents = detect_incidents(bundle)

        self.assertTrue(any(incident.category == "crash_loop" for incident in incidents))
        self.assertFalse(
            any(incident.category == "image_pull_failure" for incident in incidents)
        )

    @patch.dict(os.environ, {}, clear=True)
    @patch("collectors.evidence_collector.collect_images_evidence")
    @patch("collectors.evidence_collector.collect_latest_deployment")
    @patch("collectors.evidence_collector.collect_grafana_metrics")
    @patch("collectors.evidence_collector.get_replicasets")
    @patch("collectors.evidence_collector.get_deployments")
    @patch("collectors.evidence_collector.get_all_pod_logs")
    @patch("collectors.evidence_collector.get_events")
    @patch("collectors.evidence_collector.get_pods")
    @patch("collectors.evidence_collector.load_kubernetes_config")
    def test_mocked_collectors_flow_into_evidence_supported_rca(
        self,
        _load_config,
        get_pods,
        get_events,
        get_logs,
        get_deployments,
        get_replicasets,
        collect_grafana,
        collect_github,
        collect_registry,
    ):
        get_pods.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo-abc123",
                "workload": "ai-k8s-demo",
                "workload_kind": "Deployment",
                "phase": "Pending",
                "ready": False,
                "restarts": 0,
                "images": [IMAGE],
                "image_digests": ["containerd://sha256:" + ("b" * 64)],
                "state_reasons": ["ImagePullBackOff"],
                "containers": [
                    {
                        "name": "app",
                        "state": "waiting",
                        "state_reason": "ImagePullBackOff",
                        "state_message": "manifest unknown: tag not found",
                        "image_id": "",
                    }
                ],
            }
        ]
        get_events.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "object": "ai-k8s-demo-abc123",
                "reason": "Failed",
                "type": "Warning",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "Failed to pull image: manifest unknown",
            }
        ]
        get_logs.return_value = []
        get_deployments.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo",
                "desired_replicas": 2,
                "available_replicas": 0,
                "images": [IMAGE],
                "conditions": [],
            }
        ]
        get_replicasets.return_value = [
            {
                "namespace": "ai-troubleshooter",
                "name": "ai-k8s-demo-abc",
                "owner": {"kind": "Deployment", "name": "ai-k8s-demo"},
                "desired_replicas": 2,
                "ready_replicas": 0,
                "available_replicas": 0,
                "images": [IMAGE],
            }
        ]
        collect_grafana.return_value = {
            "cluster": "ai-k8s-cluster",
            "cluster_metrics": [
                {
                    "metric": "grafana_connection",
                    "status": "unavailable",
                    "diagnostic": "GRAFANA_CLUSTER did not match any returned labels.",
                }
            ],
            "pod_metrics": {},
            "diagnostics": ["GRAFANA_CLUSTER did not match any returned labels."],
        }
        collect_github.return_value = {
            "status": "available",
            "run": {
                "run_id": 99,
                "commit_sha": "a" * 40,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "failed_jobs": ["Build and deploy"],
                "failed_steps": ["Build and deploy / Verify rollout"],
                "image_push_status": "succeeded",
                "image_uri": IMAGE,
                "steps": [{"name": "Build and push", "conclusion": "success"}],
                "log_excerpt": "pushed image",
            },
        }
        collect_registry.return_value = [
            {
                "image_uri": IMAGE,
                "status": "available",
                "repository_exists": True,
                "image_exists": True,
                "tag_exists": False,
                "digest": None,
                "repository_resource": "projects/p/locations/r/repositories/repo",
            }
        ]

        bundle = build_observability_evidence()
        incident = incident_for_bundle(bundle)

        self.assertEqual(bundle["replicasets"][0]["ready_replicas"], 0)
        self.assertEqual(bundle["items"][0].image_digests, ["containerd://sha256:" + ("b" * 64)])
        self.assertIn("absent", incident.diagnosis["root_cause"])
        self.assertIn("GRAFANA_CLUSTER", " ".join(incident.diagnosis["integration_diagnostics"]))
        self.assertFalse(incident.eligible_remediations)


def incident_for_bundle(bundle):
    return next(
        item
        for item in detect_incidents(bundle)
        if item.category == "image_pull_failure"
    )


if __name__ == "__main__":
    unittest.main()
