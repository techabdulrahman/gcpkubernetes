"""Validate an incident and run only an explicitly approved Deployment restart."""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


TARGET_NAMESPACE = "ai-troubleshooter"
TARGET_DEPLOYMENT = "ai-k8s-demo"
TARGET_SERVICE = "ai-k8s-service"
ALLOWED_ACTION = "rollout_restart"
MAX_EVIDENCE_AGE = timedelta(minutes=30)
ROLLOUT_TIMEOUT_SECONDS = 180


class RemediationValidationError(RuntimeError):
    """Raised when a remediation request or its approval binding is invalid."""


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def validate_plan(evidence_path, incident_id, action, evidence_run_id):
    """Verify the immutable evidence and construct the exact approved action."""
    if action != ALLOWED_ACTION:
        raise RemediationValidationError("Requested operation is not allowlisted.")
    if not incident_id or not incident_id.startswith("inc-"):
        raise RemediationValidationError("A valid incident identifier is required.")
    if not evidence_run_id.isdigit() or int(evidence_run_id) <= 0:
        raise RemediationValidationError("A valid evidence workflow run ID is required.")

    evidence_path = Path(evidence_path)
    try:
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RemediationValidationError(
            "Original incident evidence could not be retrieved or decoded."
        ) from error
    if not isinstance(evidence, dict) or evidence.get("version") != 1:
        raise RemediationValidationError("Incident evidence has an unsupported format.")

    observed_at = evidence.get("observed_at")
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise ValueError("Incident timestamp must include a timezone.")
    except (AttributeError, TypeError, ValueError) as error:
        raise RemediationValidationError("Incident evidence has no valid timestamp.") from error
    age = datetime.now(timezone.utc) - observed
    if age < timedelta(0) or age > MAX_EVIDENCE_AGE:
        raise RemediationValidationError("Incident evidence is missing, future-dated, or stale.")

    incidents = evidence.get("incidents")
    if not isinstance(incidents, list):
        raise RemediationValidationError("Incident evidence has no incident list.")
    incident = next(
        (
            item
            for item in incidents
            if isinstance(item, dict) and item.get("incident_id") == incident_id
        ),
        None,
    )
    if not incident:
        raise RemediationValidationError(
            "The requested incident is not present in the original evidence."
        )
    if incident.get("namespace") != TARGET_NAMESPACE:
        raise RemediationValidationError("Incident namespace is outside the allowlist.")
    if incident.get("workload") != TARGET_DEPLOYMENT:
        raise RemediationValidationError("Incident workload is outside the allowlist.")
    if incident.get("source_status", {}).get("kubernetes") != "available":
        raise RemediationValidationError("Required Kubernetes evidence is unavailable.")
    if ALLOWED_ACTION not in incident.get("eligible_remediations", []):
        raise RemediationValidationError(
            "The requested operation is not eligible for this incident."
        )

    plan = {
        "incident_id": incident_id,
        "evidence_run_id": evidence_run_id,
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "action": ALLOWED_ACTION,
        "namespace": TARGET_NAMESPACE,
        "target": TARGET_DEPLOYMENT,
        "parameters": {},
    }
    plan["approval_digest"] = hashlib.sha256(
        _canonical_json(plan).encode("utf-8")
    ).hexdigest()
    plan["expected_impact"] = (
        "Replace the pods in ai-troubleshooter/ai-k8s-demo using the existing "
        "image and configuration."
    )
    plan["risk"] = (
        "A rolling restart can temporarily reduce availability and will not "
        "correct a bad image, configuration, probe, or resource limit."
    )
    plan["rollback"] = (
        "No image/configuration change is made. If availability worsens, stop "
        "further actions and invoke the separately reviewed recovery procedure."
    )
    return plan, evidence


def verify_approval(plan, approval_digest):
    """Verify that the approval still names the exact action and evidence."""
    binding = {
        key: plan.get(key)
        for key in (
            "incident_id",
            "evidence_run_id",
            "evidence_sha256",
            "action",
            "namespace",
            "target",
            "parameters",
        )
    }
    expected = hashlib.sha256(
        _canonical_json(binding).encode("utf-8")
    ).hexdigest()
    if (
        not approval_digest
        or approval_digest != expected
        or plan.get("approval_digest") != expected
    ):
        raise RemediationValidationError(
            "Post-approval request does not match the reviewed action and evidence."
        )
    return True


def _write_plan(plan, evidence, summary_path=None, output_path=None):
    incident = next(
        record for record in evidence["incidents"]
        if record["incident_id"] == plan["incident_id"]
    )
    content = (
        "## Approval plan (no changes have been applied)\n\n"
        f"- Incident: `{plan['incident_id']}`\n"
        f"- Operation: `{plan['action']}`\n"
        f"- Target: `{plan['namespace']}/{plan['target']}`\n"
        f"- Expected impact: {plan['expected_impact']}\n"
        f"- Risk: {plan['risk']}\n"
        f"- Recovery plan: {plan['rollback']}\n"
        f"- Evidence analysis mode: {incident.get('analysis_mode', 'unavailable')}\n"
        f"- Approval binding digest: `{plan['approval_digest']}`\n"
    )
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write(content)
    if output_path:
        Path(output_path).write_text(
            json.dumps(plan, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    output_file = os.getenv("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as output:
            output.write(f"approval_digest={plan['approval_digest']}\n")
    print(content)


def _live_incident_is_active(incident_id):
    from ai.sre_agent import detect_incidents
    from collectors.evidence_collector import build_observability_evidence

    live_bundle = build_observability_evidence()
    return incident_id in {
        incident.incident_id
        for incident in detect_incidents(live_bundle, live_bundle.get("github_actions"))
    }


def _wait_for_rollout(apps_api, core_api):
    deadline = time.monotonic() + ROLLOUT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        deployment = apps_api.read_namespaced_deployment(
            name=TARGET_DEPLOYMENT,
            namespace=TARGET_NAMESPACE,
            _request_timeout=(5, 20),
        )
        status = deployment.status
        desired = deployment.spec.replicas or 0
        if (
            status.observed_generation is not None
            and status.observed_generation >= deployment.metadata.generation
            and status.updated_replicas == desired
            and status.available_replicas == desired
            and status.unavailable_replicas in (None, 0)
        ):
            pods = core_api.list_namespaced_pod(
                namespace=TARGET_NAMESPACE,
                label_selector=f"app={TARGET_DEPLOYMENT}",
                _request_timeout=(5, 20),
            )
            ready_pods = sum(
                1
                for pod in pods.items
                if any(
                    condition.type == "Ready" and condition.status == "True"
                    for condition in (pod.status.conditions or [])
                )
            )
            if ready_pods == desired:
                return desired
        time.sleep(2)
    raise RemediationValidationError("Deployment rollout or pod readiness timed out.")


def _verify_application_health(core_api):
    response = core_api.connect_get_namespaced_service_proxy_with_path(
        name=TARGET_SERVICE,
        namespace=TARGET_NAMESPACE,
        path="health",
        _request_timeout=20,
    )
    if isinstance(response, bytes):
        response = response.decode("utf-8")
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except json.JSONDecodeError as error:
            raise RemediationValidationError(
                "Application health endpoint returned invalid JSON."
            ) from error
    if not isinstance(response, dict) or response.get("status") != "healthy":
        raise RemediationValidationError(
            "Application health endpoint did not report healthy."
        )
    return True


def execute_plan(
    plan,
    approval_digest,
    live_incident_check=None,
    apps_api=None,
    core_api=None,
):
    """Revalidate the incident then make only the one allowlisted API patch."""
    if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv(
        "REMEDIATION_APPROVAL_GRANTED"
    ) != "true":
        raise RemediationValidationError(
            "Execution is permitted only in the post-approval GitHub Environment job."
        )
    if (
        plan.get("action") != ALLOWED_ACTION
        or plan.get("namespace") != TARGET_NAMESPACE
        or plan.get("target") != TARGET_DEPLOYMENT
        or plan.get("parameters") != {}
    ):
        raise RemediationValidationError("Approval does not match the allowlisted operation.")
    verify_approval(plan, approval_digest)
    live_check = live_incident_check or _live_incident_is_active
    if not live_check(plan["incident_id"]):
        raise RemediationValidationError(
            "The original incident is no longer active in fresh Kubernetes evidence."
        )

    if apps_api is None or core_api is None:
        from kubernetes import client, config

        config.load_kube_config()
        apps_api = apps_api or client.AppsV1Api()
        core_api = core_api or client.CoreV1Api()

    restart_time = datetime.now(timezone.utc).isoformat(timespec="seconds")
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": restart_time
                    }
                }
            }
        }
    }
    try:
        apps_api.patch_namespaced_deployment(
            name=TARGET_DEPLOYMENT,
            namespace=TARGET_NAMESPACE,
            body=patch,
        )
        ready_replicas = _wait_for_rollout(apps_api, core_api)
        health_ok = _verify_application_health(core_api)
    except Exception as error:
        from kubernetes.client.rest import ApiException

        if isinstance(error, ApiException):
            detail = f"Kubernetes API returned HTTP {error.status or 'unknown'}."
        elif isinstance(error, RemediationValidationError):
            detail = str(error)
        else:
            detail = f"Verification failed ({type(error).__name__})."
        raise RemediationValidationError(
            "The approved operation may already have been applied; "
            f"stop and investigate before retrying. {detail}"
        ) from error
    try:
        from collectors.grafana_metrics_collector import collect_grafana_metrics
        from collectors.kubernetes_collector import get_pods

        metric_result = collect_grafana_metrics(
            get_pods(TARGET_NAMESPACE),
            TARGET_NAMESPACE,
            TARGET_DEPLOYMENT,
        )
        grafana_status = (
            "available"
            if any(
                metric.get("status") == "available"
                for metric in metric_result.get("cluster_metrics", [])
            )
            else "unavailable"
        )
    except Exception as error:
        # Verification result remains explicit; never report unavailable metrics as zero.
        grafana_status = f"unavailable ({type(error).__name__})"
    return {
        "status": "succeeded" if health_ok else "needs further investigation",
        "incident_id": plan["incident_id"],
        "action": ALLOWED_ACTION,
        "target": f"{TARGET_NAMESPACE}/{TARGET_DEPLOYMENT}",
        "ready_replicas": ready_replicas,
        "application_health": "healthy" if health_ok else "unhealthy",
        "grafana_metrics": grafana_status,
        "restart_annotation": restart_time,
    }


def _publish_execution_report(result):
    lines = [
        "## Approval-gated remediation result",
        f"- Status: **{result['status']}**",
        f"- Incident: `{result['incident_id']}`",
        f"- Operation: `{result['action']}`",
        f"- Target: `{result['target']}`",
        f"- Ready replicas: {result['ready_replicas']}",
        f"- Application health: {result['application_health']}",
        f"- Grafana metrics: {result['grafana_metrics']}",
        "- Verification: Deployment observed generation and desired replicas became ready; "
        "the Kubernetes service health endpoint was checked.",
        "- No image, configuration, IAM, or infrastructure change was made.",
    ]
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        raise RemediationValidationError("GITHUB_STEP_SUMMARY is not available.")
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "execute"))
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--evidence-run-id", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--approval-digest")
    parser.add_argument("--plan-output")
    args = parser.parse_args()
    try:
        plan, evidence = validate_plan(
            args.evidence,
            args.incident_id,
            args.action,
            args.evidence_run_id,
        )
        if args.mode == "plan":
            _write_plan(
                plan,
                evidence,
                os.getenv("GITHUB_STEP_SUMMARY"),
                args.plan_output,
            )
            return 0

        verify_approval(plan, args.approval_digest)
        result = execute_plan(plan, args.approval_digest)
        _publish_execution_report(result)
        return 0
    except (RemediationValidationError, OSError, ValueError) as error:
        print(f"Remediation refused or failed: {error}", file=sys.stderr)
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write(
                    "## Approval-gated remediation result\n"
                    f"- Status: **needs further investigation**\n"
                    f"- Detail: {error}\n"
                    + (
                        "- The approved operation may already have been applied; "
                        "do not retry automatically.\n"
                        if args.mode == "execute"
                        else "- No cluster change was attempted.\n"
                    )
                )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
