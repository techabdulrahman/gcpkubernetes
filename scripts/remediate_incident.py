"""Validate incident evidence and run only an explicitly approved operation."""

import argparse
import hashlib
import json
import os
import re
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
ARTIFACT_REGISTRY_READER_ACTION = "grant_artifact_registry_reader"
ALLOWED_ACTIONS = {ALLOWED_ACTION, ARTIFACT_REGISTRY_READER_ACTION}
ARTIFACT_REGISTRY_READER_ROLE = "roles/artifactregistry.reader"
MAX_EVIDENCE_AGE = timedelta(minutes=30)
ROLLOUT_TIMEOUT_SECONDS = 180
IMAGE_PULL_RECOVERY_TIMEOUT_SECONDS = 360


class RemediationValidationError(RuntimeError):
    """Raised when a remediation request or its approval binding is invalid."""


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _gcp_target_from_image(image):
    from collectors.artifact_registry_collector import _image_reference

    reference = _image_reference(image)
    project = os.getenv("PROJECT_ID") or os.getenv("GCP_PROJECT_ID")
    region = os.getenv("REGION") or os.getenv("GCP_REGION")
    repository = os.getenv("GAR_REPOSITORY")
    if not reference or not project or not region or not repository:
        raise RemediationValidationError(
            "A valid Artifact Registry image and configured project, region, and repository are required."
        )
    if (
        reference["project"] != project
        or reference["location"] != region
        or reference["repository"] != repository
    ):
        raise RemediationValidationError(
            "The image registry target is outside the configured project, region, or repository."
        )
    return {
        "project": project,
        "location": region,
        "repository": repository,
        "resource": reference["repository_resource"],
    }


def _current_node_pool_identities():
    from collectors.gke_node_identity_collector import (
        GKENodeIdentityError,
        get_node_pool_service_accounts,
    )

    project = os.getenv("PROJECT_ID") or os.getenv("GCP_PROJECT_ID")
    region = os.getenv("REGION") or os.getenv("GCP_REGION")
    cluster = os.getenv("CLUSTER_NAME") or os.getenv("GKE_CLUSTER_NAME")
    if not project or not region or not cluster:
        raise RemediationValidationError(
            "Project, region, and cluster configuration are required to verify node identities."
        )
    try:
        identity_result = get_node_pool_service_accounts(project, region, cluster)
    except GKENodeIdentityError as error:
        raise RemediationValidationError(str(error)) from error
    identities = identity_result.get("items") if isinstance(identity_result, dict) else None
    if (
        not isinstance(identity_result, dict)
        or identity_result.get("status") != "available"
        or not isinstance(identities, list)
        or not identities
    ):
        raise RemediationValidationError(
            "GKE node-pool service accounts could not be verified."
        )
    return identities


def validate_plan(evidence_path, incident_id, action, evidence_run_id):
    """Verify the immutable evidence and construct the exact approved action."""
    if action not in ALLOWED_ACTIONS:
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
    bound_run_id = evidence.get("evidence_run_id")
    if not isinstance(bound_run_id, (str, int)) or str(bound_run_id) != evidence_run_id:
        raise RemediationValidationError(
            "Evidence workflow run ID does not match the supplied investigation run."
        )

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
    source_status = incident.get("source_status")
    if not isinstance(source_status, dict) or source_status.get("kubernetes") != "available":
        raise RemediationValidationError("Required Kubernetes evidence is unavailable.")
    if action not in incident.get("eligible_remediations", []):
        raise RemediationValidationError(
            "The requested operation is not eligible for this incident."
        )
    diagnosis = incident.get("diagnosis")
    if not isinstance(diagnosis, dict):
        raise RemediationValidationError("Incident diagnosis is missing or invalid.")
    from ai.sre_agent import build_remediation_proposal

    proposal = build_remediation_proposal(incident, evidence_run_id)
    if (
        proposal["proposed_action"]["operation"] != action
        or not proposal["proposed_action"]["executable_by_remediation_workflow"]
    ):
        raise RemediationValidationError(
            "The structured proposal does not authorize this executable operation."
        )
    expected_images = (
        diagnosis.get("deployed_images", [])
        if action == ARTIFACT_REGISTRY_READER_ACTION
        else diagnosis.get("images", [])
    )
    if (
        not isinstance(expected_images, list)
        or not expected_images
        or any(not isinstance(image, str) or not image for image in expected_images)
    ):
        raise RemediationValidationError(
            "Incident evidence does not bind remediation to the deployed image."
        )
    image_digests = diagnosis.get("image_digests", {})
    if not isinstance(image_digests, dict):
        raise RemediationValidationError(
            "Incident evidence contains invalid image digest bindings."
        )
    expected_image_digests = {
        image: digest
        for image, digest in image_digests.items()
        if image in expected_images
    }
    if (
        any(
            image not in expected_images
            or not isinstance(digest, str)
            or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest)
            for image, digest in expected_image_digests.items()
        )
    ):
        raise RemediationValidationError(
            "Incident evidence contains invalid image digest bindings."
        )

    iam_target = None
    node_identities = []
    if action == ARTIFACT_REGISTRY_READER_ACTION:
        root_cause = diagnosis.get("root_cause")
        if (
            incident.get("category") != "image_pull_failure"
            or diagnosis.get("registry_pull_error_status") != 403
            or not isinstance(root_cause, str)
            or "authorization rejection" not in root_cause
            or len(expected_images) != 1
        ):
            raise RemediationValidationError(
                "Artifact Registry access remediation requires a confirmed HTTP 403 for one image."
            )
        image = expected_images[0]
        if not any(
            record.get("image_uri") == image
            and record.get("status") == "available"
            and record.get("repository_exists") is True
            and record.get("tag_exists") is True
            for record in diagnosis.get("artifact_registry", [])
        ):
            raise RemediationValidationError(
                "The exact deployed image tag must be confirmed present before an IAM grant is eligible."
            )
        iam_target = _gcp_target_from_image(image)
        node_identities = _current_node_pool_identities()

    plan = {
        "incident_id": incident_id,
        "evidence_run_id": evidence_run_id,
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "action": action,
        "namespace": TARGET_NAMESPACE,
        "target": TARGET_DEPLOYMENT,
        "operation_target": (
            iam_target["resource"]
            if iam_target
            else f"{TARGET_NAMESPACE}/{TARGET_DEPLOYMENT}"
        ),
        "expected_images": sorted(set(expected_images)),
        "expected_image_digests": dict(sorted(expected_image_digests.items())),
        "proposal": proposal,
        "verification_criteria": proposal["verification_criteria"],
        "expected_impact": proposal["expected_impact"],
        "risk": proposal["risk"],
        "parameters": (
            {
                "role": ARTIFACT_REGISTRY_READER_ROLE,
                "repository_resource": iam_target["resource"],
                "node_pool_service_accounts": node_identities,
            }
            if iam_target
            else {}
        ),
        "iam_target": iam_target,
    }
    if action == ARTIFACT_REGISTRY_READER_ACTION:
        plan["expected_impact"] = (
            f"Grant Artifact Registry Reader on {iam_target['resource']} to only "
            "the listed service accounts used by this cluster's node pools. "
            "Kubernetes will retry image pulls; no restart or image change is made."
        )
        plan["risk"] = (
            "The listed node-pool identities will gain read access to images in "
            "this one repository. The change does not grant registry write access."
        )
        plan["rollback"] = (
            "Remove only the repository-level roles/artifactregistry.reader "
            "binding added for the listed service accounts if access must be "
            "withdrawn; preserve all pre-existing bindings."
        )
    else:
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
    plan["approval_digest"] = hashlib.sha256(
        _canonical_json(_approval_binding(plan)).encode("utf-8")
    ).hexdigest()
    return plan, evidence


def _approval_binding(plan):
    return {
        key: plan.get(key)
        for key in (
            "incident_id",
            "evidence_run_id",
            "evidence_sha256",
            "action",
            "namespace",
            "target",
            "operation_target",
            "expected_images",
            "expected_image_digests",
            "parameters",
            "iam_target",
            "proposal",
            "verification_criteria",
            "expected_impact",
            "risk",
            "rollback",
        )
    }


def verify_approval(plan, approval_digest):
    """Verify that the approval still names the exact action and evidence."""
    expected = hashlib.sha256(
        _canonical_json(_approval_binding(plan)).encode("utf-8")
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
        f"- Investigation workflow run: `{plan['evidence_run_id']}`\n"
        f"- Evidence SHA-256: `{plan['evidence_sha256']}`\n"
        f"- Operation: `{plan['action']}`\n"
        f"- Proposed action: {plan['proposal']['proposed_action']['description']}\n"
        f"- Exact operation target: `{plan['operation_target']}`\n"
        f"- Workload: `{plan['namespace']}/{plan['target']}`\n"
        f"- Expected image(s): {', '.join(f'`{image}`' for image in plan['expected_images'])}\n"
        f"- Expected digest(s): {', '.join(f'`{image}={digest}`' for image, digest in plan['expected_image_digests'].items()) or 'unavailable'}\n"
        f"- Confirmed root cause: {plan['proposal']['confirmed_root_cause'] or 'Not confirmed'}\n"
        f"- Evidence confidence: **{plan['proposal']['confidence']}**\n"
        "- Supporting evidence:\n"
        + (
            "\n".join(
                f"  - {fact}"
                for fact in plan["proposal"]["supporting_evidence"]
            )
            or "  - No confirmed supporting facts were recorded."
        )
        + "\n"
        + "- Missing evidence:\n"
        + (
            "\n".join(
                f"  - {item}"
                for item in plan["proposal"]["missing_evidence"]
            )
            or "  - None reported."
        )
        + "\n"
        + (
            f"- IAM role: `{plan['parameters']['role']}` on "
            f"`{plan['iam_target']['resource']}`\n"
            "- Node-pool service accounts:\n"
            + "\n".join(
                f"  - `{identity['service_account']}` (pool `{identity['pool']}`)"
                for identity in plan["parameters"]["node_pool_service_accounts"]
            )
            + "\n"
            if plan["action"] == ARTIFACT_REGISTRY_READER_ACTION
            else ""
        )
        + f"- Expected impact: {plan['expected_impact']}\n"
        + f"- Risk: {plan['risk']}\n"
        + f"- Recovery plan: {plan['rollback']}\n"
        + "- Post-change verification:\n"
        + "\n".join(
            f"  - {criterion}"
            for criterion in plan["verification_criteria"]
        )
        + "\n"
        + "- Human approval required: **yes**, via the `kubernetes-remediation` GitHub Environment\n"
        + f"- Evidence analysis mode: {incident.get('analysis_mode', 'unavailable')}\n"
        + f"- Approval binding digest: `{plan['approval_digest']}`\n"
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


def _live_incident_is_active(
    incident_id,
    expected_images,
    expected_image_digests=None,
    operation=ALLOWED_ACTION,
):
    from ai.sre_agent import detect_incidents
    from collectors.evidence_collector import build_observability_evidence

    live_bundle = build_observability_evidence()
    incidents = detect_incidents(
        live_bundle,
        live_bundle.get("github_actions"),
    )
    incident = next(
        (item for item in incidents if item.incident_id == incident_id),
        None,
    )
    if not incident or operation not in incident.eligible_remediations:
        return False
    if expected_image_digests:
        live_image_digests = incident.diagnosis.get("image_digests", {})
        if not isinstance(live_image_digests, dict):
            return False
        live_expected_digests = {
            image: digest
            for image, digest in live_image_digests.items()
            if image in expected_images
        }
        if live_expected_digests != expected_image_digests:
            return False
    live_images = {
        image
        for deployment in live_bundle.get("deployments", [])
        if deployment.get("namespace") == TARGET_NAMESPACE
        and deployment.get("name") == TARGET_DEPLOYMENT
        for image in deployment.get("images", [])
    }
    return bool(live_images) and live_images == set(expected_images)


def _pod_image_digests_match(pod, expected_image_digests):
    statuses = {
        status.name: status
        for status in (pod.status.container_statuses or [])
    }
    for container in pod.spec.containers or []:
        expected = expected_image_digests.get(container.image)
        if not expected:
            continue
        status = statuses.get(container.name)
        match = re.search(
            r"sha256:[0-9a-fA-F]{64}",
            status.image_id if status and status.image_id else "",
        )
        if not match or match.group(0).lower() != expected.lower():
            return False
    return True


def _wait_for_rollout(
    apps_api,
    core_api,
    expected_images,
    expected_image_digests=None,
    timeout_seconds=ROLLOUT_TIMEOUT_SECONDS,
):
    expected_image_digests = expected_image_digests or {}
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        deployment = apps_api.read_namespaced_deployment(
            name=TARGET_DEPLOYMENT,
            namespace=TARGET_NAMESPACE,
            _request_timeout=(5, 20),
        )
        status = deployment.status
        desired = deployment.spec.replicas or 0
        deployment_images = {
            container.image
            for container in deployment.spec.template.spec.containers or []
        }
        if not expected_images or deployment_images != set(expected_images):
            raise RemediationValidationError(
                "Deployment image changed after approval; refusing to verify or continue."
            )
        if (
            desired > 0
            and status.observed_generation is not None
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
            ready_pods = [
                pod
                for pod in pods.items
                if any(
                    condition.type == "Ready" and condition.status == "True"
                    for condition in (pod.status.conditions or [])
                )
                and {
                    container.image
                    for container in pod.spec.containers or []
                } == set(expected_images)
                and len(pod.status.container_statuses or []) == len(pod.spec.containers or [])
                and all(
                    status.ready and status.image_id
                    for status in (pod.status.container_statuses or [])
                )
                and _pod_image_digests_match(pod, expected_image_digests)
            ]
            if len(ready_pods) == desired:
                return {
                    "ready_replicas": desired,
                    "images": sorted(deployment_images),
                    "image_digests": expected_image_digests,
                    "image_ids": sorted({
                        status.image_id
                        for pod in ready_pods
                        for status in pod.status.container_statuses
                    }),
                }
        time.sleep(2)
    raise RemediationValidationError("Deployment rollout or pod readiness timed out.")


def _grant_artifact_registry_reader(plan, apps_api, core_api):
    from collectors.artifact_registry_iam import (
        READER_ROLE,
        add_repository_reader,
        get_repository_policy,
        has_unconditional_reader,
    )

    iam_target = plan.get("iam_target")
    parameters = plan.get("parameters")
    if (
        not isinstance(iam_target, dict)
        or not isinstance(parameters, dict)
        or parameters.get("role") != READER_ROLE
        or parameters.get("repository_resource") != iam_target.get("resource")
    ):
        raise RemediationValidationError("Approved Artifact Registry IAM target is invalid.")

    target = _gcp_target_from_image(plan["expected_images"][0])
    if (
        target["resource"] != iam_target.get("resource")
        or target["project"] != iam_target.get("project")
        or target["location"] != iam_target.get("location")
        or target["repository"] != iam_target.get("repository")
    ):
        raise RemediationValidationError(
            "Artifact Registry target changed or is outside the configured allowlist."
        )

    approved_identities = parameters.get("node_pool_service_accounts")
    current_identities = _current_node_pool_identities()
    if approved_identities != current_identities:
        raise RemediationValidationError(
            "GKE node-pool service accounts changed after approval; refusing IAM update."
        )
    members = sorted({
        f"serviceAccount:{identity['service_account']}"
        for identity in current_identities
    })
    if not members:
        raise RemediationValidationError(
            "No verified GKE node-pool service accounts were found."
        )

    policy = get_repository_policy(
        target["project"],
        target["location"],
        target["repository"],
    )
    already_granted = [
        member for member in members
        if has_unconditional_reader(policy, member)
    ]
    granted = []
    for member in members:
        if member in already_granted:
            continue
        add_repository_reader(
            target["project"],
            target["location"],
            target["repository"],
            member,
        )
        granted.append(member)

    verified_policy = get_repository_policy(
        target["project"],
        target["location"],
        target["repository"],
    )
    if not all(
        has_unconditional_reader(verified_policy, member)
        for member in members
    ):
        raise RemediationValidationError(
            "Repository IAM policy did not verify the approved Reader bindings."
        )

    rollout = _wait_for_rollout(
        apps_api,
        core_api,
        plan["expected_images"],
        plan.get("expected_image_digests"),
        timeout_seconds=IMAGE_PULL_RECOVERY_TIMEOUT_SECONDS,
    )
    health_ok = _verify_application_health(core_api)
    return {
        "status": "succeeded" if health_ok else "needs further investigation",
        "incident_id": plan["incident_id"],
        "action": ARTIFACT_REGISTRY_READER_ACTION,
        "target": iam_target["resource"],
        "role": READER_ROLE,
        "granted_members": granted,
        "already_granted_members": already_granted,
        "ready_replicas": rollout["ready_replicas"],
        "verified_images": rollout["images"],
        "image_digests": rollout["image_digests"],
        "image_ids": rollout["image_ids"],
        "application_health": "healthy" if health_ok else "unhealthy",
    }


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


def _fresh_failure_diagnosis(incident_id):
    """Collect read-only evidence after a failed approved operation."""
    from ai.sre_agent import analyze_incidents
    from collectors.evidence_collector import build_observability_evidence

    bundle = build_observability_evidence()
    incidents = analyze_incidents(bundle, bundle.get("github_actions"))
    incident = next(
        (item for item in incidents if item.incident_id == incident_id),
        None,
    )
    if not incident:
        return "Fresh evidence no longer detects the approved incident."
    root_cause = incident.diagnosis.get("root_cause")
    cause_text = root_cause or "No new root cause is confirmed."
    missing = "; ".join(incident.diagnosis.get("missing_evidence", []))
    next_steps = "; ".join(incident.diagnosis.get("next_steps", []))
    return (
        f"Fresh evidence: {cause_text}. "
        f"Missing evidence: {missing or 'none reported'}. "
        f"Next steps: {next_steps or 'review the updated incident report'}."
    )


def _collect_post_change_grafana():
    try:
        from collectors.grafana_metrics_collector import collect_grafana_metrics
        from collectors.kubernetes_collector import get_pods

        metric_result = collect_grafana_metrics(
            get_pods(TARGET_NAMESPACE),
            TARGET_NAMESPACE,
            TARGET_DEPLOYMENT,
        )
        metric_records = list(metric_result.get("cluster_metrics", []))
        metric_records.extend(
            metric
            for pod_metrics in metric_result.get("pod_metrics", {}).values()
            for metric in pod_metrics
        )
        relevant_names = {
            "application.health_status",
            "application.error_rate",
            "application.latency_p95",
            "application.scrape_up",
            "deployment.unavailable_replicas",
        }
        observations = [
            {
                "metric": metric.get("metric"),
                "value": metric.get("value"),
                "scope": metric.get("scope"),
                "status": metric.get("status"),
                "observed_at": metric.get("observed_at"),
            }
            for metric in metric_records
            if metric.get("metric") in relevant_names
        ][:20]
        status = (
            "available"
            if any(metric.get("status") == "available" for metric in observations)
            else "unavailable"
        )
    except Exception as error:
        status = f"unavailable ({type(error).__name__})"
        observations = []
    return {
        "grafana_metrics": status,
        "grafana_observations": observations,
    }


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
    action = plan.get("action")
    if (
        action not in ALLOWED_ACTIONS
        or plan.get("namespace") != TARGET_NAMESPACE
        or plan.get("target") != TARGET_DEPLOYMENT
    ):
        raise RemediationValidationError("Approval does not match the allowlisted operation.")
    if action == ALLOWED_ACTION and plan.get("parameters") != {}:
        raise RemediationValidationError("Restart approval contains unexpected parameters.")
    if action == ARTIFACT_REGISTRY_READER_ACTION and not isinstance(
        plan.get("iam_target"), dict
    ):
        raise RemediationValidationError("IAM approval does not identify its exact repository.")
    verify_approval(plan, approval_digest)
    if not plan.get("expected_images"):
        raise RemediationValidationError(
            "Approved plan does not identify the expected deployment image."
        )
    active = (
        live_incident_check(plan["incident_id"])
        if live_incident_check is not None
        else _live_incident_is_active(
            plan["incident_id"],
            plan["expected_images"],
            plan.get("expected_image_digests"),
            action,
        )
    )
    if not active:
        raise RemediationValidationError(
            "The original incident is no longer active in fresh Kubernetes evidence."
        )

    if apps_api is None or core_api is None:
        from kubernetes import client, config

        config.load_kube_config()
        apps_api = apps_api or client.AppsV1Api()
        core_api = core_api or client.CoreV1Api()

    if action == ARTIFACT_REGISTRY_READER_ACTION:
        try:
            result = _grant_artifact_registry_reader(plan, apps_api, core_api)
        except Exception as error:
            from kubernetes.client.rest import ApiException

            if isinstance(error, ApiException):
                detail = f"Kubernetes API returned HTTP {error.status or 'unknown'}."
            elif isinstance(error, RemediationValidationError):
                detail = str(error)
            else:
                detail = f"Approved IAM operation or verification failed ({type(error).__name__})."
            try:
                fresh_diagnosis = _fresh_failure_diagnosis(plan["incident_id"])
            except Exception as evidence_error:
                fresh_diagnosis = (
                    "Fresh read-only evidence collection also failed "
                    f"({type(evidence_error).__name__})."
                )
            raise RemediationValidationError(
                "The approved IAM operation may already have been applied; "
                f"stop and investigate before retrying. {detail} {fresh_diagnosis}"
            ) from error
        result.update(_collect_post_change_grafana())
        return result

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
        rollout = _wait_for_rollout(
            apps_api,
            core_api,
            plan["expected_images"],
            plan.get("expected_image_digests"),
        )
        health_ok = _verify_application_health(core_api)
    except Exception as error:
        from kubernetes.client.rest import ApiException

        if isinstance(error, ApiException):
            detail = f"Kubernetes API returned HTTP {error.status or 'unknown'}."
        elif isinstance(error, RemediationValidationError):
            detail = str(error)
        else:
            detail = f"Verification failed ({type(error).__name__})."
        try:
            fresh_diagnosis = _fresh_failure_diagnosis(plan["incident_id"])
        except Exception as evidence_error:
            fresh_diagnosis = (
                "Fresh read-only evidence collection also failed "
                f"({type(evidence_error).__name__})."
            )
        raise RemediationValidationError(
            "The approved operation may already have been applied; "
            f"stop and investigate before retrying. {detail} {fresh_diagnosis}"
        ) from error
    result = {
        "status": "succeeded" if health_ok else "needs further investigation",
        "incident_id": plan["incident_id"],
        "action": ALLOWED_ACTION,
        "target": f"{TARGET_NAMESPACE}/{TARGET_DEPLOYMENT}",
        "ready_replicas": rollout["ready_replicas"],
        "verified_images": rollout["images"],
        "image_ids": rollout["image_ids"],
        "application_health": "healthy" if health_ok else "unhealthy",
    }
    result.update(_collect_post_change_grafana())
    result["restart_annotation"] = restart_time
    return result


def _publish_execution_report(result):
    lines = [
        "## Approval-gated remediation result",
        f"- Status: **{result['status']}**",
        f"- Incident: `{result['incident_id']}`",
        f"- Operation: `{result['action']}`",
        f"- Target: `{result['target']}`",
        f"- Ready replicas: {result['ready_replicas']}",
        f"- Verified images: {', '.join(result['verified_images'])}",
        f"- Runtime image IDs: {', '.join(result['image_ids'])}",
        f"- Application health: {result['application_health']}",
        f"- Grafana metrics: {result['grafana_metrics']}",
    ]
    if result["action"] == ARTIFACT_REGISTRY_READER_ACTION:
        lines.extend([
            f"- IAM role verified: `{result['role']}` on `{result['target']}`",
            "- Added service accounts: "
            + (", ".join(result["granted_members"]) or "none; already present"),
            "- Existing service accounts: "
            + (", ".join(result["already_granted_members"]) or "none"),
        ])
    lines.extend([
        "- Reviewed Grafana observations: "
        + (
            ", ".join(
                f"{metric['metric']}={metric['value']}"
                for metric in result["grafana_observations"]
                if metric.get("status") == "available"
            )
            or "no relevant metrics available"
        ),
        "- Verification: Expected image references were unchanged and running, runtime image IDs were present, "
        "desired replicas became Ready, and the Kubernetes service health endpoint was checked.",
        (
            "- Only the approved repository-scoped Artifact Registry Reader bindings were changed."
            if result["action"] == ARTIFACT_REGISTRY_READER_ACTION
            else "- No image, configuration, IAM, or infrastructure change was made."
        ),
    ])
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
