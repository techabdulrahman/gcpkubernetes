"""Select and execute the single evidence-allowlisted Kubernetes recovery action."""

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

from ai.remediation_policy import (
    ROLLOUT_RESTART,
    TARGET_NAMESPACE,
    TARGET_WORKLOAD as TARGET_DEPLOYMENT,
    restart_is_evidence_eligible,
)


ALLOWED_ACTIONS = {ROLLOUT_RESTART}
MAX_EVIDENCE_AGE = timedelta(minutes=30)
ROLLOUT_TIMEOUT_SECONDS = 180
MAX_ROLLOUT_ATTEMPTS = 1
BLOCKING_EVENT_REASONS = {
    "backoff",
    "failed",
    "failedcreate",
    "failedscheduling",
    "nodenotready",
    "nodeshutdown",
    "unreachable",
    "unhealthy",
}


class RemediationValidationError(RuntimeError):
    """Raised when evidence, authorization, or post-action verification fails."""


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _load_evidence(evidence_path):
    try:
        evidence_bytes = Path(evidence_path).read_bytes()
        evidence = json.loads(evidence_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RemediationValidationError(
            "Original incident evidence could not be retrieved or decoded."
        ) from error
    if not isinstance(evidence, dict) or evidence.get("version") != 1:
        raise RemediationValidationError("Incident evidence has an unsupported format.")
    return evidence_bytes, evidence


def _validate_evidence_source(evidence, evidence_run_id):
    if (
        not isinstance(evidence_run_id, str)
        or not evidence_run_id.isdigit()
        or int(evidence_run_id) <= 0
    ):
        raise RemediationValidationError("A valid evidence workflow run ID is required.")
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


def validate_plan(evidence_path, incident_id, action, evidence_run_id):
    """Verify evidence integrity and construct the exact bounded operation."""
    if action not in ALLOWED_ACTIONS:
        raise RemediationValidationError("Requested operation is not allowlisted.")
    if not isinstance(incident_id, str) or not re.fullmatch(r"inc-[0-9a-f]{16}", incident_id):
        raise RemediationValidationError("A valid incident identifier is required.")
    if (
        not isinstance(evidence_run_id, str)
        or not evidence_run_id.isdigit()
        or int(evidence_run_id) <= 0
    ):
        raise RemediationValidationError("A valid evidence workflow run ID is required.")

    evidence_bytes, evidence = _load_evidence(evidence_path)
    _validate_evidence_source(evidence, evidence_run_id)

    incidents = evidence.get("incidents")
    if not isinstance(incidents, list):
        raise RemediationValidationError("Incident evidence has no incident list.")
    incident = next(
        (
            item for item in incidents
            if isinstance(item, dict) and item.get("incident_id") == incident_id
        ),
        None,
    )
    if not incident:
        raise RemediationValidationError(
            "The requested incident is not present in the original evidence."
        )
    if (
        incident.get("namespace") != TARGET_NAMESPACE
        or incident.get("workload") != TARGET_DEPLOYMENT
    ):
        raise RemediationValidationError("Incident target is outside the allowlist.")
    if not restart_is_evidence_eligible(evidence, incident):
        raise RemediationValidationError(
            "Evidence does not meet the automatic rollout-restart policy."
        )

    diagnosis = incident.get("diagnosis")
    if not isinstance(diagnosis, dict):
        raise RemediationValidationError("Incident diagnosis is missing or invalid.")
    expected_images = diagnosis.get("deployed_images") or diagnosis.get("images")
    if (
        not isinstance(expected_images, list)
        or not expected_images
        or any(not isinstance(image, str) or not image for image in expected_images)
    ):
        raise RemediationValidationError(
            "Incident evidence does not bind remediation to the deployed image."
        )
    deployment = next(
        item for item in evidence["deployments"]
        if item.get("namespace") == TARGET_NAMESPACE
        and item.get("name") == TARGET_DEPLOYMENT
    )
    if sorted(set(expected_images)) != sorted(set(deployment.get("images") or [])):
        raise RemediationValidationError(
            "Incident diagnosis and Deployment image evidence do not match."
        )
    image_digests = diagnosis.get("image_digests") or {}
    if not isinstance(image_digests, dict):
        raise RemediationValidationError("Incident image digest evidence is invalid.")
    expected_image_digests = {
        image: image_digests[image]
        for image in expected_images
        if image in image_digests
    }
    if any(
        not isinstance(digest, str)
        or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest)
        for digest in expected_image_digests.values()
    ):
        raise RemediationValidationError("Incident image digest evidence is invalid.")

    from ai.sre_agent import build_remediation_proposal

    proposal = build_remediation_proposal(incident, evidence_run_id)
    if (
        proposal["proposed_action"]["operation"] != action
        or not proposal["proposed_action"]["executable_by_remediation_workflow"]
    ):
        raise RemediationValidationError(
            "The deterministic proposal does not authorize this operation."
        )
    plan = {
        "incident_id": incident_id,
        "evidence_run_id": evidence_run_id,
        "evidence_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "action": action,
        "namespace": TARGET_NAMESPACE,
        "target": TARGET_DEPLOYMENT,
        "expected_images": sorted(set(expected_images)),
        "expected_image_digests": dict(sorted(expected_image_digests.items())),
        "proposal": proposal,
        "expected_replicas": deployment["desired_replicas"],
        "max_unavailable": deployment["max_unavailable"],
        "max_surge": deployment["max_surge"],
    }
    return plan, evidence


def _selection_rejection_reasons(evidence, incident):
    """Describe relevant eligibility failures without logging evidence payloads."""
    if not isinstance(incident, dict):
        return ["incident record is not an object"]

    reasons = []
    if (
        incident.get("namespace") != TARGET_NAMESPACE
        or incident.get("workload") != TARGET_DEPLOYMENT
    ):
        reasons.append("target is outside the automatic-remediation allowlist")
    if incident.get("category") not in {"failed_rollout", "unready_pod"}:
        reasons.append("incident category is not supported for rollout_restart")

    actions = incident.get("eligible_remediations")
    if not isinstance(actions, list) or ROLLOUT_RESTART not in actions:
        reasons.append("incident does not declare the allowlisted rollout_restart action")

    source_status = incident.get("source_status")
    if not isinstance(source_status, dict):
        reasons.append("incident source-status evidence is missing")
    else:
        for source in ("kubernetes", "grafana"):
            if source_status.get(source) != "available":
                reasons.append(f"{source} evidence is not available")

    deployments = evidence.get("deployments")
    matches = [
        deployment
        for deployment in deployments or []
        if isinstance(deployment, dict)
        and deployment.get("namespace") == TARGET_NAMESPACE
        and deployment.get("name") == TARGET_DEPLOYMENT
    ] if isinstance(deployments, list) else []
    if len(matches) != 1:
        reasons.append("evidence does not contain exactly one allowlisted Deployment")
    else:
        deployment = matches[0]
        available = deployment.get("available_replicas")
        desired = deployment.get("desired_replicas")
        unavailable = deployment.get("unavailable_replicas")
        if not isinstance(available, int) or isinstance(available, bool) or available < 1:
            reasons.append("Deployment has fewer than one available replica")
        if not isinstance(desired, int) or isinstance(desired, bool) or desired < 2:
            reasons.append("Deployment has fewer than two desired replicas")
        if not isinstance(unavailable, int) or isinstance(unavailable, bool) or unavailable < 1:
            reasons.append("Deployment has no unavailable replica to recover")

    return list(dict.fromkeys(reasons))


def select_automatic_action(evidence_path, evidence_run_id):
    """Return the one policy-valid incident, or no action when ambiguous."""
    _, evidence = _load_evidence(evidence_path)
    incidents = evidence.get("incidents")
    if not isinstance(incidents, list):
        raise RemediationValidationError("Incident evidence has no incident list.")
    print(f"Incident candidates discovered: {len(incidents)}")
    _validate_evidence_source(evidence, evidence_run_id)

    eligible = []
    for index, incident in enumerate(incidents, start=1):
        reasons = _selection_rejection_reasons(evidence, incident)
        if not isinstance(incident, dict):
            print(f"Candidate {index}: rejected: {'; '.join(reasons)}.")
            continue

        incident_id = incident.get("incident_id")
        if (
            not isinstance(incident_id, str)
            or not re.fullmatch(r"inc-[0-9a-f]{16}", incident_id)
        ):
            reasons.append("incident identifier is missing or invalid")
            display_id = "invalid-id"
        else:
            display_id = incident_id
        try:
            plan, _ = validate_plan(
                evidence_path,
                incident_id,
                ROLLOUT_RESTART,
                evidence_run_id,
            )
        except RemediationValidationError as error:
            if str(error) not in reasons and not (
                str(error) == "Evidence does not meet the automatic rollout-restart policy."
                and reasons
            ):
                reasons.append(str(error))
            print(
                f"Candidate {index} ({display_id}): rejected: "
                f"{'; '.join(dict.fromkeys(reasons)) or 'policy validation failed'}."
            )
            continue

        if reasons:
            print(
                f"Candidate {index} ({incident_id}): rejected: "
                f"{'; '.join(dict.fromkeys(reasons))}."
            )
            continue
        eligible.append((incident_id, plan["action"]))
        print(f"Candidate {index} ({incident_id}): eligible for rollout_restart.")
    if len(eligible) != 1:
        print(f"Policy-eligible incidents: {len(eligible)}")
        if len(eligible) > 1:
            print("Selection rejected: multiple eligible incidents are ambiguous.")
        return None
    return {"incident_id": eligible[0][0], "action": eligible[0][1]}


def _plan_digest(plan):
    return hashlib.sha256(_canonical_json(plan).encode("utf-8")).hexdigest()


def _write_plan(plan, summary_path=None, output_path=None):
    content = (
        "## Automatic remediation plan (policy validated)\n\n"
        f"- Incident: `{plan['incident_id']}`\n"
        f"- Investigation run: `{plan['evidence_run_id']}`\n"
        f"- Evidence SHA-256: `{plan['evidence_sha256']}`\n"
        f"- Operation: `{plan['action']}`\n"
        f"- Target: `{plan['namespace']}/{plan['target']}`\n"
        f"- Expected images: {', '.join(f'`{image}`' for image in plan['expected_images'])}\n"
        f"- Confirmed cause: {plan['proposal']['confirmed_root_cause'] or 'Transient node failure corroborated by current evidence'}\n"
        f"- Expected impact: {plan['proposal']['expected_impact']}\n"
        f"- Risk: {plan['proposal']['risk']}\n"
        "- Policy: one bounded rollout restart; no IAM, image, configuration, "
        "cluster-wide security, or infrastructure changes.\n"
        "- Retry limit: one operation; no automatic retry after failure.\n"
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
            output.write(f"plan_sha256={_plan_digest(plan)}\n")
    print(content)


def _live_incident_is_active(incident_id, expected_images, expected_image_digests=None):
    from ai.sre_agent import detect_incidents
    from collectors.evidence_collector import build_observability_evidence

    live_bundle = build_observability_evidence()
    incidents = detect_incidents(live_bundle, live_bundle.get("github_actions"))
    incident = next(
        (item for item in incidents if item.incident_id == incident_id),
        None,
    )
    if not incident or ROLLOUT_RESTART not in incident.eligible_remediations:
        return False
    live_images = {
        image
        for deployment in live_bundle.get("deployments", [])
        if deployment.get("namespace") == TARGET_NAMESPACE
        and deployment.get("name") == TARGET_DEPLOYMENT
        for image in deployment.get("images", [])
    }
    if not live_images or live_images != set(expected_images):
        return False
    if expected_image_digests:
        live_image_digests = incident.diagnosis.get("image_digests", {})
        if not isinstance(live_image_digests, dict):
            return False
        if {
            image: live_image_digests.get(image)
            for image in expected_images
        } != expected_image_digests:
            return False
    return True


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
                "Deployment image changed after planning; refusing to continue."
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
                    container.image for container in pod.spec.containers or []
                } == set(expected_images)
                and len(pod.status.container_statuses or [])
                == len(pod.spec.containers or [])
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


def _verify_application_health(core_api):
    response = core_api.connect_get_namespaced_service_proxy_with_path(
        name="ai-k8s-service",
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


def _collect_post_action_events(core_api, action_started_at):
    from ai.safety import redact_sensitive_values

    pods = core_api.list_namespaced_pod(
        namespace=TARGET_NAMESPACE,
        label_selector=f"app={TARGET_DEPLOYMENT}",
        _request_timeout=(5, 20),
    )
    pod_names = {pod.metadata.name for pod in pods.items}
    response = core_api.list_namespaced_event(
        namespace=TARGET_NAMESPACE,
        _request_timeout=(5, 20),
    )
    events = []
    for event in response.items:
        involved = getattr(event, "involved_object", None)
        if not involved or involved.name not in pod_names:
            continue
        timestamp = (
            getattr(event, "event_time", None)
            or getattr(event, "last_timestamp", None)
            or getattr(event, "first_timestamp", None)
        )
        if timestamp and timestamp.replace(tzinfo=timezone.utc) < action_started_at:
            continue
        reason = str(getattr(event, "reason", "") or "Unknown")
        message = redact_sensitive_values(
            str(getattr(event, "message", "") or "")
        )[:500]
        event_type = str(getattr(event, "type", "") or "Unknown")
        events.append({
            "pod": involved.name,
            "type": event_type,
            "reason": reason,
            "message": message,
        })
    blocking = [
        event
        for event in events
        if event["type"].lower() == "warning"
        and any(marker in event["reason"].lower() for marker in BLOCKING_EVENT_REASONS)
    ]
    return {"status": "available", "events": events[:30], "blocking_warnings": blocking}


def _collect_post_change_grafana():
    from requests.exceptions import RequestException

    try:
        from collectors.grafana_metrics_collector import collect_grafana_metrics
        from collectors.kubernetes_collector import get_pods

        result = collect_grafana_metrics(
            get_pods(TARGET_NAMESPACE),
            TARGET_NAMESPACE,
            TARGET_DEPLOYMENT,
        )
    except (
        KeyError,
        OSError,
        RequestException,
        RuntimeError,
        TypeError,
        ValueError,
        AttributeError,
    ) as error:
        return {
            "grafana_metrics": f"unavailable ({type(error).__name__})",
            "grafana_observations": [],
        }
    if not isinstance(result, dict):
        return {
            "grafana_metrics": "unavailable (invalid collector response)",
            "grafana_observations": [],
        }
    cluster_metrics = result.get("cluster_metrics")
    pod_metrics = result.get("pod_metrics")
    if not isinstance(cluster_metrics, list) or not isinstance(pod_metrics, dict):
        return {
            "grafana_metrics": "unavailable (invalid collector response)",
            "grafana_observations": [],
        }
    records = list(cluster_metrics)
    records.extend(
        metric
        for pod_metric_list in pod_metrics.values()
        if isinstance(pod_metric_list, list)
        for metric in pod_metric_list
        if isinstance(metric, dict)
    )
    relevant = {
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
        for metric in records
        if isinstance(metric, dict) and metric.get("metric") in relevant
    ][:20]
    return {
        "grafana_metrics": (
            "available"
            if any(metric.get("status") == "available" for metric in observations)
            else "unavailable"
        ),
        "grafana_observations": observations,
    }


def _grafana_reports_failure(observations):
    for metric in observations:
        value = metric.get("value")
        if metric.get("status") != "available" or not isinstance(value, (int, float)):
            continue
        if metric.get("metric") == "application.health_status" and value == 0:
            return True
        if metric.get("metric") == "application.error_rate" and value > 0:
            return True
        if (
            metric.get("metric") == "deployment.unavailable_replicas"
            and value > 0
        ):
            return True
    return False


def _fresh_failure_diagnosis(incident_id):
    from ai.sre_agent import analyze_incidents
    from collectors.evidence_collector import build_observability_evidence

    bundle = build_observability_evidence()
    incidents = analyze_incidents(bundle, bundle.get("github_actions"))
    incident = next(
        (item for item in incidents if item.incident_id == incident_id),
        None,
    )
    if not incident:
        return "Fresh evidence no longer detects the original incident."
    diagnosis = incident.diagnosis.get("root_cause") or "No new root cause is confirmed."
    return (
        f"Fresh evidence: {diagnosis}. "
        f"Missing evidence: {'; '.join(incident.diagnosis.get('missing_evidence', [])) or 'none reported'}."
    )


def execute_plan(plan, plan_digest, live_incident_check=None, apps_api=None, core_api=None):
    """Apply one allowlisted patch and stop on any failed verification."""
    if (
        os.getenv("GITHUB_ACTIONS") != "true"
        or os.getenv("AUTO_REMEDIATION_SELECTED") != "true"
    ):
        raise RemediationValidationError(
            "Execution is permitted only in the policy-selected remediation job."
        )
    if (
        plan.get("action") not in ALLOWED_ACTIONS
        or plan.get("namespace") != TARGET_NAMESPACE
        or plan.get("target") != TARGET_DEPLOYMENT
    ):
        raise RemediationValidationError("Operation does not match the allowlisted target.")
    if not plan_digest or plan_digest != _plan_digest(plan):
        raise RemediationValidationError("Execution plan digest does not match validated evidence.")
    active = (
        live_incident_check(plan["incident_id"])
        if live_incident_check is not None
        else _live_incident_is_active(
            plan["incident_id"],
            plan["expected_images"],
            plan.get("expected_image_digests"),
        )
    )
    if not active:
        raise RemediationValidationError(
            "The original policy-eligible incident is no longer active in fresh evidence."
        )
    if apps_api is None or core_api is None:
        from kubernetes import client, config

        config.load_kube_config()
        apps_api = apps_api or client.AppsV1Api()
        core_api = core_api or client.CoreV1Api()

    action_started_at = datetime.now(timezone.utc)
    restart_time = action_started_at.isoformat(timespec="seconds")
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
        from kubernetes.client.rest import ApiException
        from requests.exceptions import RequestException

        if MAX_ROLLOUT_ATTEMPTS != 1:
            raise RemediationValidationError("Unexpected automatic retry policy.")
        apps_api.patch_namespaced_deployment(
            name=TARGET_DEPLOYMENT,
            namespace=TARGET_NAMESPACE,
            body=patch,
            _request_timeout=(5, 20),
        )
        rollout = _wait_for_rollout(
            apps_api,
            core_api,
            plan["expected_images"],
            plan.get("expected_image_digests"),
        )
        _verify_application_health(core_api)
        events = _collect_post_action_events(core_api, action_started_at)
        if events["blocking_warnings"]:
            raise RemediationValidationError(
                "Post-action Kubernetes events still report a workload failure."
            )
        grafana = _collect_post_change_grafana()
        if _grafana_reports_failure(grafana["grafana_observations"]):
            raise RemediationValidationError(
                "Post-action Grafana metrics still report an application or rollout failure."
            )
    except (
        ApiException,
        RemediationValidationError,
        RequestException,
        OSError,
        RuntimeError,
        ValueError,
        TimeoutError,
    ) as error:
        if isinstance(error, ApiException):
            detail = f"Kubernetes API returned HTTP {error.status or 'unknown'}."
        elif isinstance(error, RemediationValidationError):
            detail = str(error)
        elif isinstance(error, RequestException):
            detail = "A required verification service was unavailable."
        else:
            detail = f"Action or verification failed ({type(error).__name__})."
        try:
            fresh_diagnosis = _fresh_failure_diagnosis(plan["incident_id"])
        except (
            ApiException,
            OSError,
            RequestException,
            RuntimeError,
            ValueError,
            TimeoutError,
        ):
            fresh_diagnosis = "Fresh read-only evidence collection was unavailable."
        raise RemediationValidationError(
            "The single permitted action may already have been applied; stop and do not retry. "
            f"{detail} {fresh_diagnosis}"
        ) from error

    return {
        "status": "recovered",
        "incident_id": plan["incident_id"],
        "action": plan["action"],
        "target": f"{TARGET_NAMESPACE}/{TARGET_DEPLOYMENT}",
        "ready_replicas": rollout["ready_replicas"],
        "verified_images": rollout["images"],
        "image_ids": rollout["image_ids"],
        "application_health": "healthy",
        "kubernetes_events": events,
        **grafana,
        "restart_annotation": restart_time,
    }


def _publish_execution_report(result):
    events = result["kubernetes_events"]["events"]
    lines = [
        "## Automatic remediation result",
        f"- Status: **{result['status']}**",
        f"- Incident: `{result['incident_id']}`",
        f"- Operation: `{result['action']}`",
        f"- Target: `{result['target']}`",
        f"- Ready replicas: {result['ready_replicas']}",
        f"- Verified images: {', '.join(result['verified_images'])}",
        f"- Runtime image IDs: {', '.join(result['image_ids'])}",
        f"- Application health endpoint: **{result['application_health']}**",
        f"- Kubernetes events checked: **{result['kubernetes_events']['status']}** "
        f"({len(events)} relevant event(s))",
        f"- Grafana metrics: **{result['grafana_metrics']}**",
        "- Verification: rollout status, ready replicas, runtime image IDs, "
        "application health, relevant Kubernetes events, and available Grafana metrics checked.",
        "- Retry policy: one bounded action; no automatic retry.",
    ]
    lines.extend(
        f"  - {event['type']} {event['reason']} on {event['pod']}: {event['message']}"
        for event in events
    )
    lines.extend(
        "- Grafana observations: "
        + (
            ", ".join(
                f"{item['metric']}={item['value']}"
                for item in result["grafana_observations"]
                if item.get("status") == "available"
            )
            or "none available"
        ),
    )
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        raise RemediationValidationError("GITHUB_STEP_SUMMARY is not available.")
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    select_parser = subparsers.add_parser("select")
    select_parser.add_argument("--evidence", required=True)
    select_parser.add_argument("--evidence-run-id", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--evidence", required=True)
    plan_parser.add_argument("--incident-id", required=True)
    plan_parser.add_argument("--evidence-run-id", required=True)
    plan_parser.add_argument("--action", required=True)
    plan_parser.add_argument("--plan-output", required=True)

    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--evidence", required=True)
    execute_parser.add_argument("--incident-id", required=True)
    execute_parser.add_argument("--evidence-run-id", required=True)
    execute_parser.add_argument("--action", required=True)
    execute_parser.add_argument("--plan-sha256", required=True)

    args = parser.parse_args()
    try:
        if args.mode == "select":
            selection = select_automatic_action(args.evidence, args.evidence_run_id)
            output = os.getenv("GITHUB_OUTPUT")
            if output:
                with open(output, "a", encoding="utf-8") as output_file:
                    output_file.write(f"selected={'true' if selection else 'false'}\n")
                    output_file.write(
                        f"incident_id={selection['incident_id'] if selection else ''}\n"
                    )
                    output_file.write(
                        f"action={selection['action'] if selection else ''}\n"
                    )
            if selection:
                print(
                    f"Selected {selection['action']} for {selection['incident_id']} "
                    "from the deterministic evidence policy."
                )
            else:
                print("No single incident meets the automatic remediation policy.")
                summary_path = os.getenv("GITHUB_STEP_SUMMARY")
                if summary_path:
                    with open(summary_path, "a", encoding="utf-8") as summary:
                        summary.write(
                            "## Automatic remediation decision\n"
                            "- Status: **report only**\n"
                            "- No single incident met the strict evidence policy; no action was selected.\n"
                        )
            return 0

        plan, _ = validate_plan(
            args.evidence,
            args.incident_id,
            args.action,
            args.evidence_run_id,
        )
        if args.mode == "plan":
            _write_plan(
                plan,
                os.getenv("GITHUB_STEP_SUMMARY"),
                args.plan_output,
            )
            return 0
        if args.plan_sha256 != _plan_digest(plan):
            raise RemediationValidationError(
                "Execution plan digest does not match revalidated evidence."
            )
        result = execute_plan(plan, args.plan_sha256)
        _publish_execution_report(result)
        return 0
    except (RemediationValidationError, OSError, ValueError) as error:
        print(f"Automatic remediation refused or failed: {error}", file=sys.stderr)
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if summary_path and args.mode != "select":
            with open(summary_path, "a", encoding="utf-8") as summary:
                summary.write(
                    "## Automatic remediation result\n"
                    "- Status: **needs further investigation**\n"
                    f"- Detail: {error}\n"
                    "- No retry was attempted. The operation may already have been applied; "
                    "inspect the workload and events before taking further action.\n"
                )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
