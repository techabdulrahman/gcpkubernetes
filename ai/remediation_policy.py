"""Deterministic evidence gates for automatic Kubernetes remediation."""

import re
from datetime import datetime, timedelta, timezone


TARGET_NAMESPACE = "ai-troubleshooter"
TARGET_WORKLOAD = "ai-k8s-demo"
ROLLOUT_RESTART = "rollout_restart"

_BLOCKED_REASONS = {
    "crashloopbackoff",
    "containercreating",
    "createcontainerconfigerror",
    "error",
    "errimagepull",
    "imagepullbackoff",
    "oomkilled",
    "runcontainererror",
}
_TRANSIENT_NODE_MARKERS = (
    "nodenotready",
    "nodeshutdown",
    "node is not ready",
    "node is unreachable",
    "node.kubernetes.io/unreachable",
)
_BLOCKED_EVENT_MARKERS = (
    "backoff",
    "failed scheduling",
    "failedcreatepodsandbox",
    "imagepull",
    "liveness probe",
    "oomkilled",
    "readiness probe",
    "network plugin",
)


def _replica_limit(value, desired, *, round_up=False):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(value, str) and value.endswith("%"):
        try:
            percent = int(value[:-1])
        except ValueError:
            return None
        if percent < 0:
            return None
        scaled = desired * percent / 100
        return int(scaled + (0.999999 if round_up else 0))
    return None


def _fresh(timestamp):
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return False
        age = datetime.now(timezone.utc) - observed
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False
    return timedelta(0) <= age <= timedelta(minutes=15)


def restart_is_evidence_eligible(evidence, incident):
    """Permit one restart only for a corroborated transient node failure."""
    eligible_remediations = (
        incident.get("eligible_remediations")
        if isinstance(incident, dict)
        else None
    )
    if (
        not isinstance(evidence, dict)
        or not isinstance(incident, dict)
        or incident.get("namespace") != TARGET_NAMESPACE
        or incident.get("workload") != TARGET_WORKLOAD
        or incident.get("category") not in {"failed_rollout", "unready_pod"}
        or not isinstance(eligible_remediations, list)
        or ROLLOUT_RESTART not in eligible_remediations
    ):
        return False
    diagnosis = incident.get("diagnosis")
    if not isinstance(diagnosis, dict):
        return False

    source_status = incident.get("source_status")
    if (
        not isinstance(source_status, dict)
        or source_status.get("kubernetes") != "available"
        or source_status.get("grafana") != "available"
    ):
        return False

    deployments = evidence.get("deployments")
    if not isinstance(deployments, list):
        return False
    deployment_matches = [
        deployment
        for deployment in deployments
        if isinstance(deployment, dict)
        and deployment.get("namespace") == TARGET_NAMESPACE
        and deployment.get("name") == TARGET_WORKLOAD
    ]
    if len(deployment_matches) != 1:
        return False
    deployment = deployment_matches[0]
    desired = deployment.get("desired_replicas")
    available = deployment.get("available_replicas")
    unavailable = deployment.get("unavailable_replicas")
    generation = deployment.get("generation")
    observed_generation = deployment.get("observed_generation")
    if (
        not isinstance(desired, int)
        or isinstance(desired, bool)
        or desired < 2
        or not isinstance(available, int)
        or isinstance(available, bool)
        or available < 1
        or not isinstance(unavailable, int)
        or isinstance(unavailable, bool)
        or unavailable < 1
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or observed_generation != generation
        or not isinstance(deployment.get("images"), list)
        or not deployment["images"]
        or any(
            not isinstance(image, str) or not image
            for image in deployment["images"]
        )
        or deployment.get("strategy_type") != "RollingUpdate"
    ):
        return False
    max_unavailable = _replica_limit(
        deployment.get("max_unavailable"), desired
    )
    max_surge = _replica_limit(
        deployment.get("max_surge"), desired, round_up=True
    )
    if (
        max_unavailable is None
        or max_unavailable > 1
        or max_unavailable >= desired
        or max_surge is None
        or max_surge < 1
    ):
        return False
    expected_images = diagnosis.get("deployed_images") or diagnosis.get("images")
    image_digests = diagnosis.get("image_digests")
    if (
        not isinstance(expected_images, list)
        or not expected_images
        or any(not isinstance(image, str) or not image for image in expected_images)
        or sorted(set(expected_images)) != sorted(set(deployment["images"]))
        or not isinstance(image_digests, dict)
        or any(
            not isinstance(image_digests.get(image), str)
            or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image_digests[image])
            for image in expected_images
        )
    ):
        return False

    evidence_pods = evidence.get("pods")
    if not isinstance(evidence_pods, list):
        return False
    pods = [
        pod
        for pod in evidence_pods
        if isinstance(pod, dict)
        and pod.get("namespace") == TARGET_NAMESPACE
        and pod.get("workload") == TARGET_WORKLOAD
        and pod.get("ready") is False
    ]
    ready_pods = [
        pod
        for pod in evidence_pods
        if isinstance(pod, dict)
        and pod.get("namespace") == TARGET_NAMESPACE
        and pod.get("workload") == TARGET_WORKLOAD
        and pod.get("ready") is True
    ]
    if len(ready_pods) < available:
        return False
    for pod in ready_pods:
        containers = pod.get("containers")
        if not isinstance(containers, list) or not containers:
            return False
        for container in containers:
            if not isinstance(container, dict):
                return False
            image = container.get("image")
            image_id = str(container.get("image_id") or "")
            match = re.search(r"sha256:[0-9a-fA-F]{64}", image_id)
            if (
                image not in image_digests
                or not match
                or match.group(0).lower() != image_digests[image].lower()
            ):
                return False
    transient_pod_confirmed = False
    for pod in pods:
        pod_reasons = pod.get("state_reasons")
        containers = pod.get("containers")
        pod_events = pod.get("events")
        if (
            not isinstance(pod_reasons, list)
            or not isinstance(containers, list)
            or not all(isinstance(container, dict) for container in containers)
            or not isinstance(pod_events, list)
        ):
            return False
        reasons = {
            str(reason).lower()
            for reason in pod_reasons
        }
        reasons.update(
            str(container.get("state_reason") or "").lower()
            for container in containers
        )
        reasons.update(
            str(container.get("last_termination_reason") or "").lower()
            for container in containers
        )
        if reasons & _BLOCKED_REASONS or pod.get("last_termination_reason"):
            return False
        pod_sources = pod.get("source_status")
        if (
            not isinstance(pod_sources, dict)
            or pod_sources.get("container_logs") != "available"
        ):
            return False
        event_text = " ".join(str(event).lower() for event in pod_events)
        if any(marker in event_text for marker in _BLOCKED_EVENT_MARKERS):
            return False
        if any(marker in event_text for marker in _TRANSIENT_NODE_MARKERS):
            transient_pod_confirmed = True
    if not transient_pod_confirmed:
        return False

    metric_records = evidence.get("cluster_metrics")
    if not isinstance(metric_records, list):
        return False
    fresh_metrics = [
        metric
        for metric in metric_records
        if isinstance(metric, dict)
        and metric.get("status") == "available"
        and metric.get("value") is not None
        and isinstance(metric.get("value"), (int, float))
        and not isinstance(metric.get("value"), bool)
        and _fresh(metric.get("observed_at"))
    ]
    healthy_status = any(
        metric.get("metric") == "application.health_status"
        and metric.get("value") == 1
        for metric in fresh_metrics
    )
    no_application_errors = any(
        metric.get("metric") == "application.error_rate"
        and metric.get("value") == 0
        for metric in fresh_metrics
    )
    return healthy_status and no_application_errors
