from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException
from kubernetes.client.rest import ApiException

REQUEST_TIMEOUT_SECONDS = 20
MAX_PODS = 100
MAX_EVENTS = 500


def _int_or_string(value, default):
    if value is None:
        return default
    if isinstance(value, (int, str)) and not isinstance(value, bool):
        return value
    string_value = (
        getattr(value, "str_value", None)
        or getattr(value, "str_val", None)
    )
    if isinstance(string_value, str) and string_value:
        return string_value
    for attribute in ("int_value", "int_val", "value"):
        integer_value = getattr(value, attribute, None)
        if isinstance(integer_value, int) and not isinstance(integer_value, bool):
            return integer_value
    return None


def load_kubernetes_config():
    """Load in-cluster credentials or fall back to a local kubeconfig."""
    try:
        config.load_incluster_config()
        return
    except ConfigException:
        try:
            config.load_kube_config()
        except ConfigException as error:
            raise RuntimeError(
                "Unable to load in-cluster configuration or local kubeconfig."
            ) from error


def get_pods(namespace=None):
    """Collect pod status, restart counts, and termination details."""
    v1 = client.CoreV1Api()
    pods = []

    try:
        response = (
            v1.list_namespaced_pod(
                namespace,
                limit=MAX_PODS,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if namespace
            else v1.list_pod_for_all_namespaces(
                limit=MAX_PODS,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
        )

        for pod in response.items:
            container_statuses = pod.status.container_statuses or []
            readiness_condition = next(
                (
                    condition.status == "True"
                    for condition in (pod.status.conditions or [])
                    if condition.type == "Ready"
                ),
                None,
            )
            restarts = sum(
                container.restart_count or 0
                for container in container_statuses
            )

            containers = []
            last_termination = None
            images = {
                container.name: container.image
                for container in (pod.spec.containers or [])
            }
            state_reasons = []

            for container in container_statuses:
                waiting = (
                    container.state.waiting
                    if container.state
                    else None
                )
                running = (
                    container.state.running
                    if container.state
                    else None
                )
                terminated_now = (
                    container.state.terminated
                    if container.state
                    else None
                )
                terminated = (
                    container.last_state.terminated
                    if container.last_state
                    else None
                )
                state_reason = (
                    waiting.reason
                    if waiting
                    else terminated_now.reason
                    if terminated_now
                    else "Running"
                    if running
                    else None
                )
                if state_reason and state_reason != "Running":
                    state_reasons.append(state_reason)

                details = {
                    "name": container.name,
                    "image": images.get(container.name),
                    "ready": container.ready,
                    "restart_count": container.restart_count,
                    "state": (
                        "waiting"
                        if waiting
                        else "terminated"
                        if terminated_now
                        else "running"
                        if running
                        else "unknown"
                    ),
                    "state_reason": state_reason,
                    "state_message": (
                        (waiting.message or "")[:2_000] if waiting else None
                    ),
                    "image_id": container.image_id,
                    "last_termination_reason": (
                        terminated.reason if terminated else None
                    ),
                    "last_exit_code": (
                        terminated.exit_code if terminated else None
                    ),
                    "last_termination_message": (
                        terminated.message if terminated else None
                    ),
                }
                containers.append(details)

                if terminated and last_termination is None:
                    last_termination = terminated

            pods.append({
                "namespace": pod.metadata.namespace,
                "name": pod.metadata.name,
                "node": pod.spec.node_name,
                "workload": (
                    pod.metadata.labels.get("app")
                    if pod.metadata.labels and pod.metadata.labels.get("app")
                    else pod.metadata.owner_references[0].name
                    if pod.metadata.owner_references
                    else None
                ),
                "workload_kind": (
                    pod.metadata.owner_references[0].kind
                    if pod.metadata.owner_references
                    else None
                ),
                "phase": pod.status.phase,
                "ready": readiness_condition,
                "restarts": restarts,
                "containers": containers,
                "images": sorted(set(images.values())),
                "image_digests": sorted({
                    container.image_id
                    for container in container_statuses
                    if container.image_id
                }),
                "state_reasons": sorted(set(state_reasons)),
                "last_termination_reason": (
                    last_termination.reason if last_termination else None
                ),
                "last_exit_code": (
                    last_termination.exit_code
                    if last_termination else None
                ),
                "last_termination_message": (
                    last_termination.message
                    if last_termination else None
                ),
            })

        return pods

    except ApiException as error:
        raise RuntimeError(
            f"Unable to collect pods (Kubernetes HTTP {error.status or 'unknown'})."
        ) from error


def get_deployments(namespace):
    """Collect deployment rollout state for one namespace."""
    apps = client.AppsV1Api()
    try:
        response = apps.list_namespaced_deployment(
            namespace,
            _request_timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except ApiException as error:
        raise RuntimeError(
            "Unable to collect deployments "
            f"(Kubernetes HTTP {error.status or 'unknown'})."
        ) from error

    deployments = []
    for deployment in response.items:
        status = deployment.status
        spec = deployment.spec
        strategy = getattr(spec, "strategy", None)
        strategy_type = getattr(strategy, "type", None) or "RollingUpdate"
        rolling_update = getattr(strategy, "rolling_update", None)
        max_unavailable = (
            getattr(rolling_update, "max_unavailable", None)
            if rolling_update
            else "25%"
        )
        max_surge = (
            getattr(rolling_update, "max_surge", None)
            if rolling_update
            else "25%"
        )
        max_unavailable = _int_or_string(max_unavailable, "25%")
        max_surge = _int_or_string(max_surge, "25%")
        deployments.append({
            "namespace": deployment.metadata.namespace,
            "name": deployment.metadata.name,
            "generation": deployment.metadata.generation,
            "observed_generation": status.observed_generation,
            "desired_replicas": spec.replicas,
            "ready_replicas": status.ready_replicas or 0,
            "available_replicas": status.available_replicas or 0,
            "unavailable_replicas": status.unavailable_replicas or 0,
            "conditions": [
                {
                    "type": condition.type,
                    "status": condition.status,
                    "reason": condition.reason,
                    "message": (getattr(condition, "message", None) or "")[:2_000],
                    "last_update_time": (
                        condition.last_update_time.isoformat()
                        if condition.last_update_time
                        else None
                    ),
                }
                for condition in (status.conditions or [])
            ],
            "images": sorted({
                container.image
                for container in (spec.template.spec.containers or [])
            }),
            "strategy_type": strategy_type,
            "max_unavailable": (
                getattr(max_unavailable, "value", max_unavailable)
            ),
            "max_surge": getattr(max_surge, "value", max_surge),
        })
    return deployments


def get_replicasets(namespace):
    """Collect bounded ReplicaSet ownership, desired/ready state, and images."""
    apps = client.AppsV1Api()
    try:
        response = apps.list_namespaced_replica_set(
            namespace,
            limit=MAX_PODS,
            _request_timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except ApiException as error:
        raise RuntimeError(
            "Unable to collect ReplicaSets "
            f"(Kubernetes HTTP {error.status or 'unknown'})."
        ) from error

    replicasets = []
    for replica_set in response.items:
        status = replica_set.status
        spec = replica_set.spec
        owners = replica_set.metadata.owner_references or []
        replicasets.append({
            "namespace": replica_set.metadata.namespace,
            "name": replica_set.metadata.name,
            "owner": (
                {"kind": owners[0].kind, "name": owners[0].name}
                if owners
                else None
            ),
            "desired_replicas": spec.replicas or 0,
            "ready_replicas": status.ready_replicas or 0,
            "available_replicas": status.available_replicas or 0,
            "images": sorted({
                container.image
                for container in (spec.template.spec.containers or [])
            }),
        })
    return replicasets


def get_events(namespace=None):
    """Collect Kubernetes events from the last 15 minutes across all namespaces."""
    from datetime import datetime, timedelta, timezone

    v1 = client.CoreV1Api()
    events = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=15)

    try:
        response = (
            v1.list_namespaced_event(
                namespace,
                limit=MAX_EVENTS,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if namespace
            else v1.list_event_for_all_namespaces(
                limit=MAX_EVENTS,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
        )

        for event in response.items:
            timestamp = (
                event.last_timestamp
                or event.event_time
                or event.metadata.creation_timestamp
            )

            if timestamp is None:
                continue

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            if timestamp < cutoff or timestamp > now:
                continue

            events.append({
                "namespace": event.metadata.namespace,
                "reason": event.reason,
                "message": (event.message or "")[:2_000],
                "type": event.type,
                "object": event.involved_object.name,
                "timestamp": timestamp.isoformat()
            })

        return events

    except ApiException as error:
        raise RuntimeError(
            f"Unable to collect events (Kubernetes HTTP {error.status or 'unknown'})."
        ) from error


if __name__ == "__main__":
    load_kubernetes_config()

    print("\n========== PODS ==========\n")
    for pod in get_pods():
        print(
            f"{pod['namespace']}/{pod['name']} | "
            f"Status={pod['phase']} | "
            f"Restarts={pod['restarts']} | "
            f"Last reason={pod['last_termination_reason']} | "
            f"Exit code={pod['last_exit_code']}"
        )

    print("\n========== EVENTS ==========\n")
    for event in get_events():
        print(
            f"{event['namespace']} | "
            f"{event['reason']} | "
            f"{event['object']} | "
            f"{event['message']}"
        )
