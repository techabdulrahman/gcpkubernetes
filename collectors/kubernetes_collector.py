from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException
from kubernetes.client.rest import ApiException


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
            v1.list_namespaced_pod(namespace)
            if namespace
            else v1.list_pod_for_all_namespaces()
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

            for container in container_statuses:
                terminated = (
                    container.last_state.terminated
                    if container.last_state
                    else None
                )

                details = {
                    "name": container.name,
                    "ready": container.ready,
                    "restart_count": container.restart_count,
                    "state": str(container.state),
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
                    pod.metadata.owner_references[0].name
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

    except ApiException as e:
        raise RuntimeError(f"Unable to collect pods: {e}")


def get_events(namespace=None):
    """Collect Kubernetes events from the last 15 minutes across all namespaces."""
    from datetime import datetime, timedelta, timezone

    v1 = client.CoreV1Api()
    events = []
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=15)

    try:
        response = (
            v1.list_namespaced_event(namespace)
            if namespace
            else v1.list_event_for_all_namespaces()
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
                "message": event.message,
                "type": event.type,
                "object": event.involved_object.name,
                "timestamp": timestamp.isoformat()
            })

        return events

    except ApiException as e:
        raise RuntimeError(f"Unable to collect events: {e}")


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
