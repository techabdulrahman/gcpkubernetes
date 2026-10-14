from kubernetes import client, config
from kubernetes.client.rest import ApiException

REQUEST_TIMEOUT_SECONDS = 20


def load_kubernetes_config():
    """Connect to the local Kubernetes cluster."""
    try:
        config.load_kube_config()
        print("Connected to Kubernetes cluster.")
    except Exception as e:
        raise RuntimeError(f"Unable to connect to Kubernetes: {e}")


def get_pod_logs(namespace, pod_name, container=None, tail_lines=100):
    """Collect recent logs from a Kubernetes pod."""

    v1 = client.CoreV1Api()

    try:
        logs = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            _request_timeout=REQUEST_TIMEOUT_SECONDS,
        )

        return logs

    except ApiException as e:
        raise RuntimeError(
            f"Unable to collect pod logs (Kubernetes HTTP {e.status or 'unknown'})."
        ) from e


def get_all_pod_logs(namespace=None):
    """Collect logs from pods across all namespaces."""

    v1 = client.CoreV1Api()
    results = []

    try:
        pods = (
            v1.list_namespaced_pod(
                namespace,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if namespace
            else v1.list_pod_for_all_namespaces(
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
        )

        for pod in pods.items:

            namespace = pod.metadata.namespace
            pod_name = pod.metadata.name

            container_statuses = pod.status.container_statuses or []

            for container in container_statuses:

                container_name = container.name

                logs = get_pod_logs(
                    namespace=namespace,
                    pod_name=pod_name,
                    container=container_name,
                    tail_lines=50,
                )

                results.append({
                    "namespace": namespace,
                    "pod": pod_name,
                    "container": container_name,
                    "logs": logs,
                })

        return results

    except ApiException as e:
        raise RuntimeError(
            f"Unable to list pods for logs (Kubernetes HTTP {e.status or 'unknown'})."
        ) from e


if __name__ == "__main__":

    load_kubernetes_config()

    print("\n========== CONTAINER LOGS ==========\n")

    logs = get_all_pod_logs()

    for item in logs:

        print(
            f"\n--- {item['namespace']}/"
            f"{item['pod']}/"
            f"{item['container']} ---"
        )

        print(item["logs"])
