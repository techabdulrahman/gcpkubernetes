
from kubernetes import client, config
from kubernetes.client.rest import ApiException

REQUEST_TIMEOUT_SECONDS = 20


def load_kubernetes_config():
    """Load the Kubernetes configuration from the current kubeconfig."""
    try:
        config.load_kube_config()
        print("Kubernetes configuration loaded.")
    except Exception as e:
        raise RuntimeError(
            f"Unable to load Kubernetes configuration: {e}"
        ) from e


def get_pod_logs(namespace, pod_name, container=None, tail_lines=100):
    """Collect recent logs from a Kubernetes pod."""
    v1 = client.CoreV1Api()

    try:
        return v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            _request_timeout=REQUEST_TIMEOUT_SECONDS,
        )

    except ApiException as e:
        # Include the HTTP status and reason without exposing raw
        # server response bodies that might contain sensitive data.
        raise RuntimeError(
            "Unable to collect pod logs "
            f"(Kubernetes HTTP {e.status or 'unknown'}, "
            f"reason: {e.reason or 'unknown'})."
        ) from e


def get_all_pod_logs(namespace=None):
    """Collect available logs from pods in one or all namespaces."""
    v1 = client.CoreV1Api()
    results = []

    try:
        if namespace:
            pods = v1.list_namespaced_pod(
                namespace=namespace,
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )
        else:
            pods = v1.list_pod_for_all_namespaces(
                _request_timeout=REQUEST_TIMEOUT_SECONDS,
            )

    except ApiException as e:
        raise RuntimeError(
            "Unable to list pods for logs "
            f"(Kubernetes HTTP {e.status or 'unknown'}, "
            f"reason: {e.reason or 'unknown'})."
        ) from e

    for pod in pods.items:
        pod_namespace = pod.metadata.namespace
        pod_name = pod.metadata.name

        # Container statuses may be absent while a pod is being created.
        container_statuses = pod.status.container_statuses or []

        for container in container_statuses:
            container_name = container.name

            try:
                logs = get_pod_logs(
                    namespace=pod_namespace,
                    pod_name=pod_name,
                    container=container_name,
                    tail_lines=50,
                )
                log_error = None

            except RuntimeError as e:
                # One unavailable log stream must not stop collection
                # for the remaining containers.
                logs = ""
                log_error = str(e)

                print(
                    f"Warning: logs unavailable for "
                    f"{pod_namespace}/{pod_name}/{container_name}: "
                    f"{log_error}"
                )

            results.append({
                "namespace": pod_namespace,
                "pod": pod_name,
                "container": container_name,
                "logs": logs,
                "log_error": log_error,
            })

    return results


if __name__ == "__main__":
    try:
        load_kubernetes_config()

        # Verify that the API server is actually reachable.
        v1 = client.CoreV1Api()
        v1.list_namespace(
            _request_timeout=REQUEST_TIMEOUT_SECONDS
        )
        print("Connected to Kubernetes API.")

        print("\n========== CONTAINER LOGS ==========\n")

        logs = get_all_pod_logs()

        for item in logs:
            print(
                f"\n--- {item['namespace']}/"
                f"{item['pod']}/"
                f"{item['container']} ---"
            )

            if item["log_error"]:
                print(f"Log collection warning: {item['log_error']}")
            else:
                print(item["logs"])

    except Exception as e:
        print(f"Investigation failed: {e}")
        raise SystemExit(1)
