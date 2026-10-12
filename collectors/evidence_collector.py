from ai.analyzer import KubernetesAnalyzer
from collectors.kubernetes_collector import (
    get_events,
    get_pods,
    load_kubernetes_config,
)
from collectors.logs_collector import get_all_pod_logs
from collectors.grafana_metrics_collector import (
    get_node_cpu_usage,
    get_node_memory_usage,
    load_grafana_config,
)
from models.evidence import IncidentEvidence


TARGET_NAMESPACE = "ai-troubleshooter"


def extract_error_lines(log_text, max_lines=5):
    """Extract important error/failure lines from container logs."""

    if not isinstance(log_text, str):
        return []

    important_lines = []

    for line in log_text.splitlines():

        line_lower = line.lower()

        if any(
            keyword in line_lower
            for keyword in [
                "error",
                "failed",
                "failure",
                "backoff",
                "oom",
                "out of memory",
                "crashloop",
                "unhealthy",
            ]
        ):
            important_lines.append(line.strip())

        if len(important_lines) >= max_lines:
            break

    return important_lines


def build_evidence():
    """Combine Kubernetes and Grafana evidence."""

    # Ensure Kubernetes configuration is loaded before API calls.
    load_kubernetes_config()

    # Kubernetes evidence
    pods = get_pods()
    pods = [
        pod for pod in pods
        if pod.get("namespace") == TARGET_NAMESPACE
    ]
    events = get_events()
    logs = get_all_pod_logs()

    # Grafana Cloud node metrics
    grafana_config = load_grafana_config()

    node_cpu = get_node_cpu_usage(grafana_config)
    node_memory = get_node_memory_usage(grafana_config)

    evidence_list = []

    for pod in pods:

        namespace = pod.get("namespace")
        pod_name = pod.get("name")

        # -----------------------------------------
        # Collect events for this pod
        # -----------------------------------------

        pod_events = []

        for event in events:

            if (
                event.get("namespace") == namespace
                and event.get("object") == pod_name
            ):

                reason = event.get("reason") or "Unknown"
                message = event.get("message") or "No message provided"

                pod_events.append(
                    f"{reason}: {message}"
                )

        # -----------------------------------------
        # Collect important log lines
        # -----------------------------------------

        pod_logs = []

        for log_entry in logs:

            if (
                isinstance(log_entry, dict)
                and log_entry.get("namespace") == namespace
                and log_entry.get("pod") == pod_name
            ):

                log_text = log_entry.get("logs")

                error_lines = extract_error_lines(
                    log_text,
                    max_lines=5,
                )

                pod_logs.extend(error_lines)

        # Remove duplicate log lines
        pod_logs = list(dict.fromkeys(pod_logs))

        # -----------------------------------------
        # Create evidence object
        # -----------------------------------------

        evidence = IncidentEvidence(
            namespace=namespace,
            pod=pod_name,
            status=pod.get("phase"),
            restarts=pod.get("restarts", 0),
            cpu=node_cpu,
            memory=node_memory,
            events=pod_events,
            logs=pod_logs,
            last_termination_reason=pod.get("last_termination_reason"),
            last_exit_code=pod.get("last_exit_code"),
            last_termination_message=pod.get("last_termination_message"),
        )

        evidence_list.append(evidence)

    return evidence_list


def main():
    """Collect and analyze Kubernetes incident evidence."""

    load_kubernetes_config()

    evidence = build_evidence()

    analyzer = KubernetesAnalyzer()

    print(
        f"\nCollected evidence for {len(evidence)} pods."
    )

    for item in evidence:

        # Only show pods with potential incident evidence
        if (
            item.restarts > 0
            or item.events
            or item.logs
        ):

            print("\n" + "=" * 60)

            print(
                f"Pod: {item.namespace}/{item.pod}"
            )

            print(
                f"Status: {item.status}"
            )

            print(
                f"Restarts: {item.restarts}"
            )

            print(
                f"Node CPU: "
                f"{item.cpu:.3f} cores"
                if item.cpu is not None
                else "Node CPU: No data"
            )

            print(
                f"Node Memory: "
                f"{item.memory / (1024 ** 3):.3f} GB"
                if item.memory is not None
                else "Node Memory: No data"
            )

            findings = analyzer.analyze(item)

            print("\nAI Troubleshooter Findings:")

            if findings:

                for finding in findings:
                    print(f"- {finding}")

            else:

                print("- No problems detected.")


if __name__ == "__main__":
    main()