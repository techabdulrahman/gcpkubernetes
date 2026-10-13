"""Combine Kubernetes records and optional, explicitly scoped Grafana metrics."""

from datetime import datetime, timezone

from ai.analyzer import KubernetesAnalyzer
from collectors.kubernetes_collector import (
    get_events,
    get_pods,
    load_kubernetes_config,
)
from collectors.logs_collector import get_all_pod_logs
from collectors.grafana_metrics_collector import collect_grafana_metrics
from ai.safety import redact_sensitive_values
from models.evidence import IncidentEvidence


TARGET_NAMESPACE = "ai-troubleshooter"
TARGET_DEPLOYMENT = "ai-k8s-demo"


def extract_error_lines(log_text, max_lines=5):
    """Extract useful failure signals from container logs."""
    if not isinstance(log_text, str):
        return []

    important_lines = []
    keywords = (
        "error",
        "failed",
        "failure",
        "backoff",
        "oom",
        "out of memory",
        "crashloop",
        "imagepull",
        "unhealthy",
        "throttl",
    )
    for line in log_text.splitlines():
        if any(keyword in line.lower() for keyword in keywords):
            important_lines.append(redact_sensitive_values(line.strip()))
        if len(important_lines) >= max_lines:
            break
    return important_lines


def build_observability_evidence():
    """Return pod evidence and separate cluster/workload-scoped metric evidence."""
    load_kubernetes_config()
    pods = get_pods(TARGET_NAMESPACE)
    events = get_events(TARGET_NAMESPACE)
    logs = get_all_pod_logs(TARGET_NAMESPACE)
    grafana = collect_grafana_metrics(
        pods,
        TARGET_NAMESPACE,
        TARGET_DEPLOYMENT,
    )
    observed_at = datetime.now(timezone.utc).isoformat()
    evidence_items = []

    for pod in pods:
        namespace = pod.get("namespace")
        pod_name = pod.get("name")
        pod_events = [
            f"[{event.get('timestamp') or 'time unavailable'}] "
            f"{event.get('reason') or 'Unknown'}: "
            f"{redact_sensitive_values(event.get('message') or 'No message provided')}"
            for event in events
            if event.get("namespace") == namespace
            and event.get("object") == pod_name
        ]
        pod_logs = []
        for log_entry in logs:
            if (
                isinstance(log_entry, dict)
                and log_entry.get("namespace") == namespace
                and log_entry.get("pod") == pod_name
            ):
                pod_logs.extend(
                    f"{log_entry.get('container') or 'container'}: {line}"
                    for line in extract_error_lines(log_entry.get("logs"))
                )
        pod_logs = list(dict.fromkeys(pod_logs))

        evidence_items.append(
            IncidentEvidence(
                cluster=grafana.get("cluster"),
                namespace=namespace,
                workload=pod.get("workload"),
                workload_kind=pod.get("workload_kind"),
                pod=pod_name,
                node=pod.get("node"),
                status=pod.get("phase"),
                ready=pod.get("ready"),
                restarts=pod.get("restarts", 0),
                containers=pod.get("containers", []),
                events=pod_events,
                logs=pod_logs,
                # Node and deployment metrics intentionally stay outside this pod.
                metrics=grafana.get("pod_metrics", {}).get(pod_name, []),
                observed_at=observed_at,
                source_status={
                    "kubernetes": "available",
                    "grafana": (
                        "available"
                        if any(
                            metric.get("status") == "available"
                            for metric in grafana.get("pod_metrics", {}).get(
                                pod_name, []
                            )
                        )
                        else "unavailable"
                    ),
                },
                last_termination_reason=pod.get("last_termination_reason"),
                last_exit_code=pod.get("last_exit_code"),
                last_termination_message=redact_sensitive_values(
                    pod.get("last_termination_message") or ""
                ) or None,
            )
        )

    return {
        "cluster": grafana.get("cluster"),
        "observed_at": observed_at,
        "items": evidence_items,
        "cluster_metrics": grafana.get("cluster_metrics", []),
        "diagnostics": grafana.get("diagnostics", []),
        "github_failure": None,
    }


def build_evidence():
    """Backward-compatible helper returning only per-pod evidence items."""
    return build_observability_evidence()["items"]


def main():
    """Collect and analyze Kubernetes evidence without mixing metric scopes."""
    evidence_bundle = build_observability_evidence()
    analyzer = KubernetesAnalyzer()

    print(f"\nCollected evidence for {len(evidence_bundle['items'])} pods.")
    for item in evidence_bundle["items"]:
        if item.restarts > 0 or item.events or item.logs or item.metrics:
            findings = analyzer.analyze(
                item,
                cluster_metrics=evidence_bundle["cluster_metrics"],
                github_failure=evidence_bundle["github_failure"],
            )
            print(f"\n{item.namespace}/{item.pod} findings:")
            for finding in findings:
                print(f"- {finding}")


if __name__ == "__main__":
    main()
