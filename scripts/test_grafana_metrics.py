import json

from ai.safety import redact_sensitive_values
from collectors.grafana_metrics_collector import (
    GrafanaPrometheusError,
    load_grafana_config,
    query_prometheus,
    resolve_cluster_label,
)


def _check_series(description, query, required_labels=()):
    try:
        results = query_prometheus(query)
    except GrafanaPrometheusError as error:
        print(
            f"FAIL {description}: "
            f"{redact_sensitive_values(str(error))}"
        )
        return False

    if not results:
        print(
            f"FAIL {description}: no series returned. Check Grafana Cloud "
            "endpoint/authentication, cluster and namespace labels, Alloy "
            "health, and the scrape configuration."
        )
        return False

    if required_labels and not any(
        all(
            label in result.get("metric", {})
            for label in required_labels
        )
        for result in results
    ):
        print(
            f"FAIL {description}: series were returned but none had the "
            f"expected identity labels {', '.join(required_labels)}."
        )
        return False

    print(f"PASS {description}: {len(results)} series returned.")
    return True


def main():
    """Verify read access, the configured cluster label, and useful GKE series."""
    try:
        config = load_grafana_config()
        up_results = query_prometheus("up", config)
    except GrafanaPrometheusError as error:
        print(
            "Grafana Cloud Prometheus check failed: "
            f"{redact_sensitive_values(str(error))}"
        )
        return 1

    if not up_results:
        print(
            "Grafana Cloud Prometheus returned no `up` series. Check the "
            "query endpoint, a metrics:read token, Grafana username, and "
            "whether Alloy is remote-writing data."
        )
        return 1

    try:
        cluster_label = resolve_cluster_label(up_results, config.cluster)
    except GrafanaPrometheusError as error:
        print(
            "Grafana Cloud returned `up` series but the configured cluster "
            "could not be matched: "
            f"{redact_sensitive_values(str(error))}"
        )
        return 1

    print(
        f"PASS `up`: {len(up_results)} series; cluster "
        f"{config.cluster!r} matched returned label {cluster_label!r}."
    )
    cluster_selector = (
        f"{cluster_label}={json.dumps(config.cluster, ensure_ascii=True)}"
    )
    namespace_selector = (
        f'{cluster_selector},namespace="ai-troubleshooter",'
        'pod=~"ai-k8s-demo-.*"'
    )
    queries = (
        (
            "node CPU capacity (kube-state-metrics)",
            f'kube_node_status_capacity{{{cluster_selector},resource="cpu"}}',
            ("node",),
        ),
        (
            "node memory capacity (kube-state-metrics)",
            f'kube_node_status_capacity{{{cluster_selector},resource="memory"}}',
            ("node",),
        ),
        (
            "node CPU usage (Kubelet/cAdvisor)",
            "sum by (instance) (rate(container_cpu_usage_seconds_total{"
            f'{cluster_selector},container!="",pod!=""}}[5m]))',
            ("instance",),
        ),
        (
            "node memory working set (Kubelet/cAdvisor)",
            "sum by (instance) (container_memory_working_set_bytes{"
            f'{cluster_selector},container!="",pod!=""}})',
            ("instance",),
        ),
        (
            "application pod inventory (kube-state-metrics)",
            f"kube_pod_info{{{namespace_selector}}}",
            ("pod",),
        ),
        (
            "application pod CPU (Kubelet/cAdvisor)",
            "sum by (pod, container) (rate(container_cpu_usage_seconds_total{"
            f'{namespace_selector},container!=""}}[5m]))',
            ("pod", "container"),
        ),
        (
            "application pod memory (Kubelet/cAdvisor)",
            "sum by (pod, container) (container_memory_working_set_bytes{"
            f'{namespace_selector},container!=""}})',
            ("pod", "container"),
        ),
    )
    checks = [
        _check_series(description, query, required_labels)
        for description, query, required_labels in queries
    ]
    if not all(checks):
        print(
            "One or more expected series are unavailable. Check the pinned "
            "Kubernetes Monitoring features, KSM/cAdvisor targets, pod "
            "annotations, and actual labels in Grafana Explore."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
