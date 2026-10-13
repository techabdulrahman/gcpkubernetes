"""Read-only, scope-aware queries for Grafana Cloud Prometheus metrics."""

import os
import math
from dataclasses import dataclass
from datetime import datetime, timezone

import requests


PROMETHEUS_QUERY_PATH = "/api/v1/query"
REQUEST_TIMEOUT_SECONDS = 20
METRIC_SOURCE = "Grafana Cloud Prometheus"


class GrafanaPrometheusError(RuntimeError):
    """Raised when Grafana Cloud Prometheus cannot return valid data."""


@dataclass(frozen=True)
class GrafanaConfig:
    """Grafana Cloud Prometheus connection settings."""

    url: str
    username: str
    token: str
    cluster: str

    @property
    def query_url(self):
        """Accept either the /api/prom base URL or the full query endpoint."""
        base = self.url.rstrip("/")
        suffix = "/api/prom"
        if base.endswith(PROMETHEUS_QUERY_PATH):
            return base
        if base.endswith(suffix):
            return f"{base}{PROMETHEUS_QUERY_PATH}"
        return f"{base}{suffix}{PROMETHEUS_QUERY_PATH}"


def load_grafana_config():
    """Load Grafana Cloud settings without a hard-coded stack or cluster."""
    url = os.getenv("GRAFANA_PROM_URL", "").strip().rstrip("/")
    username = os.getenv("GRAFANA_USERNAME", "").strip()
    token = os.getenv("GRAFANA_TOKEN", "").strip()
    cluster = os.getenv("GRAFANA_CLUSTER", "").strip()

    missing = [
        name
        for name, value in (
            ("GRAFANA_PROM_URL", url),
            ("GRAFANA_USERNAME", username),
            ("GRAFANA_TOKEN", token),
            ("GRAFANA_CLUSTER", cluster),
        )
        if not value
    ]
    if missing:
        raise GrafanaPrometheusError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )

    return GrafanaConfig(url, username, token, cluster)


def query_prometheus(promql, config=None):
    """Run a read-only instant query using Grafana Cloud Basic Authentication."""
    config = config or load_grafana_config()
    try:
        response = requests.get(
            config.query_url,
            params={"query": promql},
            auth=(config.username, config.token),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as error:
        raise GrafanaPrometheusError(
            "Grafana Cloud Prometheus request failed; check the API URL and network."
        ) from error

    if response.status_code == 401:
        raise GrafanaPrometheusError(
            "Grafana Cloud returned HTTP 401; check the Prometheus username and token."
        )
    if response.status_code == 403:
        raise GrafanaPrometheusError(
            "Grafana Cloud returned HTTP 403; the token may lack metrics-read access."
        )
    if not response.ok:
        raise GrafanaPrometheusError(
            f"Grafana Cloud Prometheus returned HTTP {response.status_code} "
            f"for query: {promql}"
        )

    try:
        payload = response.json()
    except ValueError as error:
        raise GrafanaPrometheusError(
            f"Grafana Cloud returned invalid JSON for query: {promql}"
        ) from error

    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise GrafanaPrometheusError(
            f"Grafana Cloud returned an unsuccessful response for query: {promql}"
        )

    data = payload.get("data")
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list) or any(
        not isinstance(item, dict) for item in result
    ):
        raise GrafanaPrometheusError(
            f"Grafana Cloud returned an invalid result for query: {promql}"
        )
    return result


def resolve_cluster_label(results, expected_cluster):
    """Find the unique returned label key whose value matches GRAFANA_CLUSTER."""
    matching_keys = {
        key
        for item in results
        if isinstance(item, dict) and isinstance(item.get("metric"), dict)
        for key, value in item.get("metric", {}).items()
        if value == expected_cluster
    }
    if len(matching_keys) != 1:
        available = sorted(
            {
                f"{key}={value}"
                for item in results
                if isinstance(item, dict) and isinstance(item.get("metric"), dict)
                for key, value in item.get("metric", {}).items()
                if key.lower() in {"cluster", "cluster_name", "clustername"}
            }
        )
        observed = ", ".join(available) if available else "no cluster labels observed"
        raise GrafanaPrometheusError(
            f"GRAFANA_CLUSTER did not resolve to one unique label in the returned "
            f"up series ({observed}). Check the configured cluster name and labels."
        )
    return next(iter(matching_keys))


def _promql_quote(value):
    """Escape a Prometheus string-label value."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _metric_record(name, value, unit, scope, query, labels, status="available", diagnostic=None):
    return {
        "metric": name,
        "value": value,
        "unit": unit,
        "scope": scope,
        "source": METRIC_SOURCE,
        "query": query,
        "status": status,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "labels": labels,
        "diagnostic": diagnostic,
    }


def _query_metric(config, query, metric_name, unit, scope):
    """Return explicit metric records; empty vectors remain unavailable, not zero."""
    try:
        result = query_prometheus(query, config)
    except GrafanaPrometheusError as error:
        return [
            _metric_record(
                metric_name, None, unit, scope, query, {},
                status="unavailable", diagnostic=str(error)
            )
        ]

    if not result:
        return [
            _metric_record(
                metric_name,
                None,
                unit,
                scope,
                query,
                {},
                status="unavailable",
                diagnostic=(
                    f"No series returned for query. Check endpoint, cluster/namespace "
                    f"labels, credentials, and scrape configuration. Query: {query}"
                ),
            )
        ]

    records = []
    for item in result:
        labels = item.get("metric", {})
        if not isinstance(labels, dict):
            labels = {}
        raw_value = item.get("value", [None, None])
        try:
            value = float(raw_value[1])
        except (IndexError, TypeError, ValueError):
            value = None
        if value is not None and not math.isfinite(value):
            value = None
        records.append(
            _metric_record(
                metric_name,
                value,
                unit,
                scope,
                query,
                labels,
                status="available" if value is not None else "unavailable",
                diagnostic=None if value is not None else "Prometheus returned no numeric sample.",
            )
        )
    return records


def _derive_node_utilization(metrics):
    """Derive node percentages only when matching numerator/denominator exist."""
    by_name = {}
    for metric in metrics:
        if metric.get("status") == "available" and metric.get("value") is not None:
            by_name.setdefault(metric["metric"], []).append(metric)

    def matching_value(metric_name, labels):
        for metric in by_name.get(metric_name, []):
            if metric.get("labels", {}).get("instance") == labels.get("instance"):
                return metric["value"]
        return None

    derived = []
    for usage in by_name.get("node.cpu_usage", []):
        cores = matching_value("node.cpu_cores", usage["labels"])
        if cores and cores > 0:
            derived.append(
                _metric_record(
                    "node.cpu_utilization_percent",
                    usage["value"] * 100 / cores,
                    "percent",
                    "node",
                    "node.cpu_usage / node.cpu_cores * 100",
                    usage["labels"],
                )
            )

    for total in by_name.get("node.memory_total", []):
        available = matching_value("node.memory_available", total["labels"])
        if available is not None and total["value"] > 0:
            working_set = total["value"] - available
            derived.extend(
                (
                    _metric_record(
                        "node.memory_working_set",
                        working_set,
                        "bytes",
                        "node",
                        "node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes",
                        total["labels"],
                    ),
                    _metric_record(
                        "node.memory_utilization_percent",
                        working_set * 100 / total["value"],
                        "percent",
                        "node",
                        "(MemTotal - MemAvailable) / MemTotal * 100",
                        total["labels"],
                    ),
                )
            )
    return derived


def collect_grafana_metrics(
    pods,
    namespace,
    deployment_name,
    config=None,
    include_unmatched_container_metrics=False,
):
    """Collect optional metrics, separated by node, container, pod, workload, app scope."""
    try:
        config = config or load_grafana_config()
        up_results = query_prometheus("up", config)
        cluster_label = resolve_cluster_label(up_results, config.cluster)
    except GrafanaPrometheusError as error:
        diagnostic = str(error)
        unavailable = _metric_record(
            "grafana_connection",
            None,
            "status",
            "cluster",
            "up",
            {},
            status="unavailable",
            diagnostic=diagnostic,
        )
        return {
            "cluster": config.cluster if config else os.getenv("GRAFANA_CLUSTER"),
            "cluster_label": None,
            "cluster_metrics": [unavailable],
            "pod_metrics": {},
            "diagnostics": [diagnostic],
        }

    cluster_filter = f"{cluster_label}={_promql_quote(config.cluster)}"
    namespace_filter = f'namespace={_promql_quote(namespace)}'
    filters = f"{{{cluster_filter},{namespace_filter}}}"
    cluster_selector = f"{{{cluster_filter}}}"

    metric_specs = [
        ("node.cpu_cores", f"count by (instance) (node_cpu_seconds_total{{mode=\"idle\",{cluster_filter}}})", "cores", "node", "cluster"),
        ("node.cpu_usage", f"sum by (instance) (rate(node_cpu_seconds_total{{mode!=\"idle\",{cluster_filter}}}[5m]))", "cores", "node", "cluster"),
        ("node.memory_total", f"node_memory_MemTotal_bytes{cluster_selector}", "bytes", "node", "cluster"),
        ("node.memory_available", f"node_memory_MemAvailable_bytes{cluster_selector}", "bytes", "node", "cluster"),
        ("container.cpu_usage", f"rate(container_cpu_usage_seconds_total{filters[:-1]},container!=\"\"}}[5m])", "cores", "container", "namespace"),
        ("container.memory_working_set", f"container_memory_working_set_bytes{filters[:-1]},container!=\"\"}}", "bytes", "container", "namespace"),
        ("container.memory_limit", f"container_spec_memory_limit_bytes{filters[:-1]},container!=\"\"}}", "bytes", "container", "namespace"),
        ("container.cpu_throttled_seconds", f"rate(container_cpu_cfs_throttled_seconds_total{filters[:-1]},container!=\"\"}}[5m])", "seconds/second", "container", "namespace"),
        ("pod.container_restarts", f"kube_pod_container_status_restarts_total{filters}", "restarts", "container", "namespace"),
        ("pod.container_ready", f"kube_pod_container_status_ready{filters}", "boolean", "container", "namespace"),
        ("deployment.desired_replicas", f'kube_deployment_spec_replicas{{{cluster_filter},{namespace_filter},deployment={_promql_quote(deployment_name)}}}', "replicas", "deployment", "namespace"),
        ("deployment.available_replicas", f'kube_deployment_status_replicas_available{{{cluster_filter},{namespace_filter},deployment={_promql_quote(deployment_name)}}}', "replicas", "deployment", "namespace"),
        ("deployment.unavailable_replicas", f'kube_deployment_status_replicas_unavailable{{{cluster_filter},{namespace_filter},deployment={_promql_quote(deployment_name)}}}', "replicas", "deployment", "namespace"),
        ("application.request_rate", f'sum by (method, endpoint, status) (rate(http_requests_total{{{cluster_filter},{namespace_filter}}}[5m]))', "requests/second", "application", "namespace"),
        ("application.error_rate", f'sum by (method, endpoint) (rate(http_requests_total{{{cluster_filter},{namespace_filter},status=~"5.."}}[5m]))', "requests/second", "application", "namespace"),
        ("application.latency_p95", f'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{{{cluster_filter},{namespace_filter}}}[5m])))', "seconds", "application", "namespace"),
    ]

    cluster_metrics = []
    pod_metrics = {pod.get("name"): [] for pod in pods if pod.get("name")}
    diagnostics = []
    for name, query, unit, scope, grouping in metric_specs:
        records = _query_metric(config, query, name, unit, scope)
        if grouping == "cluster":
            cluster_metrics.extend(records)
            continue
        if scope in {"deployment", "application"}:
            cluster_metrics.extend(records)
            continue
        for record in records:
            labels = record["labels"]
            if (
                record["status"] == "unavailable"
                and not labels
                and scope == "container"
            ):
                for pod_name in pod_metrics:
                    pod_metrics[pod_name].append(record.copy())
                continue
            if grouping == "namespace" and not labels.get("pod"):
                if scope in {"deployment", "application"}:
                    cluster_metrics.append(record)
                    continue
                record["status"] = "unavailable"
                record["diagnostic"] = (
                    "Returned series lacks a pod label; cannot safely correlate it to a pod."
                )
                diagnostics.append(record["diagnostic"])
                if include_unmatched_container_metrics:
                    cluster_metrics.append(record)
                continue
            pod_name = labels.get("pod")
            if pod_name in pod_metrics:
                pod_metrics[pod_name].append(record)
            elif include_unmatched_container_metrics:
                cluster_metrics.append(record)
            else:
                diagnostics.append(
                    f"{name} returned a series without a known pod label; "
                    "it was not assigned to a pod."
                )

    cluster_metrics.extend(_derive_node_utilization(cluster_metrics))
    return {
        "cluster": config.cluster,
        "cluster_label": cluster_label,
        "cluster_metrics": cluster_metrics,
        "pod_metrics": pod_metrics,
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }


def get_node_cpu_usage(config=None):
    """Legacy helper returning node CPU cores used, without pod attribution."""
    config = config or load_grafana_config()
    cluster_label = resolve_cluster_label(
        query_prometheus("up", config),
        config.cluster,
    )
    records = _query_metric(
        config,
        "sum(rate(node_cpu_seconds_total{"
        f"mode!=\"idle\",{cluster_label}={_promql_quote(config.cluster)}"
        "}[5m]))",
        "node.cpu_usage",
        "cores",
        "node",
    )
    values = [record["value"] for record in records if record["value"] is not None]
    return sum(values) if values else None


def get_node_memory_usage(config=None):
    """Legacy helper returning node working set bytes, without pod attribution."""
    config = config or load_grafana_config()
    cluster_label = resolve_cluster_label(
        query_prometheus("up", config),
        config.cluster,
    )
    selector = f"{{{cluster_label}={_promql_quote(config.cluster)}}}"
    total = query_prometheus(f"sum(node_memory_MemTotal_bytes{selector})", config)
    available = query_prometheus(
        f"sum(node_memory_MemAvailable_bytes{selector})",
        config,
    )
    if not total or not available:
        return None
    try:
        return float(total[0]["value"][1]) - float(available[0]["value"][1])
    except (IndexError, TypeError, ValueError):
        return None


def main():
    """Verify access using actual returned labels and print no credentials."""
    try:
        config = load_grafana_config()
        result = query_prometheus("up", config)
        label = resolve_cluster_label(result, config.cluster)
    except GrafanaPrometheusError as error:
        print(f"Grafana metrics check failed: {error}")
        return 1
    print(
        f"Grafana Prometheus query succeeded; matched GRAFANA_CLUSTER "
        f"using returned label '{label}' across {len(result)} series."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
