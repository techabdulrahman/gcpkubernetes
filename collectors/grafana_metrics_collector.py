"""Query Kubernetes node metrics from Grafana Cloud Prometheus."""

import json
import os
import sys
from dataclasses import dataclass

import requests


DEFAULT_PROM_URL = (
    "https://prometheus-prod-43-prod-ap-south-1.grafana.net/api/prom"
)
PROMETHEUS_QUERY_PATH = "/api/v1/query"
REQUEST_TIMEOUT_SECONDS = 30

CLUSTER = os.getenv("GRAFANA_CLUSTER", "gke-ai-k8s-monitoring")

CPU_QUERY = (
    'sum(rate(node_cpu_usage_seconds_total'
    f'{{cluster="{CLUSTER}"}}[5m]))'
)

MEMORY_QUERY = (
    'sum(node_memory_working_set_bytes'
    f'{{cluster="{CLUSTER}"}})'
)


class GrafanaPrometheusError(RuntimeError):
    """Raised when Grafana Cloud Prometheus cannot return usable metrics."""


@dataclass(frozen=True)
class GrafanaConfig:
    """Grafana Cloud Prometheus connection settings."""

    url: str
    username: str
    token: str


def load_grafana_config():
    """Load Grafana Cloud connection settings from environment variables."""

    url = os.getenv("GRAFANA_PROM_URL", DEFAULT_PROM_URL).strip().rstrip("/")
    username = os.getenv("GRAFANA_USERNAME", "").strip()
    token = os.getenv("GRAFANA_TOKEN", "").strip()

    missing_variables = [
        name
        for name, value in (
            ("GRAFANA_USERNAME", username),
            ("GRAFANA_TOKEN", token),
        )
        if not value
    ]

    if missing_variables:
        raise GrafanaPrometheusError(
            "Missing required environment variable(s): "
            + ", ".join(missing_variables)
        )

    return GrafanaConfig(
        url=url,
        username=username,
        token=token,
    )


def query_prometheus(promql, config=None):
    """Run a read-only instant Prometheus query."""

    if config is None:
        config = load_grafana_config()

    endpoint = f"{config.url}{PROMETHEUS_QUERY_PATH}"

    try:
        response = requests.get(
            endpoint,
            params={"query": promql},
            auth=(config.username, config.token),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as error:
        raise GrafanaPrometheusError(
            f"Grafana Cloud Prometheus request failed: {error}"
        ) from error

    if response.status_code == 401:
        raise GrafanaPrometheusError(
            "Grafana Cloud returned HTTP 401: credentials were not accepted."
        )

    if response.status_code == 403:
        raise GrafanaPrometheusError(
            "Grafana Cloud returned HTTP 403: credentials lack permission."
        )

    if not response.ok:
        raise GrafanaPrometheusError(
            f"Grafana Cloud Prometheus returned HTTP {response.status_code}."
        )

    try:
        payload = response.json()
    except ValueError as error:
        raise GrafanaPrometheusError(
            "Grafana Cloud Prometheus returned invalid JSON."
        ) from error

    if payload.get("status") != "success":
        raise GrafanaPrometheusError(
            "Grafana Cloud Prometheus returned an unsuccessful response."
        )

    return payload.get("data", {}).get("result", [])


def get_node_cpu_usage(config=None):
    """Return total node CPU usage in CPU cores."""

    results = query_prometheus(CPU_QUERY, config)

    if not results:
        return None

    return float(results[0]["value"][1])


def get_node_memory_usage(config=None):
    """Return total node memory working set in bytes."""

    results = query_prometheus(MEMORY_QUERY, config)

    if not results:
        return None

    return float(results[0]["value"][1])


def main():
    """Query and display node CPU and memory metrics."""

    try:
        config = load_grafana_config()

        cpu = get_node_cpu_usage(config)
        memory = get_node_memory_usage(config)

    except GrafanaPrometheusError as error:
        print(f"Grafana metrics query failed: {error}", file=sys.stderr)
        return 1

    print("\n========== GRAFANA NODE METRICS ==========\n")

    print(f"Cluster       : {CLUSTER}")

    if cpu is None:
        print("Node CPU      : No data")
    else:
        print(f"Node CPU      : {cpu:.3f} cores")

    if memory is None:
        print("Node Memory   : No data")
    else:
        print(f"Node Memory   : {memory / (1024 ** 3):.3f} GB")

    print("\nPromQL used:")
    print(f"CPU    : {CPU_QUERY}")
    print(f"Memory : {MEMORY_QUERY}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
