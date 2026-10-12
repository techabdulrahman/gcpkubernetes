import json
import os
import sys

import requests


DEFAULT_PROM_URL = "https://prometheus-prod-43-prod-ap-south-1.grafana.net"


def main():
    """Run a simple Prometheus API query against Grafana Cloud."""
    prometheus_url = os.getenv("GRAFANA_PROM_URL", DEFAULT_PROM_URL).rstrip("/")
    username = os.getenv("GRAFANA_USERNAME")
    token = os.getenv("GRAFANA_TOKEN")

    missing_variables = [
        name
        for name, value in (
            ("GRAFANA_USERNAME", username),
            ("GRAFANA_TOKEN", token),
        )
        if not value
    ]
    if missing_variables:
        print(
            "Missing required environment variable(s): "
            + ", ".join(missing_variables),
            file=sys.stderr,
        )
        return 1

    endpoint = f"{prometheus_url}/api/prom/api/v1/query"

    try:
        response = requests.get(
            endpoint,
            params={"query": "up"},
            auth=(username, token),
            timeout=30,
        )
        print(f"HTTP status code: {response.status_code}")
        response.raise_for_status()
    except requests.RequestException as error:
        print(f"Grafana Prometheus API request failed: {error}", file=sys.stderr)
        return 1

    try:
        result = response.json()
    except ValueError as error:
        print(f"Grafana Prometheus API returned invalid JSON: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
