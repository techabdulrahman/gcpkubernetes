import json
import logging
import os
from time import perf_counter
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.exceptions import HTTPException

from ai.analyzer import KubernetesAnalyzer
from collectors.evidence_collector import build_evidence

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "Total number of HTTP requests handled by the application.",
    ("method", "endpoint", "status"),
)
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "Duration of HTTP requests in seconds.",
    ("method", "endpoint"),
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
APPLICATION_HEALTH = Gauge(
    "application_health_status",
    "Whether the application health endpoint reports healthy (1) or unhealthy (0).",
)
STANDARD_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


class JsonFormatter(logging.Formatter):
    """Format application log events as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event_data", {})
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            **event,
        }
        return json.dumps(log_entry, separators=(",", ":"))


def _get_request_logger() -> logging.Logger:
    logger = logging.getLogger("ai_kubernetes_troubleshooter")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)

    return logger


def create_app(config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(
        APP_NAME=os.getenv("APP_NAME", "AI Kubernetes Troubleshooter Demo"),
        APP_VERSION=os.getenv("APP_VERSION", "1.0.0"),
        ENVIRONMENT=os.getenv("ENVIRONMENT", "development"),
    )
    if config:
        app.config.update(config)

    request_logger = _get_request_logger()
    APPLICATION_HEALTH.set(1)

    @app.before_request
    def start_request_timer():
        if request.path != "/metrics":
            request.environ["prometheus_request_start"] = perf_counter()

    @app.after_request
    def record_request_metrics(response):
        if request.path != "/metrics":
            endpoint = request.url_rule.rule if request.url_rule else "unmatched"
            method = request.method if request.method in STANDARD_HTTP_METHODS else "OTHER"
            HTTP_REQUESTS.labels(
                method=method,
                endpoint=endpoint,
                status=str(response.status_code),
            ).inc()
            start_time = request.environ.get("prometheus_request_start")
            if start_time is not None:
                HTTP_REQUEST_DURATION.labels(
                    method=method,
                    endpoint=endpoint,
                ).observe(perf_counter() - start_time)
        return response

    @app.after_request
    def log_request(response):
        request_logger.info(
            "request",
            extra={
                "event_data": {
                    "application": app.config["APP_NAME"],
                    "version": app.config["APP_VERSION"],
                    "method": request.method,
                    "path": request.path,
                    "status": response.status_code,
                }
            },
        )
        return response

    @app.get("/")
    def home():
        return jsonify(
            {
                "message": app.config["APP_NAME"],
                "status": "running",
            }
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "healthy"})

    @app.get("/ready")
    def ready():
        return jsonify({"status": "ready"})

    @app.get("/metrics")
    def metrics():
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    @app.get("/api/info")
    def info():
        return jsonify(
            {
                "name": app.config["APP_NAME"],
                "version": app.config["APP_VERSION"],
                "environment": app.config["ENVIRONMENT"],
            }
        )

    @app.get("/api/troubleshoot")
    def troubleshoot():
        try:
            evidence_items = build_evidence()
        except Exception as error:
            request_logger.error(
                "troubleshooting evidence collection failed",
                extra={
                    "event_data": {
                        "event": "troubleshooting_evidence_collection_failed",
                        "application": app.config["APP_NAME"],
                        "version": app.config["APP_VERSION"],
                        "error_type": type(error).__name__,
                    }
                },
            )
            return jsonify(
                {
                    "status": "error",
                    "message": "Troubleshooting evidence collection failed.",
                }
            ), 500

        analyzer = KubernetesAnalyzer()
        incidents = []
        problem_finding_prefixes = (
            "Pod is currently in ",
            "Pod has restarted ",
            "High node CPU detected:",
            "High node memory detected:",
            "Container restart backoff detected:",
            "Kubernetes reported a failure:",
            "Health check problem detected:",
            "Error found in container logs:",
            "Failure found in container logs:",
        )

        for evidence in evidence_items:
            findings = analyzer.analyze(evidence)
            incident = evidence.to_dict()
            incident["findings"] = findings

            has_problem_finding = any(
                finding.startswith(problem_finding_prefixes)
                for finding in findings
            )
            if evidence.restarts > 0 or evidence.events or has_problem_finding:
                incidents.append(incident)

        return jsonify(
            {
                "status": "success",
                "pod_count": len(evidence_items),
                "incidents": incidents,
            }
        )

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        return jsonify({"error": error.name, "message": error.description}), error.code

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        APPLICATION_HEALTH.set(0)
        request_logger.error(
            "unhandled application error",
            extra={
                "event_data": {
                    "event": "unhandled_exception",
                    "application": app.config["APP_NAME"],
                    "version": app.config["APP_VERSION"],
                    "error_type": type(error).__name__,
                }
            },
        )
        return jsonify({"error": "Internal Server Error"}), 500

    return app
