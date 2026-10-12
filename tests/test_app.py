import io
import json
import logging
import os
import unittest
from unittest.mock import patch

from app import JsonFormatter, create_app


class ApplicationEndpointTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(
            {
                "TESTING": True,
                "APP_NAME": "AI Kubernetes Troubleshooter Demo",
                "APP_VERSION": "test-version",
                "ENVIRONMENT": "test",
            }
        )
        self.client = self.app.test_client()

    def test_home(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {
                "message": "AI Kubernetes Troubleshooter Demo",
                "status": "running",
            },
        )

    def test_health_and_readiness(self):
        self.assertEqual(self.client.get("/health").get_json(), {"status": "healthy"})
        self.assertEqual(self.client.get("/ready").get_json(), {"status": "ready"})

    def test_metrics_include_request_count_duration_and_health(self):
        self.client.get("/health")
        self.client.get("/not-found")
        self.client.open("/", method="CUSTOM-UNBOUNDED-METHOD")

        response = self.client.get("/metrics")
        metrics = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("text/plain"))
        self.assertIn('http_requests_total{endpoint="/health",method="GET",status="200"}', metrics)
        self.assertIn('http_requests_total{endpoint="unmatched",method="GET",status="404"}', metrics)
        self.assertIn(
            'http_request_duration_seconds_bucket{endpoint="/health",le="0.005",method="GET"}',
            metrics,
        )
        self.assertIn(
            'http_requests_total{endpoint="unmatched",method="OTHER",status="405"}',
            metrics,
        )
        self.assertIn("# TYPE application_health_status gauge", metrics)
        self.assertIn("application_health_status 1.0", metrics)
        self.assertNotIn("/metrics", metrics)

    def test_info_uses_configured_values(self):
        response = self.client.get("/api/info")

        self.assertEqual(
            response.get_json(),
            {
                "name": "AI Kubernetes Troubleshooter Demo",
                "version": "test-version",
                "environment": "test",
            },
        )

    def test_environment_variables_configure_the_app(self):
        with patch.dict(
            os.environ,
            {
                "APP_NAME": "Configured Demo",
                "APP_VERSION": "2.0.0",
                "ENVIRONMENT": "staging",
            },
        ):
            configured_app = create_app()

        response = configured_app.test_client().get("/api/info")
        self.assertEqual(
            response.get_json(),
            {
                "name": "Configured Demo",
                "version": "2.0.0",
                "environment": "staging",
            },
        )

    def test_request_logs_are_structured_and_exclude_query_values(self):
        log_output = io.StringIO()
        handler = logging.StreamHandler(log_output)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("ai_kubernetes_troubleshooter")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)

        response = self.client.get("/not-found?token=do-not-log")

        self.assertEqual(response.status_code, 404)
        log_entry = json.loads(log_output.getvalue())
        self.assertEqual(
            {
                "application": log_entry["application"],
                "version": log_entry["version"],
                "method": log_entry["method"],
                "path": log_entry["path"],
                "status": log_entry["status"],
            },
            {
                "application": "AI Kubernetes Troubleshooter Demo",
                "version": "test-version",
                "method": "GET",
                "path": "/not-found",
                "status": 404,
            },
        )
        self.assertIn("timestamp", log_entry)
        self.assertNotIn("do-not-log", log_output.getvalue())


if __name__ == "__main__":
    unittest.main()
