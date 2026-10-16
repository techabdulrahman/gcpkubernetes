"""Validate a failed master deployment before starting an investigation."""

import json
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.validate_investigation_run import validate_workflow_run


EXPECTED_WORKFLOW_PATH = ".github/workflows/deploy.yml"
ALLOWED_EVENTS = {"push"}


def validate_deployment_run(source, run, expected_repository, now=None):
    """Validate that the triggering run is a recent failed master deployment."""
    return validate_workflow_run(
        source,
        run,
        expected_repository,
        EXPECTED_WORKFLOW_PATH,
        ALLOWED_EVENTS,
        "failure",
        now,
    )


def _load_json_environment(name):
    raw_value = os.environ.get(name)
    if raw_value is None:
        return None
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return None


def main():
    source = _load_json_environment("SOURCE_RUN_JSON")
    run = _load_json_environment("API_RUN_JSON")
    failures, metadata = validate_deployment_run(
        source,
        run,
        os.environ.get("GITHUB_REPOSITORY", ""),
    )
    print("Deployment run metadata: " + json.dumps(metadata, sort_keys=True))
    if failures:
        print("Failed deployment run validation predicates: " + ", ".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
