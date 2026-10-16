"""Strictly validate the investigation run before using its artifact."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone


EXPECTED_WORKFLOW_PATH = ".github/workflows/kubernetes-investigation.yml"
EXPECTED_BRANCH = "master"
ALLOWED_EVENTS = {"schedule", "workflow_dispatch"}
MAX_RUN_AGE = timedelta(minutes=30)

SOURCE_FIELDS = (
    "id",
    "repository",
    "head_repository",
    "head_branch",
    "event",
    "status",
    "conclusion",
)
API_RUN_FIELDS = SOURCE_FIELDS + ("path", "created_at")


def _repository_name(run, field):
    if not isinstance(run, dict):
        return None
    repository = run.get(field)
    if not isinstance(repository, dict):
        return None
    return repository.get("full_name")


def _is_positive_run_id(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _matches_workflow_path(path):
    if not isinstance(path, str):
        return False
    workflow_path, separator, ref = path.partition("@")
    return (
        workflow_path == EXPECTED_WORKFLOW_PATH
        and (not separator or ref == "refs/heads/master")
    )


def _parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        created_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if created_at.tzinfo is None:
        return None
    return created_at.astimezone(timezone.utc)


def _run_metadata(run, fields):
    if not isinstance(run, dict):
        return None
    metadata = {}
    for field in fields:
        if field in ("repository", "head_repository"):
            metadata[field] = _repository_name(run, field)
        else:
            value = run.get(field)
            if isinstance(value, str):
                value = value[:300]
            metadata[field] = value
    return metadata


def validate_investigation_run(source, run, expected_repository, now=None):
    """Return named failed predicates and safe, allowlisted run metadata."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        raise ValueError("now must include a timezone")
    now = now.astimezone(timezone.utc)

    failures = []
    source_is_object = isinstance(source, dict)
    run_is_object = isinstance(run, dict)

    if not source_is_object:
        failures.append("source.present")
    if not _is_positive_run_id(source.get("id") if source_is_object else None):
        failures.append("source.id")
    if _repository_name(source, "repository") != expected_repository:
        failures.append("source.repository")
    if _repository_name(source, "head_repository") != expected_repository:
        failures.append("source.head_repository")
    if not source_is_object or source.get("head_branch") != EXPECTED_BRANCH:
        failures.append("source.head_branch")
    if not source_is_object or source.get("status") != "completed":
        failures.append("source.status")
    if not source_is_object or source.get("conclusion") != "success":
        failures.append("source.conclusion")
    source_event = source.get("event") if source_is_object else None
    if source_event not in ALLOWED_EVENTS:
        failures.append("source.event")

    if not run_is_object:
        failures.append("api_run.present")
    api_run_id = run.get("id") if run_is_object else None
    source_run_id = source.get("id") if source_is_object else None
    if (
        not _is_positive_run_id(api_run_id)
        or not _is_positive_run_id(source_run_id)
        or api_run_id != source_run_id
    ):
        failures.append("api_run.id")
    if _repository_name(run, "repository") != expected_repository:
        failures.append("api_run.repository")
    if _repository_name(run, "head_repository") != expected_repository:
        failures.append("api_run.head_repository")
    if not run_is_object or not _matches_workflow_path(run.get("path")):
        failures.append("api_run.path")
    if not run_is_object or run.get("head_branch") != EXPECTED_BRANCH:
        failures.append("api_run.head_branch")
    api_run_event = run.get("event") if run_is_object else None
    if api_run_event not in ALLOWED_EVENTS:
        failures.append("api_run.event")
    if api_run_event != source_event:
        failures.append("api_run.event_matches_source")
    if not run_is_object or run.get("status") != "completed":
        failures.append("api_run.status")
    if not run_is_object or run.get("conclusion") != "success":
        failures.append("api_run.conclusion")

    created_at = _parse_timestamp(run.get("created_at") if run_is_object else None)
    if created_at is None:
        failures.append("api_run.created_at")
        failures.append("api_run.age")
    else:
        age = now - created_at
        if age < timedelta(0) or age > MAX_RUN_AGE:
            failures.append("api_run.age")

    metadata = {
        "source": _run_metadata(source, SOURCE_FIELDS),
        "api_run": _run_metadata(run, API_RUN_FIELDS),
        "age_seconds": (
            (now - created_at).total_seconds() if created_at is not None else None
        ),
        "max_age_seconds": MAX_RUN_AGE.total_seconds(),
        "expected_repository": expected_repository,
        "expected_workflow_path": EXPECTED_WORKFLOW_PATH,
        "expected_branch": EXPECTED_BRANCH,
        "allowed_events": sorted(ALLOWED_EVENTS),
    }
    return failures, metadata


def _load_json_environment(name):
    raw_value = os.environ.get(name)
    if raw_value is None:
        return None
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return None


def main():
    expected_repository = os.environ.get("GITHUB_REPOSITORY", "")
    source = _load_json_environment("SOURCE_RUN_JSON")
    run = _load_json_environment("API_RUN_JSON")
    failures, metadata = validate_investigation_run(
        source,
        run,
        expected_repository,
    )
    print("Investigation run metadata: " + json.dumps(metadata, sort_keys=True))
    if failures:
        print("Failed source run validation predicates: " + ", ".join(failures))
        return 1

    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print("::error::GITHUB_OUTPUT is unavailable; verified run ID was not published.")
        return 1
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"evidence_run_id={source['id']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
