"""Narrow IAM policy helpers for the approved Artifact Registry reader operation."""

import json
import re
import subprocess


READER_ROLE = "roles/artifactregistry.reader"
REQUEST_TIMEOUT_SECONDS = 30
MAX_RESPONSE_CHARS = 200_000


class ArtifactRegistryIAMError(RuntimeError):
    """Raised when a repository IAM policy cannot be safely read or updated."""


def _validate_target(project, location, repository):
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", project or ""):
        raise ArtifactRegistryIAMError("Artifact Registry project is invalid.")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", location or ""):
        raise ArtifactRegistryIAMError("Artifact Registry location is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", repository or ""):
        raise ArtifactRegistryIAMError("Artifact Registry repository is invalid.")


def _run_gcloud(arguments):
    try:
        result = subprocess.run(
            ["gcloud", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise ArtifactRegistryIAMError("Google Cloud CLI is not installed.") from error
    except subprocess.TimeoutExpired as error:
        raise ArtifactRegistryIAMError(
            f"Artifact Registry IAM operation exceeded {REQUEST_TIMEOUT_SECONDS} seconds."
        ) from error
    if result.returncode:
        raise ArtifactRegistryIAMError(
            "Artifact Registry IAM operation failed or was not authorized."
        )
    if len(result.stdout) > MAX_RESPONSE_CHARS:
        raise ArtifactRegistryIAMError("Artifact Registry IAM response exceeded its size limit.")
    return result.stdout


def get_repository_policy(project, location, repository):
    _validate_target(project, location, repository)
    raw = _run_gcloud([
        "artifacts",
        "repositories",
        "get-iam-policy",
        repository,
        f"--project={project}",
        f"--location={location}",
        "--format=json",
    ])
    try:
        policy = json.loads(raw or "null")
    except json.JSONDecodeError as error:
        raise ArtifactRegistryIAMError(
            "Artifact Registry returned invalid IAM policy JSON."
        ) from error
    if not isinstance(policy, dict) or not isinstance(policy.get("bindings", []), list):
        raise ArtifactRegistryIAMError("Artifact Registry returned an invalid IAM policy.")
    return policy


def has_unconditional_reader(policy, member):
    bindings = policy.get("bindings", [])
    if not isinstance(bindings, list):
        return False
    return any(
        binding.get("role") == READER_ROLE
        and not binding.get("condition")
        and isinstance(binding.get("members"), list)
        and member in binding["members"]
        for binding in bindings
        if isinstance(binding, dict)
    )


def add_repository_reader(project, location, repository, member):
    _validate_target(project, location, repository)
    if not re.fullmatch(
        r"serviceAccount:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com",
        member or "",
    ):
        raise ArtifactRegistryIAMError("Artifact Registry member is invalid.")
    _run_gcloud([
        "artifacts",
        "repositories",
        "add-iam-policy-binding",
        repository,
        f"--project={project}",
        f"--location={location}",
        f"--member={member}",
        f"--role={READER_ROLE}",
        "--quiet",
    ])
