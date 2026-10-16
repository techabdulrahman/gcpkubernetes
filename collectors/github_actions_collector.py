"""Read-only GitHub Actions deployment history and bounded run evidence."""

import io
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from ai.safety import redact_sensitive_values


GITHUB_API = "https://api.github.com"
DEPLOY_WORKFLOW = "deploy.yml"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LOG_ARCHIVE_BYTES = 5 * 1024 * 1024
MAX_LOG_CHARS = 20_000


class GitHubRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the workflow token to a different host."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        original_url = urllib.parse.urlsplit(request.full_url)
        target_url = urllib.parse.urlsplit(new_url)
        if redirected is not None and (
            target_url.scheme.lower() != "https"
            or original_url.hostname != target_url.hostname
        ):
            redirected.remove_header("Authorization")
        return redirected


class GitHubCollectionError(RuntimeError):
    """A bounded GitHub API or run-log collection failure."""


def _github_request(url, token, max_bytes):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AI-Kubernetes-Troubleshooter",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        opener = urllib.request.build_opener(GitHubRedirectHandler())
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read(max_bytes + 1)
    except urllib.error.HTTPError as error:
        raise GitHubCollectionError(
            f"GitHub Actions API returned HTTP {error.code}."
        ) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise GitHubCollectionError(
            "GitHub Actions API could not be reached within the request timeout."
        ) from error
    if len(body) > max_bytes:
        raise GitHubCollectionError("GitHub Actions API response exceeded the size limit.")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GitHubCollectionError("GitHub Actions API returned invalid JSON.") from error


def _collect_run_logs(repository, token, run_id):
    encoded_repository = urllib.parse.quote(repository, safe="/")
    url = f"{GITHUB_API}/repos/{encoded_repository}/actions/runs/{run_id}/logs"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": "AI-Kubernetes-Troubleshooter",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        opener = urllib.request.build_opener(GitHubRedirectHandler())
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            archive_bytes = response.read(MAX_LOG_ARCHIVE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise GitHubCollectionError(
            f"GitHub Actions run logs returned HTTP {error.code}."
        ) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise GitHubCollectionError(
            "GitHub Actions run logs could not be reached within the request timeout."
        ) from error
    if len(archive_bytes) > MAX_LOG_ARCHIVE_BYTES:
        raise GitHubCollectionError("GitHub Actions run-log archive exceeded the size limit.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError) as error:
        raise GitHubCollectionError(
            "GitHub Actions returned an invalid run-log archive."
        ) from error

    parts = []
    remaining = MAX_LOG_CHARS
    try:
        for entry in archive.infolist()[:50]:
            if entry.is_dir() or not entry.filename.lower().endswith(".txt") or remaining <= 0:
                continue
            with archive.open(entry) as log_file:
                text = log_file.read(remaining + 1).decode("utf-8", errors="replace")
            if text.strip():
                text = redact_sensitive_values(text[:remaining])
                parts.append(
                    f"--- {entry.filename.rsplit('/', 1)[-1]} ---\n{text}"
                )
                remaining -= len(text)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise GitHubCollectionError(
            "GitHub Actions run-log archive could not be read."
        ) from error
    return "\n\n".join(parts)[:MAX_LOG_CHARS]


def _collect_run_details(repository, token, run_id):
    encoded_repository = urllib.parse.quote(repository, safe="/")
    jobs_url = (
        f"{GITHUB_API}/repos/{encoded_repository}/actions/runs/{run_id}/jobs"
        "?per_page=50"
    )
    jobs_payload = _github_request(jobs_url, token, MAX_RESPONSE_BYTES)
    jobs = jobs_payload.get("jobs") if isinstance(jobs_payload, dict) else None
    if not isinstance(jobs, list):
        raise GitHubCollectionError("GitHub Actions returned invalid job details.")

    job_records = []
    failed_jobs = []
    failed_steps = []
    steps = []
    push_steps = []
    for job in jobs[:50]:
        if not isinstance(job, dict):
            continue
        job_name = str(job.get("name") or "Unknown job")[:200]
        job_record = {
            "name": job_name,
            "conclusion": job.get("conclusion"),
            "failed_steps": [],
        }
        if job.get("conclusion") == "failure":
            failed_jobs.append(job_name)
        for step in job.get("steps", []):
            if not isinstance(step, dict):
                continue
            step_name = str(step.get("name") or "Unknown step")[:200]
            conclusion = str(step.get("conclusion") or step.get("status") or "unknown")
            step_record = {
                "job": job_name,
                "name": step_name,
                "conclusion": conclusion,
            }
            steps.append(step_record)
            if conclusion == "failure":
                failed_steps.append(f"{job_name} / {step_name}")
                job_record["failed_steps"].append(step_name)
            if any(word in step_name.lower() for word in ("push", "build and push")):
                push_steps.append(step_record)
        job_records.append(job_record)

    try:
        log_excerpt = _collect_run_logs(repository, token, run_id)
        log_diagnostic = None
    except GitHubCollectionError as error:
        log_excerpt = ""
        log_diagnostic = str(error)
    push_status = "unknown"
    if any(step["conclusion"] == "success" for step in push_steps):
        push_status = "succeeded"
    elif any(step["conclusion"] == "failure" for step in push_steps):
        log_lower = log_excerpt.lower()
        if any(
            marker in log_lower
            for marker in ("denied:", "push access denied", "docker push", "failed to push")
        ):
            push_status = "failed"
        elif "docker build" in log_lower or "failed to solve" in log_lower:
            push_status = "not_attempted"

    push_error_category = None
    if push_status == "failed":
        if any(marker in log_excerpt.lower() for marker in ("permission denied", "unauthorized", "forbidden", "403", "denied:")):
            push_error_category = "authorization"
        elif any(marker in log_excerpt.lower() for marker in ("too many requests", "rate limit", "429")):
            push_error_category = "rate_limit"
        elif any(marker in log_excerpt.lower() for marker in ("timeout", "timed out", "connection refused", "no such host")):
            push_error_category = "network"

    image_match = re.search(
        r"[A-Za-z0-9.-]+-docker\.pkg\.dev/[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+",
        log_excerpt,
    )
    return {
        "jobs": job_records,
        "failed_jobs": failed_jobs,
        "failed_steps": failed_steps,
        "steps": steps[:200],
        "image_uri": image_match.group(0)[:500] if image_match else None,
        "image_push_status": push_status,
        "image_push_error_category": push_error_category,
        "log_excerpt": log_excerpt,
        "log_diagnostic": log_diagnostic,
    }


def _image_tag(image_uri):
    if not isinstance(image_uri, str):
        return None
    without_digest = image_uri.split("@", 1)[0]
    final_component = without_digest.rsplit("/", 1)[-1]
    separator, _, tag = final_component.rpartition(":")
    return tag if separator else None


def collect_latest_deployment(repository, token, image_uris=None):
    """Return the latest deployment run and its failed jobs, steps, and logs."""
    if not repository or not token:
        return {
            "status": "unavailable",
            "diagnostic": "GitHub repository or read token is not configured.",
            "run": None,
        }

    encoded_repository = urllib.parse.quote(repository, safe="/")
    url = (
        f"{GITHUB_API}/repos/{encoded_repository}/actions/workflows/"
        f"{DEPLOY_WORKFLOW}/runs?per_page=10"
    )
    try:
        payload = _github_request(url, token, MAX_RESPONSE_BYTES)
    except GitHubCollectionError as error:
        return {"status": "unavailable", "diagnostic": str(error), "run": None}

    if not isinstance(payload, dict):
        return {
            "status": "unavailable",
            "diagnostic": "GitHub Actions API returned an unexpected response.",
            "run": None,
        }
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list) or not runs:
        return {
            "status": "unavailable",
            "diagnostic": "No deployment workflow run was returned.",
            "run": None,
        }

    image_tags = {
        tag
        for image in (image_uris or [])
        if (tag := _image_tag(image)) is not None
    }
    image_commit = next(
        (
            tag
            for tag in image_tags
            if re.fullmatch(r"[0-9a-fA-F]{40}", tag)
        ),
        None,
    )
    if image_commit:
        filtered_url = (
            f"{GITHUB_API}/repos/{encoded_repository}/actions/workflows/"
            f"{DEPLOY_WORKFLOW}/runs?"
            + urllib.parse.urlencode({"per_page": 10, "head_sha": image_commit})
        )
        try:
            filtered_payload = _github_request(
                filtered_url,
                token,
                MAX_RESPONSE_BYTES,
            )
        except GitHubCollectionError:
            filtered_payload = None
        filtered_runs = (
            filtered_payload.get("workflow_runs")
            if isinstance(filtered_payload, dict)
            else None
        )
        if isinstance(filtered_runs, list) and filtered_runs:
            same_commit_runs = [
                candidate
                for candidate in filtered_runs
                if isinstance(candidate, dict)
                and candidate.get("head_sha") == image_commit
            ]
            failed_run = next(
                (
                    candidate
                    for candidate in same_commit_runs
                    if candidate.get("conclusion") == "failure"
                ),
                None,
            )
            if failed_run:
                runs = [failed_run, *runs]
            elif same_commit_runs:
                runs = [same_commit_runs[0], *runs]
    matching_run = next(
        (
            candidate
            for candidate in runs
            if isinstance(candidate, dict)
            and candidate.get("head_sha") in image_tags
        ),
        None,
    )
    raw_run = matching_run or runs[0]
    if not isinstance(raw_run, dict):
        return {
            "status": "unavailable",
            "diagnostic": "GitHub Actions API returned invalid run metadata.",
            "run": None,
        }
    run = {
        "repository": repository,
        "workflow": raw_run.get("name"),
        "run_id": raw_run.get("id"),
        "run_url": raw_run.get("html_url"),
        "branch": raw_run.get("head_branch"),
        "commit_sha": raw_run.get("head_sha"),
        "status": raw_run.get("status"),
        "conclusion": raw_run.get("conclusion"),
        "created_at": raw_run.get("created_at"),
        "updated_at": raw_run.get("updated_at"),
    }
    if isinstance(run["run_id"], int) and run["run_id"] > 0:
        try:
            run.update(_collect_run_details(repository, token, run["run_id"]))
        except GitHubCollectionError as error:
            run["details_diagnostic"] = str(error)
    else:
        run["details_diagnostic"] = "GitHub Actions API did not return a valid run ID."

    updated_at = run["updated_at"]
    try:
        updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - updated
        is_stale = (
            updated.tzinfo is None
            or age < timedelta(0)
            or age > timedelta(hours=24)
        )
    except (AttributeError, TypeError, ValueError):
        is_stale = True
    return {
        "status": "stale" if is_stale else "available",
        "diagnostic": (
            "Latest deployment run is older than 24 hours."
            if is_stale
            else None
        ),
        "run": run,
    }
