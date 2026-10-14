"""Read-only GitHub Actions deployment history collection."""

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


GITHUB_API = "https://api.github.com"
DEPLOY_WORKFLOW = "deploy.yml"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


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


def collect_latest_deployment(repository, token):
    """Return bounded metadata for the latest deployment workflow run."""
    if not repository or not token:
        return {
            "status": "unavailable",
            "diagnostic": "GitHub repository or read token is not configured.",
            "run": None,
        }

    encoded_repository = urllib.parse.quote(repository, safe="/")
    url = (
        f"{GITHUB_API}/repos/{encoded_repository}/actions/workflows/"
        f"{DEPLOY_WORKFLOW}/runs?per_page=1"
    )
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
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return {
                    "status": "unavailable",
                    "diagnostic": "GitHub Actions API response exceeded the size limit.",
                    "run": None,
                }
            payload = json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as error:
        return {
            "status": "unavailable",
            "diagnostic": f"GitHub Actions API returned HTTP {error.code}.",
            "run": None,
        }
    except (urllib.error.URLError, TimeoutError):
        return {
            "status": "unavailable",
            "diagnostic": "GitHub Actions API could not be reached.",
            "run": None,
        }
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "status": "unavailable",
            "diagnostic": "GitHub Actions API returned invalid JSON.",
            "run": None,
        }

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

    raw_run = runs[0]
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
