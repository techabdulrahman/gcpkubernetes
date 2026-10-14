"""Collect read-only Kubernetes evidence and publish deduplicated incident reports."""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ai.sre_agent import analyze_incidents
from collectors.evidence_collector import build_observability_evidence
from collectors.github_actions_collector import GitHubRedirectHandler


GITHUB_API = "https://api.github.com"
MAX_ISSUE_BODY_CHARS = 20_000


class IncidentPublishError(RuntimeError):
    """Raised when incident report publication fails."""


def _stable_json(payload):
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")


def collect_evidence():
    """Collect evidence and return a durable, secret-minimized incident payload."""
    bundle = build_observability_evidence()
    incidents = analyze_incidents(bundle, bundle.get("github_actions"))
    incident_data = []
    for incident in incidents:
        record = incident.to_dict()
        record["analysis"] = record["analysis"][:8_000]
        incident_data.append(record)
    payload = {
        "version": 1,
        "cluster": bundle.get("cluster"),
        "observed_at": bundle.get("observed_at"),
        "source_status": {
            "kubernetes": "available",
            "grafana": (
                "available"
                if any(
                    metric.get("status") == "available"
                    for metric in bundle.get("cluster_metrics", [])
                )
                else "unavailable"
            ),
            "github_actions": bundle.get("github_actions", {}).get(
                "status", "unavailable"
            ),
        },
        "incidents": incident_data,
        "diagnostics": [
            str(diagnostic)[:500]
            for diagnostic in bundle.get("diagnostics", [])
        ],
    }
    return payload


def write_evidence(payload, output_path):
    """Write deterministic bounded evidence for later approval-gated retrieval."""
    output_path = Path(output_path)
    output_path.write_bytes(_stable_json(payload))


def _github_request(method, path, token, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{GITHUB_API}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "AI-Kubernetes-Troubleshooter",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        opener = urllib.request.build_opener(GitHubRedirectHandler())
        with opener.open(request, timeout=20) as response:
            raw = response.read(1_000_001)
    except urllib.error.HTTPError as error:
        raise IncidentPublishError(
            f"GitHub incident report request failed with HTTP {error.code}."
        ) from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise IncidentPublishError(
            "GitHub incident report service could not be reached."
        ) from error
    if len(raw) > 1_000_000:
        raise IncidentPublishError("GitHub returned an oversized incident response.")
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IncidentPublishError("GitHub returned invalid incident JSON.") from error


def _render_incident(incident, evidence_digest, evidence_run_id):
    lines = [
        f"<!-- ai-sre-incident:v1 id={incident['incident_id']} "
        f"sha256={evidence_digest} run={evidence_run_id} -->",
        f"# {incident['category'].replace('_', ' ').title()}",
        "",
        f"- Incident ID: `{incident['incident_id']}`",
        f"- Severity: **{incident['severity']}**",
        f"- Detected: `{incident['detected_at']}`",
        f"- Target: `{incident['namespace']}/{incident['workload']}`",
        f"- Analysis mode: **{incident['analysis_mode']}**",
        f"- Evidence workflow run: {evidence_run_id}",
        "",
        incident["analysis"],
        "",
        "## Proposed operation (not executed)",
        (
            "Allowlisted operation available after explicit approval: "
            "`rollout_restart`."
            if "rollout_restart" in incident.get("eligible_remediations", [])
            else "No automated remediation is currently eligible."
        ),
        "",
        "No Kubernetes changes were made during this investigation.",
    ]
    body = "\n".join(lines)
    if len(body) > MAX_ISSUE_BODY_CHARS:
        raise IncidentPublishError("Generated incident report exceeded the issue size limit.")
    return body


def publish_incidents(payload, repository, token, evidence_run_id):
    """Create or update one GitHub issue per stable active incident fingerprint."""
    if not token or not repository:
        raise IncidentPublishError(
            "GitHub token and repository are required to publish deduplicated incidents."
        )
    owner, separator, repo = repository.partition("/")
    if not separator or not owner or not repo:
        raise IncidentPublishError("GITHUB_REPOSITORY must be owner/repository.")

    evidence_bytes = _stable_json(payload)
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    encoded_repository = urllib.parse.quote(repository, safe="/")
    published = []
    for incident in payload.get("incidents", []):
        incident_id = incident.get("incident_id")
        if not incident_id:
            continue
        title = f"AI SRE incident {incident_id}"
        query = urllib.parse.urlencode({
            "q": f"repo:{repository} is:issue is:open in:title {incident_id}",
            "per_page": 10,
        })
        search = _github_request(
            "GET", f"/search/issues?{query}", token
        )
        items = search.get("items") if isinstance(search, dict) else None
        if not isinstance(items, list):
            raise IncidentPublishError("GitHub issue search returned an invalid response.")
        body = _render_incident(incident, evidence_digest, evidence_run_id)
        existing = next(
            (
                item
                for item in items
                if isinstance(item, dict)
                and item.get("title") == title
                and item.get("state") == "open"
            ),
            None,
        )
        if existing:
            issue_number = existing.get("number")
            if not isinstance(issue_number, int):
                raise IncidentPublishError("Existing incident issue has no valid number.")
            _github_request(
                "PATCH",
                f"/repos/{encoded_repository}/issues/{issue_number}",
                token,
                {"body": body},
            )
            published.append({"incident_id": incident_id, "issue_number": issue_number, "deduplicated": True})
        else:
            created = _github_request(
                "POST",
                f"/repos/{encoded_repository}/issues",
                token,
                {"title": title, "body": body},
            )
            if not isinstance(created, dict) or not isinstance(created.get("number"), int):
                raise IncidentPublishError("GitHub did not return the created incident issue.")
            published.append({
                "incident_id": incident_id,
                "issue_number": created["number"],
                "deduplicated": False,
            })
    return published


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("collect", "publish"))
    parser.add_argument("--input", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "collect":
            write_evidence(collect_evidence(), args.input)
            print("Read-only incident evidence collection completed.")
            return 0

        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        published = publish_incidents(
            payload,
            os.getenv("GITHUB_REPOSITORY", ""),
            os.getenv("GH_TOKEN", ""),
            os.getenv("GITHUB_RUN_ID", ""),
        )
        summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if not summary_path:
            raise IncidentPublishError("GITHUB_STEP_SUMMARY is not available.")
        with open(summary_path, "a", encoding="utf-8") as summary:
            if not published:
                summary.write("No eligible Kubernetes incidents were detected.\n")
            for incident in published:
                summary.write(
                    f"- `{incident['incident_id']}`: "
                    f"https://github.com/{os.getenv('GITHUB_REPOSITORY')}/issues/"
                    f"{incident['issue_number']}"
                    + (" (updated existing issue)" if incident["deduplicated"] else "")
                    + "\n"
                )
        print(f"Published or updated {len(published)} deduplicated incident report(s).")
        return 0
    except (IncidentPublishError, OSError, ValueError, RuntimeError) as error:
        print(f"Incident investigation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
