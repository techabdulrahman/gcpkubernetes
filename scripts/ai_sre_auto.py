"""One-shot AI SRE run: check GitHub + Kubernetes + Grafana, write the RCA, fix safe causes.

Flow:  collect evidence -> RCA (Gemini or rules) -> decide -> (optional) fix -> verify.

Auto-fix is limited to two allowlisted actions on ONE deployment:
  1. image pull rejected with 403  -> give the GKE node service accounts
     roles/artifactregistry.reader on that one repository, then rollout restart
  2. crash / not ready (no pull problem) -> rollout restart
Anything else (for example a missing image tag) is reported, never guessed at.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

NAMESPACE = os.getenv("INCIDENT_NAMESPACE", "ai-troubleshooter")
DEPLOYMENT = os.getenv("INCIDENT_WORKLOAD", "ai-k8s-demo")
READER_ROLE = "roles/artifactregistry.reader"
PULL_REASONS = {"ImagePullBackOff", "ErrImagePull"}
CRASH_REASONS = {"CrashLoopBackOff", "OOMKilled", "Error", "CreateContainerConfigError"}
IMAGE_RE = re.compile(r"^([a-z0-9-]+)-docker\.pkg\.dev/([^/]+)/([^/]+)/")


def decide(payload):
    """Return {'action', 'reason', 'image'} from collected evidence. Pure function."""
    pods = payload.get("pods") or []
    pull_pods = [
        p for p in pods if PULL_REASONS & set(p.get("state_reasons") or [])
    ]
    if pull_pods:
        text = " ".join(
            (c.get("state_message") or "")
            for p in pull_pods
            for c in p.get("containers") or []
        ).lower()
        image = (pull_pods[0].get("images") or [None])[0]
        if "403" in text or "forbidden" in text or "permission" in text:
            return {
                "action": "grant_reader_and_restart",
                "reason": "Image pull rejected with 403: the GKE node service account "
                          "cannot read the Artifact Registry repository.",
                "image": image,
            }
        return {
            "action": "report_only",
            "reason": "Image pull is failing but not with a 403 (tag missing or wrong?). "
                      "Re-run the Deploy workflow to build and push the image.",
            "image": image,
        }
    crashing = [
        p for p in pods
        if CRASH_REASONS & set(p.get("state_reasons") or [])
    ]
    deployments = payload.get("deployments") or []
    short = [
        d for d in deployments
        if (d.get("available_replicas") or 0) < (d.get("desired_replicas") or 0)
    ]
    if crashing or short:
        return {
            "action": "restart",
            "reason": "Pods are crashing or the deployment has fewer ready replicas than desired.",
            "image": None,
        }
    return {"action": "healthy", "reason": "No unhealthy pods or deployments found.", "image": None}


def _run(cmd, timeout=120):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return result.returncode, (result.stdout + result.stderr).strip()


def grant_reader(image):
    from collectors.gke_node_identity_collector import get_node_pool_service_accounts

    match = IMAGE_RE.match(image or "")
    if not match:
        raise RuntimeError("Could not read project/repository from the image URI.")
    location, project, repo = match.groups()
    cluster = os.environ["CLUSTER_NAME"]
    region = os.environ["REGION"]
    accounts = get_node_pool_service_accounts(project, region, cluster)["items"]
    done = []
    for item in accounts:
        member = f"serviceAccount:{item['service_account']}"
        code, out = _run([
            "gcloud", "artifacts", "repositories", "add-iam-policy-binding", repo,
            f"--location={location}", f"--project={project}",
            f"--member={member}", f"--role={READER_ROLE}", "--quiet",
        ])
        if code:
            raise RuntimeError(
                f"IAM grant failed for {member}. The identity running this workflow needs "
                f"roles/artifactregistry.admin on repo {repo}. Details: {out[-300:]}"
            )
        done.append(member)
    return done


def restart_and_verify():
    code, out = _run(["kubectl", "rollout", "restart", f"deployment/{DEPLOYMENT}", "-n", NAMESPACE])
    if code:
        raise RuntimeError(f"rollout restart failed: {out[-300:]}")
    code, out = _run(
        ["kubectl", "rollout", "status", f"deployment/{DEPLOYMENT}", "-n", NAMESPACE, "--timeout=240s"],
        timeout=300,
    )
    return code == 0, out[-500:]


def write_summary(lines):
    text = "\n".join(lines) + "\n"
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


def main():
    from scripts.investigate_kubernetes import collect_evidence, write_evidence

    auto_fix = os.getenv("AUTO_FIX", "true").lower() == "true"
    payload = collect_evidence()
    evidence_file = os.getenv("EVIDENCE_FILE", "incident-evidence.json")
    write_evidence(payload, evidence_file)

    sources = payload.get("source_status", {})
    lines = ["# AI SRE report", "", "## Data sources"]
    lines += [f"- {name}: **{state}**" for name, state in sources.items()]
    for diagnostic in payload.get("diagnostics", []):
        lines.append(f"- note: {diagnostic}")

    lines += ["", "## Root cause analysis"]
    incidents = payload.get("incidents") or []
    if not incidents:
        lines.append("No incident detected.")
    for incident in incidents:
        lines += [f"### {incident.get('category')} ({incident.get('severity')})", "",
                  incident.get("analysis", ""), ""]

    decision = decide(payload)
    lines += ["## Decision", f"- action: `{decision['action']}`", f"- why: {decision['reason']}"]

    exit_code = 0
    if decision["action"] == "healthy":
        pass
    elif decision["action"] == "report_only" or not auto_fix:
        lines.append("- auto-fix: **not performed** (report only).")
        exit_code = 1
    else:
        try:
            if decision["action"] == "grant_reader_and_restart":
                granted = grant_reader(decision["image"])
                lines.append("- granted `roles/artifactregistry.reader` to: " + ", ".join(granted))
            ok, detail = restart_and_verify()
            lines.append(f"- rollout after fix: **{'healthy' if ok else 'still failing'}**")
            lines.append(f"```\n{detail}\n```")
            exit_code = 0 if ok else 1
        except Exception as error:  # report the failure instead of hiding it
            lines.append(f"- auto-fix **failed**: {error}")
            exit_code = 1

    write_summary(lines)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
