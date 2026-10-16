"""Compatibility report-only entry point for the former one-shot AI SRE workflow."""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def decide(payload):
    """Report health state without authorizing a Kubernetes or IAM mutation."""
    incidents = payload.get("incidents") or []
    if not incidents:
        return {"action": "healthy", "reason": "No incident detected."}
    return {
        "action": "report_only",
        "reason": (
            "This compatibility workflow is read-only. Automatic remediation is "
            "selected only by the evidence policy in the Kubernetes remediation workflow."
        ),
    }


def write_summary(lines):
    text = "\n".join(lines) + "\n"
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


def main():
    from scripts.investigate_kubernetes import collect_evidence, write_evidence

    payload = collect_evidence()
    evidence_file = os.getenv("EVIDENCE_FILE", "incident-evidence.json")
    write_evidence(payload, evidence_file)

    lines = ["# AI SRE read-only report", "", "## Data sources"]
    lines += [
        f"- {name}: **{state}**"
        for name, state in (payload.get("source_status") or {}).items()
    ]
    lines.extend(
        f"- note: {diagnostic}"
        for diagnostic in payload.get("diagnostics", [])
    )
    lines.extend(["", "## Root cause analysis"])
    incidents = payload.get("incidents") or []
    if not incidents:
        lines.append("No incident detected.")
    for incident in incidents:
        lines.extend([
            f"### {incident.get('category')} ({incident.get('severity')})",
            "",
            incident.get("analysis", ""),
            "",
        ])
    decision = decide(payload)
    lines.extend([
        "## Decision",
        f"- action: `{decision['action']}`",
        f"- why: {decision['reason']}",
        "- no production changes were made by this report-only workflow.",
    ])
    write_summary(lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
