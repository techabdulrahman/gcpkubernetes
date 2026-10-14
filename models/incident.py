"""Structured incident records shared by the SRE investigation workflow."""

from dataclasses import asdict, dataclass, field


@dataclass
class Incident:
    incident_id: str
    category: str
    severity: str
    detected_at: str
    namespace: str
    workload: str
    pods: list[str] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    source_status: dict[str, str] = field(default_factory=dict)
    recommended_remediation: str = ""
    eligible_remediations: list[str] = field(default_factory=list)
    github_run: dict | None = None
    analysis_mode: str = "rules-based"
    analysis: str = ""

    def to_dict(self):
        """Return JSON-serializable incident data."""
        return asdict(self)
