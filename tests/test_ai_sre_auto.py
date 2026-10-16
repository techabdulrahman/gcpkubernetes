from scripts.ai_sre_auto import decide


def test_incident_is_report_only():
    assert decide({"incidents": [{"category": "failed_rollout"}]})["action"] == "report_only"


def test_healthy_report():
    assert decide({"incidents": []})["action"] == "healthy"
