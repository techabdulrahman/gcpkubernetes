from scripts.ai_sre_auto import decide


def pull(msg):
    return {"pods": [{"state_reasons": ["ImagePullBackOff"], "images": ["asia-south1-docker.pkg.dev/p/r/i:t"],
                      "containers": [{"state_message": msg}]}]}


def test_403_pull_grants_reader():
    assert decide(pull("failed to fetch oauth token: 403 Forbidden"))["action"] == "grant_reader_and_restart"


def test_missing_tag_is_report_only():
    assert decide(pull("manifest unknown: not found"))["action"] == "report_only"


def test_crash_restarts():
    assert decide({"pods": [{"state_reasons": ["CrashLoopBackOff"]}]})["action"] == "restart"


def test_healthy():
    payload = {"pods": [{"state_reasons": []}], "deployments": [{"available_replicas": 2, "desired_replicas": 2}]}
    assert decide(payload)["action"] == "healthy"
