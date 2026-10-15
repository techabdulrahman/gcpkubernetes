"""Read node-pool service-account identities for a single GKE cluster."""

import json
import re
import subprocess


REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_CHARS = 200_000
MAX_NODE_POOLS = 20


class GKENodeIdentityError(RuntimeError):
    """Raised when node-pool identities cannot be verified safely."""


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
        raise GKENodeIdentityError("Google Cloud CLI is not installed.") from error
    except subprocess.TimeoutExpired as error:
        raise GKENodeIdentityError(
            f"GKE identity lookup exceeded {REQUEST_TIMEOUT_SECONDS} seconds."
        ) from error
    if result.returncode:
        raise GKENodeIdentityError(
            "GKE node-pool identity lookup failed or was not authorized."
        )
    if len(result.stdout) > MAX_RESPONSE_CHARS:
        raise GKENodeIdentityError("GKE identity response exceeded its size limit.")
    try:
        return json.loads(result.stdout or "null")
    except json.JSONDecodeError as error:
        raise GKENodeIdentityError("GKE returned invalid node-pool JSON.") from error


def _project_number(project_id):
    project = _run_gcloud([
        "projects",
        "describe",
        project_id,
        "--format=json(projectNumber)",
    ])
    number = project.get("projectNumber") if isinstance(project, dict) else None
    if not isinstance(number, (str, int)) or not str(number).isdigit():
        raise GKENodeIdentityError("GKE project number could not be verified.")
    return str(number)


def get_node_pool_service_accounts(project_id, region, cluster_name):
    """Return all distinct service accounts configured on this cluster's pools."""
    if not all(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value)
        for value in (project_id, region, cluster_name)
    ):
        raise GKENodeIdentityError("Project, region, or cluster name is invalid.")

    pools = _run_gcloud([
        "container",
        "node-pools",
        "list",
        f"--cluster={cluster_name}",
        f"--region={region}",
        f"--project={project_id}",
        "--format=json(name,config.serviceAccount)",
    ])
    if not isinstance(pools, list) or not pools or len(pools) >= MAX_NODE_POOLS:
        raise GKENodeIdentityError(
            "GKE returned no node pools or reached the configured pool safety bound."
        )

    default_account = None
    identities = []
    for pool in pools:
        if not isinstance(pool, dict):
            raise GKENodeIdentityError("GKE returned invalid node-pool metadata.")
        pool_name = pool.get("name")
        if not isinstance(pool_name, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,128}", pool_name
        ):
            raise GKENodeIdentityError("GKE returned an invalid node-pool name.")

        config = pool.get("config")
        account = config.get("serviceAccount") if isinstance(config, dict) else None
        if not account or account == "default":
            if default_account is None:
                default_account = (
                    f"{_project_number(project_id)}-compute@developer."
                    "gserviceaccount.com"
                )
            account = default_account
        if not isinstance(account, str) or not re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com",
            account,
        ):
            raise GKENodeIdentityError(
                f"Service account for node pool {pool_name} could not be verified."
            )
        identities.append({"pool": pool_name, "service_account": account})

    return {
        "status": "available",
        "items": sorted(
            identities,
            key=lambda item: (item["pool"], item["service_account"]),
        ),
    }
