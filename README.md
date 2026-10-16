# AI Kubernetes Troubleshooter Demo

A Flask REST API deployed to Google Kubernetes Engine (GKE), instrumented with Prometheus metrics and Grafana Alloy. The repository includes read-only Kubernetes/Grafana/GitHub incident investigation, Gemini or rules-based RCA, and a separate policy-controlled automatic remediation workflow.

## Architecture

```text
GitHub
  -> GitHub Actions deployment
  -> Docker
  -> Google Artifact Registry
  -> GKE
  -> Flask application (/metrics)
  -> Prometheus
  -> Grafana

Failed deployment workflow run
  -> GitHub Actions failure-analysis workflow
  -> GitHub run logs + commit diff
  -> Gemini
  -> Root-cause report in the Actions job summary

Local/API Kubernetes troubleshooting
  -> Kubernetes and Grafana evidence collectors
  -> Gemini analysis (when configured) or local rules

Scheduled/manual AI SRE investigation (every 15 minutes)
  -> read-only Kubernetes + Artifact Registry + commit-correlated GitHub Actions + optional Grafana
  -> deduplicated GitHub incident issues + short-lived evidence artifact
  -> Gemini hypothesis or structured rules-based RCA

Successful investigation run
  -> trusted workflow_run handoff (repository, branch, workflow, status, and age verified)
  -> downloads that run's immutable evidence artifact; no manual run/incident ID
  -> deterministic policy selects a single evidence-eligible action or reports only
  -> narrowly scoped GKE API operation + rollout/readiness/events/health/Grafana verification
```

The Flask app exports request metrics. The optional `/api/troubleshoot` endpoint collects namespaced Kubernetes evidence and read-only Grafana Cloud Prometheus metrics; it keeps pod/container measurements separate from node and deployment context.

## Application endpoints and metrics

| Endpoint | Purpose |
| --- | --- |
| `/` | Demo message and running status |
| `/health` | Liveness health check |
| `/ready` | Readiness check |
| `/api/info` | Application name, version, and environment |
| `/metrics` | Prometheus text exposition format |

The application exports:

- `http_requests_total{method,endpoint,status}` — request counts split by HTTP method, Flask route template, and response code.
- `http_request_duration_seconds{method,endpoint}` — request duration histogram with buckets suitable for latency quantiles.
- `application_health_status` — `1` when the application starts healthy, `0` after an unexpected application exception; a successful `/health` request restores it to `1`.

The `/metrics` scrape endpoint is intentionally excluded from the HTTP request counters and latency histogram to prevent scrapes from inflating application traffic. It is still logged. The `endpoint` label uses Flask's route template (for example `/api/info`), not a raw URL, and unmatched paths use the fixed value `unmatched`. Standard HTTP methods are retained; unusual custom methods are normalized to `OTHER`. No query strings, user IDs, IP addresses, or other unbounded or sensitive values are used as metric labels.

Gunicorn runs one worker per pod so its in-process counters and histograms are complete. Kubernetes runs multiple replicas and PromQL aggregates their series. Scale with pod replicas rather than adding Gunicorn workers without first configuring Prometheus multiprocess collection.

## Grafana Cloud evidence collection

The collector reads `GRAFANA_PROM_URL`, `GRAFANA_USERNAME`, `GRAFANA_TOKEN`, and `GRAFANA_CLUSTER` from the process environment. Configure the URL from the Grafana Cloud Prometheus details for your stack; it can be the `/api/prom` base URL or full `/api/prom/api/v1/query` endpoint. The client uses HTTP Basic Authentication, a 20-second timeout, and never prints the credentials. Use the Prometheus instance/user ID for `GRAFANA_USERNAME` and a token with metrics-read access only for `GRAFANA_TOKEN`. `GRAFANA_CLUSTER` must exactly match a cluster label value returned by `up`; the collector discovers which returned label key contains it instead of assuming a key name. It does not default to an invented cluster.

For a local connectivity/label check, set those four variables in your shell and run:

```powershell
python scripts\test_grafana_metrics.py
```

The check prints the matched label key and series count, not the token or full response. If it fails, inspect the Prometheus endpoint path (`/api/prom/api/v1/query`), the read-only token/user ID, and the labels on `up` in Grafana Explore; then set `GRAFANA_CLUSTER` to the actual value.

When configured, `/api/troubleshoot` queries node-exporter series (`node_cpu_seconds_total`, `node_memory_MemTotal_bytes`, and `node_memory_MemAvailable_bytes`), kube-state-metrics series for pod restarts/readiness and deployment replicas, cAdvisor container CPU/memory/throttling series, and the app's `http_requests_total` and request-duration histogram. The collector uses the cluster label found in `up`, plus the expected namespace/workload selectors. A series that is absent or does not include correlatable labels is marked unavailable with the query and a diagnostic; it is not represented as zero. These metric names are queried as optional candidates and are not claimed available until returned by your data source. Container CPU is in cores, memory in bytes, throttling in seconds/second, request/error rate in requests/second, and latency in seconds. Node-level metrics remain separate context and are never assigned to a pod.

For the in-cluster application, provide the optional `ai-troubleshooter-runtime` Kubernetes Secret with keys `GRAFANA_PROM_URL`, `GRAFANA_USERNAME`, `GRAFANA_TOKEN`, `GRAFANA_CLUSTER`, `GEMINI_API_KEY`, and `GEMINI_MODEL`. The Deployment references these keys optionally, so absent configuration does not prevent the app from starting; the API reports telemetry as unavailable instead. Create/populate the Secret through your approved secret manager or secure operator workflow, not a committed YAML file. Apply namespace-scoped read-only permissions for pods, events, and pod logs when you want Kubernetes API evidence:

```powershell
kubectl apply -f k8s\troubleshooter-rbac.yaml
```

Run that command once using an identity authorized to create namespace Roles and RoleBindings. The routine GitHub deployer intentionally does not manage RBAC resources. This RoleBinding grants the `default` service account read access only in `ai-troubleshooter` for pods, events, logs, Deployments, and ReplicaSets. The collector uses in-cluster credentials in GKE and falls back to local kubeconfig for development. Do not expose `/api/troubleshoot` publicly without adding authentication/authorization; it can return event and log excerpts.

## AI SRE incident investigation and remediation

The AI SRE workflow is an additional operator tool; it does not replace or modify the existing `deploy.yml` pipeline or the Alloy scrape configuration.

### Triggers and evidence flow

- `.github/workflows/ai-failure-analysis.yml` continues to run after failed deployment/test workflows on `master`. It records repository, workflow, run ID/URL, branch, commit SHA, failed steps, all available build/image-push/deploy step results, bounded logs, and a safe commit diff. It classifies test, build, image-push/image-pull, deployment, rollout-timeout, and post-deployment health-check failures. Gemini output is labeled; if Gemini is absent or errors, the workflow publishes a rules-based, explicitly uncertain report.
- `.github/workflows/kubernetes-investigation.yml` runs every 15 minutes and can also be manually dispatched from `master`. It reads the configured namespace (pods, waiting/container states and pull errors, events, bounded recent logs, Deployments and ReplicaSets), checks exact deployed Artifact Registry image tags/digests read-only, queries optional Grafana Cloud Prometheus metrics, and retrieves bounded job/failed-step/log evidence for the deployment run matching the image commit (falling back to recent deployment history).
- It detects CrashLoopBackOff, ImagePullBackOff/ErrImagePull, OOMKilled, probe/readiness failure, restarts (3 or more), warning/scheduling/networking events, unavailable replicas, application health/error/latency signals, and high container utilization when matching request/limit metrics exist. Metrics are tagged as Grafana Cloud Prometheus data; absent/stale series are unavailable, never zero. The cluster label is discovered from `up`; configure `GRAFANA_CLUSTER` to the actual returned value (currently observed application labels include `cluster="gke-ai-k8s-monitoring"`, not necessarily the GKE cluster name `ai-k8s-cluster`).
- One open GitHub issue is maintained per stable incident fingerprint. The workflow refreshes its evidence run link instead of opening a duplicate issue. A seven-day, secret-minimized `incident-evidence` artifact is attached to each investigation run. Issue reports do not contain raw log lines. Close an issue when the incident is resolved; a later recurrence may then open a new issue with the same stable fingerprint.
- Each incident report includes a deterministic structured remediation proposal: incident and investigation-run IDs, evidence hash, confirmed cause and support, confidence, missing evidence, exact target/image/digest, expected impact, risk, and verification criteria. Gemini output remains hypothesis-only and cannot authorize executable actions. Missing-image publication and wrong-image deployment recommendations point to the existing reviewed release process; no image publication or Deployment image-change action is implemented. Failed pushes include failed steps and error category; the workflow does not expose a push retry operation.
- For image pulls the RCA distinguishes missing repositories/tags, failed pushes, URI mismatches, explicit registry authorization failures, and network/rate-limit errors; it does not promote a hypothesis to a root cause when evidence is inconclusive. Unknown network, DNS, pull-secret, and other causes request read-only evidence rather than speculative IAM, network, or secret changes. CrashLoopBackOff, probe, and resource failures after image startup remain startup/resource incidents, not ImagePullBackOff, and direct operators to logs, termination state, probes, configuration, and requests/limits. Grafana errors are reported separately and do not block sufficient Kubernetes/CI evidence.
- No image-pull condition can trigger automatic remediation. The workflow never grants IAM permissions or changes images, configuration, cluster security, or infrastructure. The only implemented operation is `rollout_restart`, and it is eligible only when fresh Kubernetes evidence confirms a transient node-not-ready/shutdown event on an unready pod, fresh Grafana metrics confirm application health and zero errors, logs are available, and the exact target Deployment has safe rolling-update capacity. Crash, OOM, pull, configuration, probe, scheduling, networking, missing-Grafana, ambiguous, and incomplete evidence remain report-only.

### GitHub setup

Configure these repository **Variables**:

| Variable | Value |
| --- | --- |
| `GCP_PROJECT_ID` | `abdulproject-510307` |
| `GCP_REGION` | `asia-south1` |
| `GKE_CLUSTER_NAME` | `ai-k8s-cluster` |
| `GAR_REPOSITORY` | `ai-k8s-repo` |
| `GCP_WIF_PROVIDER` | Full resource name of the existing, verified GitHub Workload Identity Federation provider |
| `GCP_INVESTIGATION_SERVICE_ACCOUNT` | Dedicated read-only investigation service-account email |
| `GCP_REMEDIATION_SERVICE_ACCOUNT` | Separate remediation service-account email |
| `INCIDENT_NAMESPACE` | Optional namespace to investigate (default: `ai-troubleshooter`) |
| `INCIDENT_WORKLOAD` | Optional workload used for application/deployment metrics (default: `ai-k8s-demo`) |
| `GRAFANA_CLUSTER` | Exact cluster label value returned by Grafana Cloud Prometheus `up` (for example `gke-ai-k8s-monitoring`) |
| `GEMINI_MODEL` | Approved Gemini model ID |

Configure these repository **Secrets**:

| Secret | Use |
| --- | --- |
| `GEMINI_API_KEY` | Optional Gemini RCA; without it, rules-based analysis is used |
| `GRAFANA_PROM_URL` | Grafana Cloud Prometheus `/api/prom` endpoint |
| `GRAFANA_USERNAME` | Prometheus instance/user ID |
| `GRAFANA_TOKEN` | Read-only Grafana Cloud metrics token |

`GITHUB_TOKEN` is supplied by Actions. The evidence-collection job has Actions/contents read and OIDC token issuance; a separate report-publisher job has only Actions/contents read and issue write for deduplicated reports. The remediation planning job has Actions/contents read and issue read; its execution job gets Actions/contents read, OIDC token issuance, and issue write only after policy selection. For local investigations, provide `GH_TOKEN` with Actions read scope; never paste credentials into command history or commit them.

For both dedicated Google service accounts, configure WIF to trust only this repository's protected `master` ref and the intended workflow identities, then grant the provider principal `roles/iam.workloadIdentityUser` on that service account. Use different accounts for read-only investigation and workload remediation; do not reuse the deployer identity. The existing deploy workflow and its credentials are deliberately unchanged.

GKE requires `container.clusters.get` to generate the `gcloud ... get-credentials` kubeconfig entry (typically through `roles/container.clusterViewer`). This cloud permission does not replace Kubernetes API authorization. See Google's [GKE RBAC guide](https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control) and [cluster access guide](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl). Have a cluster administrator verify the authenticated Kubernetes subjects and bind `k8s/investigation-rbac.yaml` and `k8s/remediation-rbac.yaml` in `ai-troubleshooter`. Investigation RBAC is read-only. Remediation RBAC permits bounded reads, `get` on the `ai-k8s-service` health proxy, and `patch` only on the named `ai-k8s-demo` Deployment.

Both identities need read-only `roles/artifactregistry.reader` on only the repository containing deployed images because the investigation and live pre-action validation verify exact image tags/digests. Neither identity needs registry write access, node-pool discovery, IAM policy write access, project Editor, cluster-admin, or permissions to alter cluster-wide security settings. GKE RBAC cannot restrict a Deployment patch to an annotation field; protect `master` and both workflow files with code review and branch protection, and do not bind the remediation Role if that boundary is insufficient.

### Automatic policy-controlled remediation

`.github/workflows/kubernetes-remediation.yml` is triggered only when the named investigation workflow completes. It obtains the exact source run ID from the trusted `workflow_run` event, downloads that run's `incident-evidence` artifact, and verifies the repository, source workflow path, `master` branch, completed/success status, event type, and 30-minute age. The evidence payload's run ID and SHA-256 are validated again before execution. No one enters a run ID, incident ID, or operation manually, and no GitHub Environment or reviewer wait is required.

The sole implemented action is `rollout_restart`, with a strict evidence gate. The deterministic policy requires all of the following:

1. Exactly one incident for `ai-troubleshooter/ai-k8s-demo` qualifies; the evidence is fresh and its Kubernetes/Grafana sources are available.
2. The Deployment is observed at its current generation, has at least two desired replicas, at least one available and one unavailable replica, and uses a `RollingUpdate` strategy with no more than one unavailable replica and at least one surge slot.
3. An unready pod has an explicit recent `NodeNotReady`, `NodeShutdown`, or equivalent node-unreachable event, with available pod logs and no image-pull, crash, OOM, configuration, probe, scheduling, or networking failure evidence.
4. Fresh Grafana metrics report application health `1` and error rate `0`. Missing/stale Grafana data or any ambiguous/contradictory evidence disables automatic action.

The investigation job uses its read-only Google identity. Only after the plan job selects and validates this one action does the execution job authenticate as the separate remediation identity. It rechecks live evidence and image references immediately before making exactly one patch: the restart annotation on the named Deployment. A marker comment on the open incident issue enforces one attempt for that incident across later scheduled runs; the outcome is also published to the issue. No model output is executable. Concurrency prevents overlapping remediation runs, and job/rollout/API timeouts bound execution.

Recovery is reported only after the rollout completes, every desired pod is Ready with the expected image/runtime digest, the application health endpoint is healthy, relevant post-action Kubernetes events have been checked, and available fresh Grafana metrics show no failure. A verification failure stops the workflow, publishes a needs-investigation summary, and instructs operators not to retry automatically. Missing Grafana data is explicitly reported and cannot satisfy the pre-action policy. Actions logs and the workflow summary provide the audit record; credentials are not included in evidence artifacts or summaries.

### GitHub and GCP configuration

Configure these repository **Variables**:

| Variable | Value |
| --- | --- |
| `GCP_PROJECT_ID` | Target GCP project ID |
| `GCP_REGION` | GKE location |
| `GKE_CLUSTER_NAME` | Target cluster |
| `GAR_REPOSITORY` | Repository containing deployed images |
| `GCP_WIF_PROVIDER` | Full resource name of the existing GitHub Workload Identity Federation provider |
| `GCP_INVESTIGATION_SERVICE_ACCOUNT` | Dedicated read-only investigation service-account email |
| `GCP_REMEDIATION_SERVICE_ACCOUNT` | Separate service account, granted only the documented namespaced workload permissions |
| `INCIDENT_NAMESPACE` | Optional investigation namespace (default: `ai-troubleshooter`) |
| `INCIDENT_WORKLOAD` | Optional workload used for investigation (default: `ai-k8s-demo`) |
| `GRAFANA_CLUSTER` | Exact cluster label value returned by Grafana Cloud Prometheus `up` |
| `GEMINI_MODEL` | Approved Gemini model ID |

Configure these repository **Secrets**:

| Secret | Use |
| --- | --- |
| `GEMINI_API_KEY` | Optional Gemini RCA; rules-based analysis is used when absent/unavailable |
| `GRAFANA_PROM_URL` | Grafana Cloud Prometheus `/api/prom` endpoint |
| `GRAFANA_USERNAME` | Prometheus instance/user ID |
| `GRAFANA_TOKEN` | Read-only Grafana Cloud metrics token |

The investigation job's `GITHUB_TOKEN` is limited to Actions/contents read and OIDC token issuance; a separate report-publisher job gets issue write to maintain deduplicated incident reports. The remediation planning job has Actions/contents read and issue read only. Its execution job gets Actions/contents read, OIDC token issuance, and issue write to record the one-shot attempt and outcome. Configure WIF to trust only this repository's protected `master` ref and the intended workflow identities; grant each dedicated service account only `roles/iam.workloadIdentityUser` for that provider. Do not reuse the deployer identity or create broad service-account keys.

The investigation and remediation identities need the GKE permissions required to obtain cluster credentials (`container.clusters.get`, normally through `roles/container.clusterViewer`) and Kubernetes API access through namespace-scoped Roles. Apply the templates in `k8s/investigation-rbac.yaml` and `k8s/remediation-rbac.yaml` with verified service-account subjects. Investigation RBAC is read-only. Remediation RBAC permits bounded reads, health-service proxy `get`, and `patch` only on `ai-troubleshooter/ai-k8s-demo`; the trusted code sends only the restart-annotation patch. Kubernetes RBAC cannot constrain patch fields, so protect the workflow and `master` with mandatory code review and branch protection; do not bind the remediation Role if that trust boundary is insufficient.

Both service accounts need repository-scoped `roles/artifactregistry.reader` because investigation and live pre-action validation inspect exact image tags/digests. Neither identity needs Artifact Registry write access, node-pool identity discovery, IAM policy write access, project Editor, cluster-admin, or any permission to modify cluster-wide security settings. The deployed workload's service account and existing Artifact Registry bindings must be configured by an administrator outside this workflow.

No remediation has been executed during implementation or tests. Start with the investigation workflow and confirm its generated evidence and the remediation job's plan summary before relying on this automation in production.

### Manual investigation, reports, and safe tests

For a local read-only investigation, install `requirements.txt`, use a kubeconfig with the same namespace-scoped read Role, and optionally set the GitHub/Grafana/Gemini variables above:

```powershell
python scripts\investigate_kubernetes.py collect --input .\incident-evidence.json
```

To publish/deduplicate issues manually, set a GitHub token scoped for issue write plus workflow-run read, then run:

```powershell
python scripts\investigate_kubernetes.py publish --input .\incident-evidence.json
```

Inspect the issue's incident ID, timestamp, severity, evidence references, source availability, analysis mode, hypotheses, recommended remediation, risk, recovery plan, and verification criteria. The attached evidence artifact is required for remediation and expires after seven days; the remediation validator additionally refuses evidence older than 30 minutes.

Unit and mocked integration-style tests cover GitHub Actions run handoffs, Kubernetes waiting states/events/ReplicaSets, Artifact Registry repository/tag/digest lookups, Grafana availability, Gemini/rules diagnosis, failed pushes, missing images, IAM/network evidence, inconclusive evidence, operation allowlisting, authorization boundaries, retry limits, and successful/failed post-remediation verification. They do not authenticate to GCP, call production APIs, or execute a cluster change:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q ai app collectors models scripts tests
```

### Illustrative report examples (not observations from your cluster)

- **ImagePullBackOff:** Confirmed fact: Kubernetes reports an image-pull failure for `ai-troubleshooter/ai-k8s-demo`. Hypothesis (low/medium confidence): the image tag or registry pull authorization may be wrong. Missing evidence: successful image-push result or node-side registry event details. Recommendation: compare the pod image with the latest successful build and inspect pull authorization; do not restart as a fix. Analysis mode is shown explicitly.
- **CrashLoopBackOff:** Confirmed fact: Kubernetes reports CrashLoopBackOff and a restart count. Hypothesis: startup/configuration or the deployed application may be responsible; this is not proven by the restart count. Recommendation: compare termination reason, redacted startup signals, image SHA, and deployment history; correct the cause before considering a restart.
- **Resource exhaustion:** Confirmed fact only when Kubernetes reports `OOMKilled`; exit code 137 alone is not treated as proof. Grafana utilization is reported with container scope and actual labels, and is not treated as causation. Recommendation: review request/limit and application memory behavior in a change; no resource setting is changed automatically.
- **Failed CI/CD build:** Confirmed fact: GitHub identifies a failed test/build/push/deploy/health step and provides a run URL, branch, commit SHA, and run ID. Hypothesis: the change may have caused the failure only when supported by the diff/log evidence. Missing Kubernetes/Grafana evidence is called out rather than inferred. No code or deployment change is made.

### Troubleshooting and disabling

- **No Grafana metric:** Inspect the exact query, returned labels, Alloy target, scrape job (`prometheus.scrape.app_metrics`), and `GRAFANA_CLUSTER`. The workflow marks an empty/missing series unavailable; it does not invent zeros or assume GKE Managed Prometheus metrics exist in Grafana Cloud.
- **Gemini failure:** Confirm `GEMINI_API_KEY` and `GEMINI_MODEL`. Empty, malformed, or unavailable Gemini responses switch to the labelled rules-based report; no raw credentials are included.
- **GitHub permission failure:** Check the workflow's minimal permissions and repository `GITHUB_TOKEN` policy. The investigation workflow needs issue write only for report deduplication and Actions read for deployment context/artifact retrieval.
- **GKE or registry access failure:** Check WIF provider conditions, `roles/container.clusterViewer` for `container.clusters.get`, the investigation identity's repository-scoped `roles/artifactregistry.reader`, the per-namespace RoleBinding subject, cluster endpoint network reachability, and the target namespace. Private control planes may require an appropriately networked self-hosted runner; do not broaden RBAC to cluster-admin.
- **Disable triggers:** Disable `AI SRE Kubernetes Investigation` to stop periodic collection and automatic remediation. The separate `AI SRE - read-only report` is manual-dispatch only. Preserve the existing deploy and failure-analysis workflows unless intentionally disabling those separately.

## Project files

```text
app/
  __init__.py                 Flask app, JSON request logs, and Prometheus instrumentation
  app.py                      Local application entry point
tests/
  test_app.py                 Endpoint, logging, configuration, and metrics tests
  test_grafana_metrics.py     Mocked Prometheus API and metric-scope tests
  test_observability_evidence.py Kubernetes evidence and AI-input tests
  test_analyze_github_failure.py
                              GitHub evidence and report safety tests
  test_remediate_incident.py Evidence, policy, handoff, and recovery tests
scripts/
  analyze_github_failure.py   Redacted GitHub Actions evidence analysis
  investigate_kubernetes.py  Read-only collection and deduplicated incident reports
  remediate_incident.py      Evidence validator and one-operation automatic executor
ai/
  sre_agent.py               Cross-source incident detection, RCA and fallback
  remediation_policy.py      Deterministic evidence gates for rollout restart
collectors/
  github_actions_collector.py Read-only deployment run metadata
  artifact_registry_collector.py Read-only repository/image/tag/digest checks
models/
  incident.py                Structured incident record
k8s/
  namespace.yaml              ai-troubleshooter namespace
  deployment.yaml             Two replicas, probes, resources, and Prometheus pod annotations
  service.yaml                ClusterIP application service
  servicemonitor.yaml         Optional Prometheus Operator scrape configuration
  investigation-rbac.yaml     Namespace-scoped investigation read access template
  remediation-rbac.yaml       Target-scoped remediation RBAC template
.github/workflows/
  deploy.yml                  Build, push, deploy, and verify on pushes to master
  ai-failure-analysis.yml     Analyze failed runs with Gemini and optional Grafana
  kubernetes-investigation.yml Scheduled/manual read-only incident detection
  kubernetes-remediation.yml  Trusted workflow_run policy-controlled remediation
Dockerfile                    Python 3.12 image; Gunicorn runs as a non-root user
.dockerignore                 Excludes local and repository files from image builds
.gitignore                    Excludes local environment and editor files from Git
requirements.txt              Flask, Gunicorn, Kubernetes, and Google Gen AI SDK
```

## Local development

Prerequisites: Python 3.12. From the project root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m app.app
```

The app listens on `http://localhost:8080`. Optional configuration:

```powershell
$env:APP_NAME = "AI Kubernetes Troubleshooter Demo"
$env:APP_VERSION = "1.0.0"
$env:ENVIRONMENT = "development"
$env:PORT = "8080"
python -m app.app
```

Check the API and metrics:

```powershell
Invoke-RestMethod http://localhost:8080/
Invoke-RestMethod http://localhost:8080/health
Invoke-RestMethod http://localhost:8080/ready
Invoke-RestMethod http://localhost:8080/api/info
Invoke-WebRequest http://localhost:8080/metrics
```

Run the tests:

```powershell
python -m unittest discover -s tests -v
```

## Docker

Prerequisite: Docker Desktop or another Docker-compatible engine.

```powershell
docker build -t ai-k8s-demo:local .
docker run --rm -p 8080:8080 ai-k8s-demo:local
```

In another terminal, call the local endpoints above, including `http://localhost:8080/metrics`. Inspect logs with `docker logs <CONTAINER_ID>`. The image uses `python:3.12-slim`, runs as a non-root user, and includes a `/health` Docker health check.

## Google Cloud and GKE setup

Replace placeholders with your own project, region, cluster, and repository values. The existing deployment workflow contains Workload Identity provider and service-account identifiers; configure matching Google Cloud resources or update those workflow inputs before deploying. Google Cloud billing and the Google Cloud CLI are required.

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable artifactregistry.googleapis.com container.googleapis.com
```

### Artifact Registry

Use the same region as the GKE cluster:

```bash
gcloud artifacts repositories create YOUR_GAR_REPOSITORY \
  --repository-format=docker \
  --location=YOUR_REGION \
  --description="AI Kubernetes Troubleshooter demo images"
```

### GKE cluster

This example creates an Autopilot cluster. Creating a cluster, external LoadBalancer, and monitoring resources can incur charges.

```bash
gcloud container clusters create-auto YOUR_GKE_CLUSTER --region YOUR_REGION
gcloud container clusters get-credentials YOUR_GKE_CLUSTER \
  --region YOUR_REGION \
  --project YOUR_PROJECT_ID
kubectl get nodes
```

## GitHub Actions deployment setup

The existing deployment workflow authenticates with Workload Identity Federation and a dedicated Google Cloud service account. It does not read a `GCP_CREDENTIALS` secret. The provider and service account are currently specified in `.github/workflows/deploy.yml`; configure those resources to match or update the workflow authentication inputs to your own values. Restrict the identity provider's attribute condition to this repository and the `master` branch.

Grant the deployer the Artifact Registry writer and GKE deployment permissions required by the workflow. For example:

```bash
gcloud iam service-accounts create github-deployer \
  --display-name="GitHub Actions GKE deployer"

DEPLOYER="github-deployer@YOUR_PROJECT_ID.iam.gserviceaccount.com"
gcloud artifacts repositories add-iam-policy-binding YOUR_GAR_REPOSITORY \
  --location=YOUR_REGION \
  --member="serviceAccount:${DEPLOYER}" \
  --role="roles/artifactregistry.writer"
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:${DEPLOYER}" \
  --role="roles/container.developer"
```

Add repository **Actions variables** in **Settings → Secrets and variables → Actions → Variables**:

| Variable | Value |
| --- | --- |
| `GCP_PROJECT_ID` | Your Google Cloud project ID |
| `GCP_REGION` | Region containing both the Artifact Registry repository and GKE cluster |
| `GKE_CLUSTER_NAME` | Your GKE cluster name |
| `GAR_REPOSITORY` | Your Artifact Registry Docker repository |

Push to `master` to run **Deploy AI Kubernetes Demo to GKE**. The workflow authenticates, builds an image tagged with `github.sha`, pushes it to Artifact Registry, substitutes `IMAGE_PLACEHOLDER`, applies the namespace/deployment/service, waits for rollout, and displays pods and service status. Provision `k8s/troubleshooter-rbac.yaml` separately with an authorized cluster operator; the deployer is not granted permission to create or modify Roles or RoleBindings. A failed rollout fails the workflow and prints deployment, pod, event, and log diagnostics.

### Gemini analysis of failed deployment runs

The separate **AI GitHub Actions Failure Analysis** workflow starts when the configured deployment or test workflow completes on `master`. It skips successful runs. For a failed run, it checks out only trusted analyzer code from the default branch, retrieves the original workflow logs, failed-step metadata, commit message, and eligible text patches through the GitHub API, then writes an RCA and source run URL/commit SHA to the Actions job summary. When the read-only GKE identity is configured, it also collects current pod/deployment/events status and diagnostic log markers, correlates image tags with the failed commit, and includes optional Grafana data. Raw Kubernetes log lines are not included in the report or sent to Gemini. It does not check out or execute the failed commit, download artifacts, post comments, modify pull requests, or remediate Kubernetes.

Configure these repository settings in **Settings → Secrets and variables → Actions**:

| Setting | Type | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Secret | Gemini API key; never place it in a variable or source file |
| `GEMINI_MODEL` | Variable | A model name supported by the Gemini API project |
| `GRAFANA_PROM_URL` | Secret (optional) | Grafana Cloud Prometheus `/api/prom` base URL or full query endpoint |
| `GRAFANA_USERNAME` | Secret (optional) | Prometheus stack/user ID for Basic Authentication |
| `GRAFANA_TOKEN` | Secret (optional) | Read-only metrics token; no write scopes |
| `GRAFANA_CLUSTER` | Variable (optional) | Exact cluster value identified in returned `up` labels |

The built-in `GITHUB_TOKEN` is provided by GitHub Actions; no personal access token is needed. The analysis workflow grants it `actions: read` and `contents: read` to retrieve run logs/jobs and commit information, plus `id-token: write` only to obtain the separate, read-only investigation identity through WIF. It never uses the deployment service account. If the GCP investigation variables are absent, the workflow skips GKE authentication and marks Kubernetes evidence unavailable. Optional Grafana values are passed only to this failed-workflow analysis; create a dedicated read-only token and do not make it available to pull-request workflows or jobs that execute pull-request code. No GKE credentials are needed to query Prometheus.

The analysis job uses Python 3.12 and installs only `google-genai>=2.28.0,<3.0.0`, `requests>=2.32.3,<3.0.0`, and the existing Kubernetes client dependency `kubernetes>=30,<40`. `GEMINI_MODEL` must name a model available to your Gemini API project; model availability varies by project and can change. Grafana and Kubernetes collection are optional: when credentials or access are missing, the report marks the corresponding evidence unavailable and still analyzes the GitHub failure.

The Gemini request contains bounded excerpts from workflow logs, the commit message, selected changed-file patches, and—if configured—bounded read-only Grafana metric values and labels. Likely credential files (including `.env` and private-key files) are excluded, and common secret patterns are redacted, but automated redaction cannot guarantee that every sensitive value is removed. This evidence is sent to the Gemini API; review your organization's data-handling requirements before enabling the secrets.

Logs, commit messages, diffs, and metrics are treated as untrusted evidence and instructions within them are ignored. The analyzer runs from the workflow's default-branch checkout and retrieves the failed commit's metadata/diff via the GitHub API; no code is checked out or executed from the failed commit. Artifacts from the failed run are never downloaded. Missing GitHub evidence fails the job visibly. If Gemini is absent, rate-limited, or unavailable, the labeled rules-based fallback still publishes an explicitly uncertain report; missing or inaccessible Kubernetes/Grafana evidence is called out rather than treated as zero.

For local unit tests of log parsing and report safeguards:

```powershell
python -m unittest discover -s tests -v
```

## Grafana Cloud Kubernetes Monitoring on GKE (Autopilot)

The GKE installation uses the official `grafana/k8s-monitoring` chart pinned to `4.5.3`. The checked-in `grafana-values.yaml` is the upstream default values file for that chart version, not a configured release. `grafana-cloud-values.yaml` and `scripts/install-grafana-cloud-local.ps1` are retained for the separate Docker Desktop setup; do not use them for this GKE installation.

The GKE values enable cluster metrics, cluster events, Kubernetes-API pod log collection for `ai-troubleshooter`, and annotation-based scraping of the Flask `/metrics` endpoint. They set the remote-write `cluster` label to `ai-k8s-cluster`. This is configured for GKE Autopilot: Node Exporter/host metrics are disabled. The supplied GKE inspection found a managed kube-state-metrics StatefulSet but no Service or EndpointSlice, so it cannot be configured as a chart Service scrape target. The pinned chart therefore deploys its own kube-state-metrics Service in `monitoring`; the GKE-managed StatefulSet and Google-managed collectors remain untouched. The GKE-managed component continues to serve Google Cloud monitoring; Alloy scrapes the chart-managed instance for the Grafana Cloud path. Review ingestion in both backends after installation to confirm this does not duplicate billable collection.

The Prometheus remote-write URL ends with `/api/prom/push`; the query script uses the separate `/api/prom/api/v1/query` endpoint. Logs require the Loki push URL. Both destinations use Kubernetes Secret key references, not literal credentials in Helm values. The installer prompts locally for the Prometheus and Loki instance IDs if their environment variables are unset, securely prompts for a replacement `metrics:write` token, and accepts `GRAFANA_LOKI_TOKEN` for a replacement `logs:write` token (falling back to a non-echoing secure prompt when it is unset). It removes `GRAFANA_LOKI_TOKEN` from the current process environment on exit. No Fleet Management credential is needed for the GKE chart configuration.

**Credential incident:** a Grafana token was pasted into chat and must be revoked in Grafana Cloud before proceeding. Do not reuse it or paste a replacement into chat. Create new least-privilege tokens after revocation.

Authenticate to the intended cluster and verify the existing application before installing monitoring:

```powershell
gcloud config set project abdulproject-510307
gcloud container clusters get-credentials ai-k8s-cluster `
  --region asia-south1 `
  --project abdulproject-510307
kubectl config current-context
kubectl get deployment ai-k8s-demo --namespace ai-troubleshooter
kubectl get service ai-k8s-service --namespace ai-troubleshooter
kubectl get pods --namespace gke-gmp-system
kubectl get pods --all-namespaces | Select-String kube-state-metrics
helm list --all-namespaces
```

The current context must be `gke_abdulproject-510307_asia-south1_ai-k8s-cluster`, and the application resources must still be present. For this cluster, inspection found a GKE-managed pod labelled `app.kubernetes.io/name=gke-managed-kube-state-metrics` in `gke-managed-cim`, but no matching Service or EndpointSlice. The Helm chart needs a discoverable KSM Service endpoint, so the GKE values explicitly set `telemetryServices.kube-state-metrics.deploy: true`. They do not point at that nonexistent GKE-managed Service or alter the managed StatefulSet. This is a separate Grafana-targeted instance; Google-managed monitoring remains enabled.

Before installing, validate and review the pinned chart output:

```powershell
helm repo add grafana https://grafana.github.io/helm-charts --force-update
helm repo update grafana
helm pull grafana/k8s-monitoring --version 4.5.3 --destination $env:TEMP
helm lint "$env:TEMP\k8s-monitoring-4.5.3.tgz" --namespace monitoring `
  --values grafana-cloud-gke-values.yaml
helm template grafana-cloud grafana/k8s-monitoring --version 4.5.3 `
  --namespace monitoring --values grafana-cloud-gke-values.yaml
```

For a live Helm diff, install the Helm Diff plugin if needed and ensure the target GKE context is active:

```powershell
helm plugin install https://github.com/databus23/helm-diff
helm diff upgrade --allow-unreleased grafana-cloud grafana/k8s-monitoring `
  --version 4.5.3 --namespace monitoring `
  --values grafana-cloud-gke-values.yaml
```

`--allow-unreleased` is needed because `helm list -A` currently reports no releases. Review the diff and stop if it includes the application Deployment, Service, namespace, or GKE-managed resources. The installer checks the target context and existing app resources, renders the chart before creating the monitoring namespace or Secret, then installs the release.

Set the Prometheus tenant/instance ID (already supplied for this stack) and the Loki tenant/instance ID in the current PowerShell session. These are identifiers, not tokens. You can set the Loki username in `GRAFANA_LOKI_USERNAME` and provide a freshly issued `logs:write` token in `GRAFANA_LOKI_TOKEN`; alternatively, the installer securely prompts for the token. Do not assign a token using a literal command in shell history. The installer securely prompts for a `metrics:write` token, writes the credentials Secret via standard input (not command-line arguments or Helm values), pins the chart, and checks the current GKE context and application resources before installing:

```powershell
$env:GRAFANA_PROM_USERNAME = "3640099"
$env:GRAFANA_LOKI_USERNAME = "<Loki instance ID from Grafana Cloud>"
# Optional: set this from your approved secret manager or a secure process environment.
# If omitted, the installer prompts without echoing the token.
# $env:GRAFANA_LOKI_TOKEN = ...
.\scripts\install-grafana-cloud-gke.ps1
Remove-Item Env:GRAFANA_PROM_USERNAME, Env:GRAFANA_LOKI_USERNAME
```

The installer removes `GRAFANA_LOKI_TOKEN` from the current process environment when it exits. For an interactive setup, its secure prompt is preferred over manually assigning the variable.

The installer updates the local Helm repository cache, applies only the `monitoring` namespace and `grafana-cloud-write` Secret, then installs/upgrades the `grafana-cloud` Helm release. It does not change the application Deployment, Service, namespace, GKE cluster, Google-managed monitoring, or application image. It does not delete Alloy pods after Helm.

Verify the release and collector readiness:

```powershell
helm status grafana-cloud --namespace monitoring
kubectl get pods --namespace monitoring -o wide
kubectl get daemonsets,statefulsets,deployments --namespace monitoring
kubectl get events --namespace monitoring --sort-by=.lastTimestamp
```

All Alloy and operator pods should become `Running` and `Ready`. For authentication or remote-write failures, inspect the relevant Alloy pod logs using the pod names returned by `kubectl get pods -n monitoring`; do not print or share Secret contents. HTTP 401/403 indicates a wrong tenant ID, revoked token, or missing write scope. In Grafana Cloud Explore, first verify that samples are arriving and inspect the actual `cluster` label in the returned `up` series; the currently observed application series use `gke-ai-k8s-monitoring`. The example values file sets `cluster.name` to `ai-k8s-cluster`, so do not assume its value matches an already-running stack. The Prometheus test below requires a separate read-only `metrics:read` token; do not reuse either write token.

The Prometheus scrape annotations are in the Deployment template for future rollouts. To enable discovery on the already-running pods without restarting them, annotate those pods after installation:

```powershell
kubectl annotate pods --namespace ai-troubleshooter `
  --selector app=ai-k8s-demo `
  prometheus.io/scrape=true `
  prometheus.io/path=/metrics `
  prometheus.io/port=8080 `
  prometheus.io/scheme=http `
  --overwrite
```

Set up the local Prometheus query check without placing its read token in shell history:

```powershell
$env:GRAFANA_PROM_URL = "https://prometheus-prod-43-prod-ap-south-1.grafana.net/api/prom"
$env:GRAFANA_USERNAME = "3640099"
$env:GRAFANA_CLUSTER = "ai-k8s-cluster"
$secureReadToken = Read-Host "Enter a separate Grafana metrics:read token" -AsSecureString
$env:GRAFANA_TOKEN = (New-Object System.Net.NetworkCredential("", $secureReadToken)).Password
python scripts\test_grafana_metrics.py
Remove-Item Env:GRAFANA_PROM_URL, Env:GRAFANA_USERNAME, Env:GRAFANA_CLUSTER, Env:GRAFANA_TOKEN
```

The test requires non-empty results for `up`, node CPU/memory capacity from kube-state-metrics, and the `ai-k8s-demo` pod inventory, CPU, and memory. Missing series return actionable failures rather than being treated as zero. A successful local API query verifies read access and telemetry availability, but not by itself the health of every scrape target.

Useful Grafana Cloud Explore queries for the currently observed application series (`cluster="gke-ai-k8s-monitoring"`):

```promql
up{cluster="gke-ai-k8s-monitoring"}
kube_node_status_capacity{cluster="gke-ai-k8s-monitoring",resource="cpu"}
kube_node_status_capacity{cluster="gke-ai-k8s-monitoring",resource="memory"}
sum by (node) (rate(container_cpu_usage_seconds_total{cluster="gke-ai-k8s-monitoring",container!="",pod!=""}[5m]))
sum by (node) (container_memory_working_set_bytes{cluster="gke-ai-k8s-monitoring",container!="",pod!=""})
sum by (pod, container) (rate(container_cpu_usage_seconds_total{cluster="gke-ai-k8s-monitoring",namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!=""}[5m]))
sum by (pod, container) (container_memory_working_set_bytes{cluster="gke-ai-k8s-monitoring",namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!=""})
kube_pod_status_ready{cluster="gke-ai-k8s-monitoring",namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*"}
sum by (pod) (rate(http_requests_total{cluster="gke-ai-k8s-monitoring",namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*"}[5m]))
```

For logs, use the Grafana Cloud Loki data source with `{cluster="gke-ai-k8s-monitoring", namespace="ai-troubleshooter", pod=~"ai-k8s-demo-.*"}`. If a query returns no data, inspect the actual labels on returned series in Explore rather than assuming a label exists; verify Alloy target health, annotations, existing kube-state-metrics discovery, and token scopes. GKE Autopilot does not expose Node Exporter host metrics; node capacity and per-node usage available through Kubelet/cAdvisor are distinct from host-level Node Exporter CPU metrics. The checked-in GKE values may label a newly installed stack differently; use the returned label value and set `GRAFANA_CLUSTER` accordingly.

Rollback only the monitoring release and its write credential Secret:

```powershell
helm uninstall grafana-cloud --namespace monitoring
kubectl delete secret grafana-cloud-write --namespace monitoring
```

Do not delete the `monitoring` namespace: it may contain resources not owned by this Helm release. No deployment or live-cluster validation was performed from this repository workspace.

## Grafana Cloud (local Docker Desktop)

This setup installs Grafana Kubernetes Monitoring into the `monitoring` namespace and configures Alloy remote configuration for the local `docker-desktop` cluster. The local override file must be passed after `grafana-cloud-values.yaml` so its values take precedence.

Create a Grafana Cloud access policy token for the correct stack. The token must start with `glc_` and include these scopes:

- `fleet-management:read`
- `metrics:write`
- `logs:write`
- `traces:write`

Do not commit the token, put it in a values file, or paste it into chat. In PowerShell, set it for the current terminal session and run the installer from the project directory:

```powershell
$secureToken = Read-Host "Enter Grafana Cloud access policy token" -AsSecureString
$env:GRAFANA_FLEET_TOKEN = (New-Object System.Net.NetworkCredential("", $secureToken)).Password
$env:GRAFANA_FLEET_USERNAME = Read-Host "Enter Grafana Cloud Fleet instance ID"
.\scripts\install-grafana-cloud-local.ps1
Remove-Item Env:GRAFANA_FLEET_TOKEN, Env:GRAFANA_FLEET_USERNAME
```

The installer creates or updates the `grafana-cloud-remote-config` Secret and installs/upgrades the `grafana/k8s-monitoring` chart. The token is not echoed by the prompt or written into the repository; remove it from the session environment when installation finishes. Secret data is passed to Kubernetes via standard input rather than command-line arguments. The installer does not delete pods after the Helm upgrade. The chart's `node-exporter` is disabled because Docker Desktop Kubernetes does not support the required host mount.

Verify collector startup with `kubectl get pods -n monitoring`. An Alloy `invalid token` error usually means the token is wrong, expired, belongs to a different Grafana Cloud stack, or the Fleet Management user ID is incorrect.

The values file includes a TODO for the Prometheus, Loki, and OTLP destinations generated by the Grafana Cloud Kubernetes Monitoring setup page. Add the actual destination settings from that page before expecting telemetry to appear in Grafana Cloud.

## Deploy Prometheus

The app pod template has the standard annotations `prometheus.io/scrape: "true"`, `prometheus.io/path: /metrics`, and `prometheus.io/port: "8080"`. Prometheus discovery must be configured to honor these annotations. The annotations alone do not install or configure Prometheus. The `ai-k8s-demo` Service exposes the port named `http`, also used by the optional ServiceMonitor.

For pod CPU, memory, restarts, readiness, resources, and deployment replica state, install the standard Kubernetes monitoring components as well: kube-state-metrics and kubelet/cAdvisor metrics. Node Exporter is useful for node-level panels. Neither these components nor a custom Kubernetes collector are added to the Flask application.

### Option 1: Prometheus Operator

One beginner-friendly option is `kube-prometheus-stack`, which installs Prometheus Operator, Prometheus, Grafana, kube-state-metrics, and node exporters. Install Helm first, then:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace
```

Deploy this app with the GitHub workflow (or apply its manifests manually). Then create the optional ServiceMonitor:

```bash
kubectl apply -f k8s/servicemonitor.yaml
```

The example ServiceMonitor has `release: prometheus`. Confirm that it matches your Prometheus Operator's `serviceMonitorSelector`; edit that label if your Helm release name or selector is different. Confirm that the Operator also selects ServiceMonitors in the `ai-troubleshooter` namespace. The ServiceMonitor is deliberately not applied by the app deployment workflow, so a cluster without the Operator's CRD will not fail application deployment.

Check the target in Prometheus under **Status → Targets**. Port-forward the Prometheus service to access its UI locally:

```bash
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090
```

Open `http://localhost:9090`.

### Option 2: Prometheus without the Operator

Install a regular Prometheus chart (the chart includes optional Kubernetes metric exporters) or use an existing Prometheus server:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/prometheus \
  --namespace monitoring --create-namespace
```

Add the following scrape job to that server's `prometheus.yml` under `scrape_configs`. The Prometheus service account needs permission to list and watch pods in the `ai-troubleshooter` namespace (or across namespaces if it discovers all pods). The job retains only explicitly annotated pods and uses the pod's IP, port annotation, and metrics path:

```yaml
- job_name: ai-k8s-demo
  kubernetes_sd_configs:
    - role: pod
  relabel_configs:
    - source_labels: [__meta_kubernetes_namespace]
      action: keep
      regex: ai-troubleshooter
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
      action: keep
      regex: "true"
    - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
      action: replace
      target_label: __metrics_path__
      regex: (.+)
    - source_labels: [__meta_kubernetes_namespace]
      action: replace
      target_label: namespace
    - source_labels:
        - __address__
        - __meta_kubernetes_pod_annotation_prometheus_io_port
      action: replace
      regex: ([^:]+)(?::\d+)?;(\d+)
      replacement: $1:$2
      target_label: __address__
```

Allow the Prometheus server's service account to discover pods in this application's namespace. For the example `monitoring` namespace and `prometheus-server` service account:

```bash
kubectl create role prometheus-pod-discovery \
  --verb=get,list,watch --resource=pods -n ai-troubleshooter
kubectl create rolebinding prometheus-pod-discovery \
  --role=prometheus-pod-discovery \
  --serviceaccount=monitoring:prometheus-server \
  -n ai-troubleshooter
```

If the Role or RoleBinding already exists, update it with `kubectl edit role` / `kubectl edit rolebinding` rather than repeatedly creating it. If your Prometheus release uses a different service account or namespace, substitute those values.

For the Helm chart above, save the scrape job in the chart's values/configuration for `serverFiles.prometheus.yml` so upgrades retain it. As a quick first setup, port-forward Prometheus, open `http://localhost:9090/config` to inspect its active configuration, then edit the Helm-managed Prometheus ConfigMap to add the job under `scrape_configs` while preserving existing jobs:

```bash
kubectl edit configmap prometheus-server -n monitoring
kubectl rollout restart deployment/prometheus-server -n monitoring
kubectl rollout status deployment/prometheus-server -n monitoring
```

For a durable install, put the same job in the Helm values and run `helm upgrade prometheus prometheus-community/prometheus --namespace monitoring -f YOUR_VALUES_FILE.yaml`. Check **Status → Targets** and confirm `ai-k8s-demo` targets are `UP`. Port-forward the chart's server service:

```bash
kubectl port-forward -n monitoring svc/prometheus-server 9090:80
```

Open `http://localhost:9090`.

### Kubernetes infrastructure metrics

The `kube-prometheus-stack` option provides common kube-state-metrics series for workload state and kubelet/cAdvisor series for container resource use. The plain Prometheus chart can install kube-state-metrics and Node Exporter; verify chart components and scrape targets in your chosen version. GKE Managed Service for Prometheus is another option; its managed collection and Grafana data-source setup differ from self-managed Prometheus and must be configured in Google Cloud.

## Grafana setup

Install Grafana with the Operator stack above, or deploy it separately. With `kube-prometheus-stack` installed as release `prometheus`, the Grafana UI can be reached locally with:

```bash
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
```

Open `http://localhost:3000`. Retrieve the initial admin password from the generated Kubernetes secret for the Helm release; change it after first login. For separately installed Grafana, use its own documented install and credential setup.

In Grafana, go to **Connections → Data sources → Add data source → Prometheus**:

- **Operator stack URL (release `prometheus`):** `http://prometheus-kube-prometheus-prometheus.monitoring.svc:9090`
- **Non-Operator Helm chart URL (release `prometheus`):** `http://prometheus-server.monitoring.svc.cluster.local`
- **Access:** Server (Grafana makes the request from inside the cluster)
- Click **Save & test**. Prometheus and Grafana must be able to reach each other over their Kubernetes services.

Create a dashboard, set the default time range to **Last 1 hour**, and use a 30-second refresh. Add the following panels as Prometheus time-series or stat panels. These queries assume Prometheus labels from the app and standard kube-state-metrics/cAdvisor installations. The app's endpoint label is a bounded Flask route template.

### Application Overview dashboard

| Panel | Example PromQL |
| --- | --- |
| Request rate (requests/s) | `sum(rate(http_requests_total{namespace="ai-troubleshooter"}[5m]))` |
| HTTP 2xx rate | `sum(rate(http_requests_total{namespace="ai-troubleshooter",status=~"2.."}[5m]))` |
| HTTP 4xx rate | `sum(rate(http_requests_total{namespace="ai-troubleshooter",status=~"4.."}[5m]))` |
| HTTP 5xx rate | `sum(rate(http_requests_total{namespace="ai-troubleshooter",status=~"5.."}[5m]))` |
| Request latency p50 (seconds) | `histogram_quantile(0.50, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))` |
| Request latency p95 (seconds) | `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))` |
| Request latency p99 (seconds) | `histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))` |
| Application health | `application_health_status` |
| Requests during selected time range | `sum(increase(http_requests_total[$__range]))` |

The application queries use the `namespace` target label, which is attached automatically by the Prometheus Operator or explicitly by the non-Operator scrape job above.

### Kubernetes Overview dashboard

These panels filter to the application's namespace and pods:

| Panel | Example PromQL |
| --- | --- |
| Total application pods | `count(kube_pod_info{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*"})` |
| Running pods | `sum(kube_pod_status_phase{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",phase="Running"})` |
| Ready pods | `sum(kube_pod_status_ready{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",condition="true"})` |
| Pod restarts in the last hour | `sum by (pod) (increase(kube_pod_container_status_restarts_total{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*"}[1h]))` |
| CPU usage (cores) by pod | `sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!="",image!=""}[5m]))` |
| Memory working set (bytes) by pod | `sum by (pod) (container_memory_working_set_bytes{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!="",image!=""})` |
| CPU requests (cores) | `sum(kube_pod_container_resource_requests{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",resource="cpu",unit="core"})` |
| Memory limits (bytes) | `sum(kube_pod_container_resource_limits{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",resource="memory",unit="byte"})` |
| Desired replicas | `kube_deployment_spec_replicas{namespace="ai-troubleshooter",deployment="ai-k8s-demo"}` |
| Available replicas | `kube_deployment_status_replicas_available{namespace="ai-troubleshooter",deployment="ai-k8s-demo"}` |
| Unavailable replicas | `kube_deployment_status_replicas_unavailable{namespace="ai-troubleshooter",deployment="ai-k8s-demo"}` |

### Incident Investigation dashboard

Use time-series panels for the first four rows and stat/table panels for pod-level state:

| Incident panel | Example PromQL |
| --- | --- |
| Restarting pods (restarts in 15m) | `sum by (pod) (increase(kube_pod_container_status_restarts_total{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*"}[15m])) > 0` |
| Failed pods | `sum by (pod) (kube_pod_status_phase{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",phase="Failed"})` |
| Pending pods | `sum by (pod) (kube_pod_status_phase{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",phase="Pending"})` |
| High CPU (usage / request > 80%) | `100 * sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!="",image!=""}[5m])) / on (pod) sum by (pod) (kube_pod_container_resource_requests{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",resource="cpu",unit="core"}) > 80` |
| High memory (working set / limit > 80%) | `100 * sum by (pod) (container_memory_working_set_bytes{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",container!="",image!=""}) / on (pod) sum by (pod) (kube_pod_container_resource_limits{namespace="ai-troubleshooter",pod=~"ai-k8s-demo-.*",resource="memory",unit="byte"}) > 80` |
| HTTP 5xx rate | `sum(rate(http_requests_total{status=~"5.."}[5m]))` |
| HTTP 5xx share of requests | `sum(rate(http_requests_total{status=~"5.."}[5m])) / clamp_min(sum(rate(http_requests_total[5m])), 1e-9)` |
| High request latency (p95 > 1s) | `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) > 1` |
| Unavailable deployment replicas | `kube_deployment_status_replicas_unavailable{namespace="ai-troubleshooter",deployment="ai-k8s-demo"}` |

Set useful panel thresholds (for example, health `0`, HTTP 5xx share above `1%`, p95 latency above `1s`, or resource usage above `80%`) to make incidents visible. Tune thresholds to the workload. Some metric names/labels vary by exporter version; use Prometheus **Graph** autocomplete to check what your installation exposes.

## Verify and troubleshoot

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud container clusters get-credentials YOUR_GKE_CLUSTER --region YOUR_REGION
kubectl get nodes
kubectl get pods -n ai-troubleshooter
kubectl get svc -n ai-troubleshooter
kubectl describe pod POD_NAME -n ai-troubleshooter
kubectl logs POD_NAME -n ai-troubleshooter
kubectl get events -n ai-troubleshooter --sort-by=.lastTimestamp
kubectl rollout status deployment/ai-k8s-demo -n ai-troubleshooter
```

Confirm the app endpoint responds and the Prometheus target is `UP`. The external service IP can take a few minutes:

```bash
kubectl get service ai-k8s-demo -n ai-troubleshooter --watch
```

When assigned, check `http://EXTERNAL_IP/`, `/health`, `/ready`, `/api/info`, or `/metrics`.

## Existing application troubleshooting API

The optional `/api/troubleshoot` endpoint remains a separate read-only application feature. The GitHub Actions AI SRE workflows described above provide scheduled/manual read-only investigation and evidence-gated automatic remediation.
