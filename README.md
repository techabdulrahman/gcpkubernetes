# AI Kubernetes Troubleshooter Demo

A small Flask REST API deployed to Google Kubernetes Engine (GKE), instrumented with Prometheus metrics and ready to visualize in Grafana. The repository also contains a Gemini-powered Kubernetes troubleshooter and a separate GitHub Actions failure-analysis workflow.

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

This RoleBinding grants the `default` service account read access only in `ai-troubleshooter`. The collector uses in-cluster credentials in GKE and falls back to local kubeconfig for development. Do not expose `/api/troubleshoot` publicly without adding authentication/authorization; it can return event and log excerpts.

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
scripts/
  analyze_github_failure.py   Redacted GitHub Actions evidence analysis
k8s/
  namespace.yaml              ai-troubleshooter namespace
  deployment.yaml             Two replicas, probes, resources, and Prometheus pod annotations
  service.yaml                External LoadBalancer application service
  servicemonitor.yaml         Optional Prometheus Operator scrape configuration
.github/workflows/
  deploy.yml                  Build, push, deploy, and verify on pushes to master
  ai-failure-analysis.yml     Analyze failed runs with Gemini and optional Grafana
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

Push to `master` to run **Deploy AI Kubernetes Demo to GKE**. The workflow authenticates, builds an image tagged with `github.sha`, pushes it to Artifact Registry, substitutes `IMAGE_PLACEHOLDER`, applies the namespace/deployment/service, waits for rollout, and displays pods and service status. A failed rollout fails the workflow and prints deployment, pod, event, and log diagnostics.

### Gemini analysis of failed deployment runs

The separate **AI GitHub Actions Failure Analysis** workflow starts when **Deploy AI Kubernetes Demo to GKE** completes on `master`. It skips successful runs. For a failed run, it checks out only trusted analyzer code from the default branch, retrieves the original workflow logs, failed-step metadata, commit message, and eligible text patches through the GitHub API, then writes the Gemini report and source run URL/commit SHA to the Actions job summary. It does not check out or execute the failed commit, download artifacts, post comments, modify pull requests, or remediate Kubernetes.

Configure these repository settings in **Settings → Secrets and variables → Actions**:

| Setting | Type | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Secret | Gemini API key; never place it in a variable or source file |
| `GEMINI_MODEL` | Variable | A model name supported by the Gemini API project |
| `GRAFANA_PROM_URL` | Secret (optional) | Grafana Cloud Prometheus `/api/prom` base URL or full query endpoint |
| `GRAFANA_USERNAME` | Secret (optional) | Prometheus stack/user ID for Basic Authentication |
| `GRAFANA_TOKEN` | Secret (optional) | Read-only metrics token; no write scopes |
| `GRAFANA_CLUSTER` | Variable (optional) | Exact cluster value identified in returned `up` labels |

The built-in `GITHUB_TOKEN` is provided by GitHub Actions; no personal access token is needed. The analysis workflow explicitly grants it only `actions: read` and `contents: read` to retrieve run logs/jobs and commit information. It does not receive the deployment's Google Cloud identity or `id-token: write` permission. Optional Grafana values are passed only to this failed-`master`-deployment workflow; create a dedicated read-only token and do not make it available to pull-request workflows or jobs that execute pull-request code. No GKE credentials are needed to query Prometheus.

The analysis job uses Python 3.12 and installs only the analyzer dependencies `google-genai>=2.28.0,<3.0.0` and `requests>=2.32.3,<3.0.0`, matching `requirements.txt`; it does not install unrelated application dependencies. `GEMINI_MODEL` must name a model available to your Gemini API project; model availability varies by project and can change. Grafana collection is optional: if any of the four Grafana settings are missing or a query fails, the report includes an unavailable diagnostic and still analyzes the GitHub failure.

The Gemini request contains bounded excerpts from workflow logs, the commit message, selected changed-file patches, and—if configured—bounded read-only Grafana metric values and labels. Likely credential files (including `.env` and private-key files) are excluded, and common secret patterns are redacted, but automated redaction cannot guarantee that every sensitive value is removed. This evidence is sent to the Gemini API; review your organization's data-handling requirements before enabling the secrets.

Logs, commit messages, diffs, and metrics are treated as untrusted evidence and instructions within them are ignored. The analyzer runs from the workflow's default-branch checkout and retrieves the failed commit's metadata/diff via the GitHub API; no code is checked out or executed from the failed commit. Artifacts from the failed run are never downloaded. If GitHub evidence is missing, a rate limit is reached, the Gemini configuration is absent, or Gemini fails, the job summary reports that analysis was unavailable and the analysis job fails visibly.

For local unit tests of log parsing and report safeguards:

```powershell
python -m unittest discover -s tests -v
```

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
.\scripts\install-grafana-cloud-local.ps1
Remove-Item Env:GRAFANA_FLEET_TOKEN
```

The installer creates or updates the `grafana-cloud-remote-config` Secret and installs/upgrades the `grafana/k8s-monitoring` chart. The token is not echoed by the prompt or written into the repository; remove it from the session environment when installation finishes. The chart's `node-exporter` is disabled because Docker Desktop Kubernetes does not support the required host mount.

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

## Future AI troubleshooting architecture

The future troubleshooting agent can combine Prometheus queries with Kubernetes API evidence to investigate restarts, CPU or memory pressure, increasing HTTP 5xx rates, latency, failed deployments, and availability. It may use Kubernetes tools such as `get_pods()`, `get_pod_logs()`, `get_pod_events()`, `describe_pod()`, `get_deployment()`, `get_services()`, and `get_nodes()`, alongside Prometheus and Grafana. A later phase may add GitHub API context for changes and deployments. **No AI agent, model SDK, or remediation automation is implemented here.**
