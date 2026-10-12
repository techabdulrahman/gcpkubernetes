$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:GRAFANA_FLEET_TOKEN)) {
    Write-Error "GRAFANA_FLEET_TOKEN is empty. Set it to a Grafana Cloud access policy token before running this script."
    exit 1
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to ensure the monitoring namespace exists."
    }

    kubectl create secret generic grafana-cloud-remote-config -n monitoring --from-literal=username=1857938 --from-literal=password=$env:GRAFANA_FLEET_TOKEN --dry-run=client -o yaml | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create or update the Grafana remote-config Secret."
    }

    helm upgrade --install grafana-cloud grafana/k8s-monitoring -n monitoring --create-namespace -f grafana-cloud-values.yaml -f grafana-cloud-local-overrides.yaml
    if ($LASTEXITCODE -ne 0) {
        throw "Grafana Cloud Kubernetes Monitoring Helm upgrade failed."
    }

    kubectl delete pod -n monitoring -l app.kubernetes.io/name=alloy
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restart Alloy pods."
    }

    kubectl get pods -n monitoring
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve monitoring pod status."
    }
}
finally {
    Pop-Location
}
