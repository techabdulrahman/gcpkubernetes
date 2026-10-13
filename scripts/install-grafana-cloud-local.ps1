$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:GRAFANA_FLEET_TOKEN)) {
    Write-Error "GRAFANA_FLEET_TOKEN is empty. Set it to a Grafana Cloud access policy token before running this script."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($env:GRAFANA_FLEET_USERNAME)) {
    Write-Error "GRAFANA_FLEET_USERNAME is empty. Set it to the Grafana Cloud Fleet instance ID."
    exit 1
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

try {
    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to ensure the monitoring namespace exists."
    }

    $usernameEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($env:GRAFANA_FLEET_USERNAME)
    )
    $passwordEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($env:GRAFANA_FLEET_TOKEN)
    )
    $secretManifest = @"
apiVersion: v1
kind: Secret
metadata:
  name: grafana-cloud-remote-config
  namespace: monitoring
type: Opaque
data:
  username: $usernameEncoded
  password: $passwordEncoded
"@
    $secretManifest | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create or update the Grafana remote-config Secret."
    }

    helm upgrade --install grafana-cloud grafana/k8s-monitoring -n monitoring --create-namespace -f grafana-cloud-values.yaml -f grafana-cloud-local-overrides.yaml
    if ($LASTEXITCODE -ne 0) {
        throw "Grafana Cloud Kubernetes Monitoring Helm upgrade failed."
    }

    kubectl get pods -n monitoring
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to retrieve monitoring pod status."
    }
}
finally {
    Remove-Variable secretManifest -ErrorAction SilentlyContinue
    Pop-Location
}
