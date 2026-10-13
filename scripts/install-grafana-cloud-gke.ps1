$ErrorActionPreference = "Stop"

$projectId = "abdulproject-510307"
$region = "asia-south1"
$clusterName = "ai-k8s-cluster"
$expectedContext = "gke_${projectId}_${region}_${clusterName}"
$chartVersion = "4.5.3"
$releaseName = "grafana-cloud"
$monitoringNamespace = "monitoring"
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot

try {
    $currentContext = kubectl config current-context
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the current kubectl context."
    }
    if ($currentContext.Trim() -ne $expectedContext) {
        throw "Wrong kubectl context. Select '$expectedContext' before continuing."
    }

    kubectl get deployment ai-k8s-demo --namespace ai-troubleshooter --no-headers
    if ($LASTEXITCODE -ne 0) {
        throw "The existing ai-k8s-demo deployment was not found; no monitoring changes were made."
    }
    kubectl get service ai-k8s-service --namespace ai-troubleshooter --no-headers
    if ($LASTEXITCODE -ne 0) {
        throw "The existing ai-k8s-service was not found; no monitoring changes were made."
    }

    helm repo add grafana https://grafana.github.io/helm-charts --force-update
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure the official Grafana Helm repository."
    }
    helm repo update grafana
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to update the Grafana Helm repository index."
    }

    helm template $releaseName grafana/k8s-monitoring `
        --version $chartVersion `
        --namespace $monitoringNamespace `
        --values grafana-cloud-gke-values.yaml | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The pinned chart failed local rendering; no namespace, Secret, or release was changed."
    }

    $prometheusUsername = $env:GRAFANA_PROM_USERNAME
    if ([string]::IsNullOrWhiteSpace($prometheusUsername)) {
        $prometheusUsername = Read-Host "Grafana Cloud Prometheus instance ID (not a token)"
    }
    $lokiUsername = $env:GRAFANA_LOKI_USERNAME
    if ([string]::IsNullOrWhiteSpace($lokiUsername)) {
        $lokiUsername = Read-Host "Grafana Cloud Loki instance ID (not a token)"
    }
    if (
        [string]::IsNullOrWhiteSpace($prometheusUsername) -or
        [string]::IsNullOrWhiteSpace($lokiUsername)
    ) {
        throw "Both Grafana Cloud instance IDs are required."
    }

    $metricsTokenSecure = Read-Host `
        "Enter a NEW Grafana token scoped only to metrics:write" `
        -AsSecureString
    $logsTokenSecure = Read-Host `
        "Enter a NEW Grafana token scoped only to logs:write" `
        -AsSecureString
    $metricsToken = [System.Net.NetworkCredential]::new("", $metricsTokenSecure).Password
    $logsToken = [System.Net.NetworkCredential]::new("", $logsTokenSecure).Password
    if (
        [string]::IsNullOrWhiteSpace($metricsToken) -or
        [string]::IsNullOrWhiteSpace($logsToken)
    ) {
        throw "Both replacement write tokens are required."
    }

    kubectl create namespace $monitoringNamespace --dry-run=client -o yaml |
        kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to ensure the monitoring namespace exists."
    }

    $prometheusUsernameEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($prometheusUsername)
    )
    $prometheusPasswordEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($metricsToken)
    )
    $lokiUsernameEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($lokiUsername)
    )
    $lokiPasswordEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($logsToken)
    )

    $secretManifest = @"
apiVersion: v1
kind: Secret
metadata:
  name: grafana-cloud-write
  namespace: monitoring
type: Opaque
data:
  prometheus-username: $prometheusUsernameEncoded
  prometheus-password: $prometheusPasswordEncoded
  loki-username: $lokiUsernameEncoded
  loki-password: $lokiPasswordEncoded
"@
    $secretManifest | kubectl apply -f -
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the Grafana Cloud credentials Secret."
    }

    helm upgrade --install $releaseName grafana/k8s-monitoring `
        --version $chartVersion `
        --namespace $monitoringNamespace `
        --create-namespace `
        --values grafana-cloud-gke-values.yaml
    if ($LASTEXITCODE -ne 0) {
        throw "Grafana Kubernetes Monitoring Helm installation failed."
    }

    helm status $releaseName --namespace $monitoringNamespace
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to verify the Grafana Kubernetes Monitoring release."
    }
    kubectl get pods --namespace $monitoringNamespace -o wide
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to retrieve monitoring pod status."
    }
}
finally {
    if ($metricsTokenSecure) {
        $metricsTokenSecure.Dispose()
    }
    if ($logsTokenSecure) {
        $logsTokenSecure.Dispose()
    }
    Remove-Variable metricsToken, logsToken, secretManifest -ErrorAction SilentlyContinue
    Pop-Location
}
