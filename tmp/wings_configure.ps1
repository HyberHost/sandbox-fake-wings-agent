<#
.SYNOPSIS
Fetch node configuration from Panel and write to a local `wings.json` (Panel-compatible).

.DESCRIPTION
Works similarly to `wings configure --panel-url ... --token ... --node <id>`.
By default writes JSON to `C:\Agent\wings.json`. Optionally POSTs the config to
`https://localhost:8080/api/update` so a running daemon picks it up immediately.

.EXAMPLE
.
  .\tmp\wings_configure.ps1 -PanelUrl 'https://panel.gameforge.gg' -PanelToken 'ptla_xxx' -Node 4 -SkipCertificateCheck -UpdateLocalDaemon

.PARAMETER PanelUrl
Base URL of the Panel (e.g. https://panel.example.com)

.PARAMETER PanelToken
Application API key with permission to retrieve node configuration (Bearer token)

.PARAMETER Node
Numeric Node ID to fetch configuration for

.PARAMETER OutPath
Where to write the config JSON. Default: C:\Agent\wings.json

.PARAMETER SkipCertificateCheck
Skip TLS certificate verification (useful for self-signed test environments)

.PARAMETER UpdateLocalDaemon
If specified, POST the fetched config to https://localhost:8080/api/update.

.PARAMETER DaemonToken
Optional Authorization token to send when POSTing to the local daemon.
#>

param(
  [Parameter(Mandatory=$true)][string]$PanelUrl,
  [Parameter(Mandatory=$true)][string]$PanelToken,
  [Parameter(Mandatory=$true)][int]$Node,
  [string]$OutPath = 'C:\Agent\wings.json',
  [switch]$SkipCertificateCheck,
  [switch]$UpdateLocalDaemon,
  [string]$DaemonToken
)

function Mask-Token($t) {
  if (-not $t) { return '' }
  $last = $t.Length -le 8 ? $t : $t.Substring($t.Length - 4)
  return ('***' + $last)
}

try {
  $PanelUrl = $PanelUrl.TrimEnd('/')
  $uri = "$PanelUrl/api/application/nodes/$Node/configuration"
  Write-Host "Fetching node configuration from $uri"

  $headers = @{ Authorization = "Bearer $PanelToken" }
  $invokeParams = @{ Uri = $uri; Method = 'GET'; Headers = $headers }
  if ($SkipCertificateCheck) { $invokeParams['SkipCertificateCheck'] = $true }

  $resp = Invoke-RestMethod @invokeParams
  if (-not $resp) { throw "Empty response from Panel" }

  # Ensure we have an object and serialize to JSON with pretty print
  $json = $resp | ConvertTo-Json -Depth 15

  # Create parent directory if needed
  $destDir = Split-Path -Parent $OutPath
  if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }

  # Write the file atomically
  $tmp = "$OutPath.tmp"
  Set-Content -Path $tmp -Value $json -Encoding UTF8
  Move-Item -Force -Path $tmp -Destination $OutPath

  Write-Host "Saved node configuration to $OutPath"
  Write-Host "Panel token used:" (Mask-Token $PanelToken)

  if ($UpdateLocalDaemon) {
    $daemonUri = 'https://localhost:8080/api/update'
    Write-Host "Posting configuration to local daemon at $daemonUri"
    $dHeaders = @{}
    if ($DaemonToken) { $dHeaders['Authorization'] = "Bearer $DaemonToken" }
    $postParams = @{ Uri = $daemonUri; Method = 'POST'; ContentType = 'application/json'; Body = $json }
    if ($SkipCertificateCheck) { $postParams['SkipCertificateCheck'] = $true }
    if ($DaemonToken) { $postParams['Headers'] = $dHeaders }

    try {
      $postResp = Invoke-RestMethod @postParams
      Write-Host "Daemon response:" ($postResp | ConvertTo-Json -Depth 5)
    } catch {
      Write-Warning "Failed to POST to local daemon: $($_.Exception.Message)"
    }
  }

  Write-Host "Done."
  exit 0
} catch {
  Write-Error "Failed: $($_.Exception.Message)"
  exit 1
}