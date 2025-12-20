param(
  [Parameter(Mandatory)][string]$ServerId,
  [Parameter(Mandatory)][string]$UserId,
  [string]$NodeToken = $env:PANEL_TOKEN
)

if (-not $NodeToken) { Write-Host "Set PANEL_TOKEN env or pass -NodeToken"; exit 1 }

$uri = "https://localhost:8080/api/servers/$ServerId/ws/authorize"
$body = @{ user_uuid = $UserId; permissions = @('websocket.connect','control.console'); ttl = 3600 } | ConvertTo-Json

Write-Host "Requesting websocket token from $uri"
$resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -Headers @{ Authorization = "Bearer $NodeToken" } -SkipCertificateCheck
$token = $resp.token
$socket = $resp.socket
Write-Host "Token: $token"
Write-Host "Socket: $socket"

# Connect with wscat if available
if (Get-Command wscat -ErrorAction SilentlyContinue) {
    Write-Host "Connecting with wscat..."
    wscat -c "$socket?token=$token" --no-check
} else {
    Write-Host "wscat not found. You can connect manually with:"
    Write-Host "wscat -c \"$socket?token=$token\" --no-check"
}
