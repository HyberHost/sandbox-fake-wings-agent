param(
  [Parameter(Mandatory)]
  [string]$ServerId
)

$Base       = "C:\Servers\sbox-$ServerId"
$SteamExe  = "C:\Tools\steamcmd.exe"
$SteamDest = "$Base\steamcmd"

$Dirs = @(
  $Base,
  $SteamDest,
  "$Base\game",
  "$Base\logs"
)

foreach ($dir in $Dirs) {
  if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
  }
}

# Copy SteamCMD executable if missing
if (-not (Test-Path "$SteamDest\steamcmd.exe")) {
  Copy-Item $SteamExe "$SteamDest\steamcmd.exe"
}

# Metadata
@{
  server_id = $ServerId
  created   = (Get-Date).ToString("o")
} | ConvertTo-Json | Out-File "$Base\server.json"
Write-Host "Server '$ServerId' created at $Base"