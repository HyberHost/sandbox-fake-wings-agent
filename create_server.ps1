
param(
  [Parameter(Mandatory)]
  [string]$ServerId
)

# Example spoofed ENVs (for panel integration/testing)
$STEAM_LOGIN   = $env:STEAM_LOGIN
$SBOX_GAME     = $env:SBOX_GAME
$SBOX_HOSTNAME = $env:SBOX_HOSTNAME

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

# Metadata (include S&Box settings if provided)
$meta = @{
  server_id = $ServerId
  created   = (Get-Date).ToString("o")
}
if ($SBOX_GAME -and $SBOX_GAME -ne '') { $meta['sbox_game'] = $SBOX_GAME }
if ($SBOX_HOSTNAME -and $SBOX_HOSTNAME -ne '') { $meta['hostname'] = $SBOX_HOSTNAME }
$meta | ConvertTo-Json | Out-File "$Base\server.json"
Write-Host "Server '$ServerId' created at $Base"