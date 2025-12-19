param(
    [Parameter(Mandatory)] [string]$ServerId,
    [string]$SteamUser = "",        # dedicated Steam account username
    [string]$SteamPass = ""         # password (plain text for automation)
)

$Base       = "C:\Servers\sbox-$ServerId"
$SteamCMD   = "$Base\steamcmd\steamcmd.exe"
$GameDir    = "$Base\game"
$LogDir     = "$Base\logs"
$AppID      = 1892930  # S&Box dedicated server

# Ensure directories exist
$Dirs = @($Base, "$Base\steamcmd", $GameDir, $LogDir)
foreach ($dir in $Dirs) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
}

# Ensure SteamCMD exe is present
if (-not (Test-Path $SteamCMD)) {
    Write-Host "Copying SteamCMD executable..."
    Copy-Item "C:\Tools\steamcmd.exe" $SteamCMD
}

# Determine login method (supports spoofed ENV STEAM_LOGIN or username/password)
$EnvSteamLogin = $env:STEAM_LOGIN
if ($EnvSteamLogin -and $EnvSteamLogin -ne "") {
    # If the env contains a space assume "user pass", else pass through as single token
    if ($EnvSteamLogin -match '\s') {
        $parts = $EnvSteamLogin -split '\s+',2
        $LoginCmd = "+login $($parts[0]) $($parts[1])"
    } else {
        $LoginCmd = "+login $EnvSteamLogin"
    }
} elseif ($SteamUser -ne "" -and $SteamPass -ne "") {
    $LoginCmd = "+login $SteamUser $SteamPass"
} else {
    $LoginCmd = "+login anonymous"
}

# Run SteamCMD
Write-Host "Installing/updating S&Box server..."
& $SteamCMD `
    +force_install_dir "$GameDir" `
    $LoginCmd `
    +app_update $AppID validate `
    +quit

Write-Host "Installation finished."
