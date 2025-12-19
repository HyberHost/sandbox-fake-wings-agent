param(
    [Parameter(Mandatory)] [string]$ServerId,
    [string]$SteamUser = "",        # dedicated Steam account username
    [string]$SteamPass = "",        # password (plain text for automation)
    [string]$STEAM_LOGIN = "",      # Steam login (overrides SteamUser/SteamPass if set)
    [string]$SBOX_GAME = "facepunch.walker", # S&Box gamemode
    [string]$SBOX_HOSTNAME = "",    # S&Box server hostname
    [string]$STEAM_GAME_TOKEN = ""  # Steam game token
)

$Base       = "C:\Servers\sbox-$ServerId"
$SteamCMD   = "$Base\steamcmd\steamcmd.exe"
$GameDir    = "$Base\game"
$LogDir     = "$Base\logs"
$AppID      = 1892930  # S&Box dedicated server

# Allow environment variable overrides (panel may set these)
if ($env:STEAM_LOGIN -and $env:STEAM_LOGIN -ne '') { $STEAM_LOGIN = $env:STEAM_LOGIN }
if ($env:SBOX_GAME -and $env:SBOX_GAME -ne '') { $SBOX_GAME = $env:SBOX_GAME }
if ($env:SBOX_HOSTNAME -and $env:SBOX_HOSTNAME -ne '') { $SBOX_HOSTNAME = $env:SBOX_HOSTNAME }

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
    if ($EnvSteamLogin -match '\s') {
        $parts = $EnvSteamLogin -split '\s+',2
        $LoginCmd = "+login $($parts[0]) $($parts[1])"
    } else {
        $LoginCmd = "+login $EnvSteamLogin"
    }
} elseif ($STEAM_LOGIN -ne "") {
    # Parameter may be passed from a controller panel
    if ($STEAM_LOGIN -match '\s') {
        $parts = $STEAM_LOGIN -split '\s+',2
        $LoginCmd = "+login $($parts[0]) $($parts[1])"
    } else {
        $LoginCmd = "+login $STEAM_LOGIN"
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

# Persist runtime metadata (last_install)
$MetaPath = "$Base\server.json"
$meta = @{}
if (Test-Path $MetaPath) {
    try {
        $meta = Get-Content $MetaPath | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $meta = @{}
    }
}

# Support both hashtable/dictionary and PSCustomObject from ConvertFrom-Json
if ($meta -is [System.Collections.IDictionary]) {
    $meta['last_install'] = (Get-Date).ToString("o")
    $out = [PSCustomObject]$meta
} else {
    $meta | Add-Member -NotePropertyName last_install -NotePropertyValue (Get-Date).ToString("o") -Force
    $out = $meta
}

$out | ConvertTo-Json | Out-File -FilePath $MetaPath -Encoding UTF8
Write-Host "Saved server metadata to $MetaPath"

# --- Start the S&Box server process and persist runtime metadata (pid, last_start)
try {
    $meta = Get-Content $MetaPath | ConvertFrom-Json -ErrorAction Stop
} catch {
    $meta = @{}
}

# Check if a PID is recorded and running
$existingPid = $null
if ($meta -is [System.Collections.IDictionary]) {
    if ($meta.ContainsKey('pid')) { $existingPid = $meta['pid'] }
} else {
    if ($meta.PSObject.Properties.Name -contains 'pid') { $existingPid = $meta.pid }
}

if ($existingPid) {
    $proc = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Server already running with PID $existingPid. Not starting another instance."
        return
    }
}

# Locate the server executable in common locations
$possibleExe = @("$GameDir\sbox-server.exe", "$GameDir\bin\sbox-server.exe")
$ServerExe = $possibleExe | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $ServerExe) {
    Write-Host "Could not find sbox-server.exe in $GameDir or $GameDir\bin. Server not started."
    return
}


# Build server arguments from parameters
$Map = "garry.scenemap" # You may want to add as a parameter later
$Game = if ($SBOX_GAME -ne "") { $SBOX_GAME } else { "facepunch.walker" }
$Hostname = if ($SBOX_HOSTNAME -ne "") { $SBOX_HOSTNAME } else { "sbox-$ServerId" }
$ServerArgs = @()
$ServerArgs += "+game $Game $Map"
$ServerArgs += "+hostname '$Hostname'"
if ($STEAM_GAME_TOKEN -ne "") { $ServerArgs += "+sv_setsteamaccount $STEAM_GAME_TOKEN" }

# Flatten argument array to string
$ServerArgs = $ServerArgs -join " "

Write-Host "Starting S&Box server: $ServerExe $ServerArgs"
$proc = Start-Process -FilePath $ServerExe -ArgumentList $ServerArgs -WorkingDirectory $GameDir -PassThru

if ($proc -and $proc.Id) {
    # update metadata with runtime info
    if ($meta -is [System.Collections.IDictionary]) {
        $meta['pid'] = $proc.Id
        $meta['last_start'] = (Get-Date).ToString("o")
        $out = [PSCustomObject]$meta
    } else {
        $meta | Add-Member -NotePropertyName pid -NotePropertyValue $proc.Id -Force
        $meta | Add-Member -NotePropertyName last_start -NotePropertyValue (Get-Date).ToString("o") -Force
        $out = $meta
    }

    $out | ConvertTo-Json | Out-File -FilePath $MetaPath -Encoding UTF8
    Write-Host "Server started (PID $($proc.Id)), metadata updated."
} else {
    Write-Host "Failed to start server process."
}
