param(
    [Parameter(Mandatory)] [string]$ServerId
)

# Spoofed ENVs (panel may set these)
$STEAM_LOGIN   = $env:STEAM_LOGIN
$SBOX_GAME     = $env:SBOX_GAME
$SBOX_HOSTNAME = $env:SBOX_HOSTNAME

$Base    = "C:\Servers\sbox-$ServerId"
$MetaPath = "$Base\server.json"
$PidFile = "$Base\server.pid"

$pid = $null
if (Test-Path $MetaPath) {
    try { $meta = Get-Content $MetaPath | ConvertFrom-Json -ErrorAction Stop } catch { $meta = @{} }
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.ContainsKey('pid')) { $pid = $meta['pid'] }
    } else {
        if ($meta.PSObject.Properties.Name -contains 'pid') { $pid = $meta.pid }
    }
}

if (-not $pid -and (Test-Path $PidFile)) { $pid = Get-Content $PidFile }

if ($pid) {
    # Validate process identity using recorded start time to avoid killing unrelated processes
    $metaStart = $null
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.ContainsKey('pid_start_time')) { $metaStart = $meta['pid_start_time'] }
    } else {
        if ($meta.PSObject.Properties.Name -contains 'pid_start_time') { $metaStart = $meta.pid_start_time }
    }

    $proc = $null
    try { $proc = Get-Process -Id $pid -ErrorAction Stop } catch { $proc = $null }

    if ($proc -and $metaStart) {
        $currentStart = $proc.StartTime.ToString("o")
        if ($currentStart -ne $metaStart) {
            Write-Host "PID $pid is running but its start time ($currentStart) does not match recorded start time ($metaStart). Not stopping to avoid killing an unrelated process."
            return
        }
    }

    try {
        Stop-Process -Id $pid -Force -ErrorAction Stop
        Write-Host "Stopped process $pid."
    } catch {
        Write-Host "Failed to stop process $pid: $_"
    }

    # remove pid and token from metadata and persist last_stop
    if (Test-Path $MetaPath) {
        try { $meta = Get-Content $MetaPath | ConvertFrom-Json -ErrorAction Stop } catch { $meta = @{} }
        if ($meta -is [System.Collections.IDictionary]) {
            $meta.Remove('pid') | Out-Null
            $meta.Remove('pid_start_time') | Out-Null
            if ($meta.ContainsKey('instance_token')) { $meta.Remove('instance_token') | Out-Null }
            $meta['last_stop'] = (Get-Date).ToString("o")
            $out = [PSCustomObject]$meta
        } else {
            if ($meta.PSObject.Properties.Name -contains 'pid') { $meta.PSObject.Properties.Remove('pid') }
            if ($meta.PSObject.Properties.Name -contains 'pid_start_time') { $meta.PSObject.Properties.Remove('pid_start_time') }
            if ($meta.PSObject.Properties.Name -contains 'instance_token') { $meta.PSObject.Properties.Remove('instance_token') }
            $meta | Add-Member -NotePropertyName last_stop -NotePropertyValue (Get-Date).ToString("o") -Force
            $out = $meta
        }
        $out | ConvertTo-Json | Out-File -FilePath $MetaPath -Encoding UTF8
    }

    if (Test-Path $PidFile) { Remove-Item $PidFile }
    Write-Host "Server $ServerId stopped."
} else {
    Write-Host "No running server found for $ServerId (no PID)."
}
