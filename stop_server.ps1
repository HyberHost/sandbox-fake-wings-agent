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
    try {
        Stop-Process -Id $pid -Force -ErrorAction Stop
        Write-Host "Stopped process $pid."
    } catch {
        Write-Host "Failed to stop process $pid: $_"
    }

    # remove pid from metadata and persist last_stop
    if (Test-Path $MetaPath) {
        try { $meta = Get-Content $MetaPath | ConvertFrom-Json -ErrorAction Stop } catch { $meta = @{} }
        if ($meta -is [System.Collections.IDictionary]) {
            $meta.Remove('pid') | Out-Null
            $meta['last_stop'] = (Get-Date).ToString("o")
            $out = [PSCustomObject]$meta
        } else {
            if ($meta.PSObject.Properties.Name -contains 'pid') { $meta.PSObject.Properties.Remove('pid') }
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
