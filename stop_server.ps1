param(
    [Parameter(Mandatory)] [string]$ServerId
)

$Base    = "C:\Servers\sbox-$ServerId"
$PidFile = "$Base\server.pid"

if (Test-Path $PidFile) {
    $Pid = Get-Content $PidFile
    Stop-Process -Id $Pid -Force
    Remove-Item $PidFile
    Write-Host "Server $ServerId stopped."
} else {
    Write-Host "No PID file found for $ServerId. Server may not be running."
}
