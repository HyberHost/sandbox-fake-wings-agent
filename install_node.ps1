# install_node.ps1
# Downloads and installs .NET runtimes (if missing) and fetches the /Agent folder from GitHub.
# Usage: Run in an elevated PowerShell session for runtime installation.

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Test-DotnetRuntime {
    param(
        [string]$Product, # e.g. Microsoft.NETCore.App or Microsoft.AspNetCore.App
        [string]$Version
    )
    try {
        $runtimes = & dotnet --list-runtimes 2>$null
        if (-not $runtimes) { return $false }
        return $runtimes -match "^$Product\s+$Version"
    } catch {
        return $false
    }
}

function Download-File($Url, $Destination) {
    Write-Host "Downloading $Url -> $Destination"
    $headers = @{ 'User-Agent' = 'PowerShell' }
    Invoke-WebRequest -Uri $Url -OutFile $Destination -Headers $headers
}

function Install-Exe($Path, $Args) {
    Write-Host "Running installer: $Path $Args"
    $p = Start-Process -FilePath $Path -ArgumentList $Args -Wait -PassThru -NoNewWindow
    return $p.ExitCode
}

# Runtimes to ensure
$dotnetUrl = 'https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.1/dotnet-runtime-10.0.1-win-x64.exe'
$aspnetUrl = 'https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/10.0.1/aspnetcore-runtime-10.0.1-win-x64.exe'
$dotnetProduct = 'Microsoft.NETCore.App'
$aspnetProduct = 'Microsoft.AspNetCore.App'
$requiredVersion = '10.0.1'

$tmp = Join-Path $env:TEMP "dotnet_install_$(Get-Date -UFormat %s)"
New-Item -Path $tmp -ItemType Directory -Force | Out-Null

$needDotnet = -not (Test-DotnetRuntime -Product $dotnetProduct -Version $requiredVersion)
$needAspnet = -not (Test-DotnetRuntime -Product $aspnetProduct -Version $requiredVersion)

if (-not $needDotnet -and -not $needAspnet) {
    Write-Host "Required runtimes already present."
} else {
    if ($needDotnet) {
        $installer = Join-Path $tmp "dotnet-runtime-10.0.1-win-x64.exe"
        Download-File $dotnetUrl $installer
        Write-Host "Installing .NET Runtime 10.0.1 (requires elevation)"
        $rc = Install-Exe $installer '/install','/quiet','/norestart'
        Write-Host "Installer exit code: $rc"
    }
    if ($needAspnet) {
        $installer = Join-Path $tmp "aspnetcore-runtime-10.0.1-win-x64.exe"
        Download-File $aspnetUrl $installer
        Write-Host "Installing ASP.NET Core Runtime 10.0.1 (requires elevation)"
        $rc = Install-Exe $installer '/install','/quiet','/norestart'
        Write-Host "Installer exit code: $rc"
    }

    Write-Host "Re-checking runtimes..."
    Start-Sleep -Seconds 2
    $dotnetOk = Test-DotnetRuntime -Product $dotnetProduct -Version $requiredVersion
    $aspnetOk = Test-DotnetRuntime -Product $aspnetProduct -Version $requiredVersion
    if ($dotnetOk -and $aspnetOk) {
        Write-Host "Runtimes installed successfully."
    } else {
        Write-Host "Warning: One or more runtimes are still missing. Check installers or run with elevated privileges."
    }
}

# Download Agent folder from GitHub
$repoZip = 'https://github.com/HyberHost/sandbox-fake-wings-agent/archive/refs/heads/main.zip'
$zipPath = Join-Path $tmp 'repo.zip'
$extractPath = Join-Path $tmp 'repo'

Write-Host "Downloading repository archive..."
Download-File $repoZip $zipPath

Write-Host "Extracting archive to $extractPath"
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Determine script/repo root where this script lives
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$srcAgent = Join-Path $extractPath 'sandbox-fake-wings-agent-main\Agent'
$dstAgent = Join-Path $ScriptDir 'Agent'

if (-not (Test-Path $srcAgent)) {
    Write-Host "Error: Agent folder not found in downloaded archive: $srcAgent"
    exit 1
}

Write-Host "Copying Agent folder to repository root: $dstAgent"
if (-not (Test-Path $dstAgent)) { New-Item -ItemType Directory -Path $dstAgent | Out-Null }
Copy-Item -Path (Join-Path $srcAgent '*') -Destination $dstAgent -Recurse -Force

Write-Host "Done. Clean up temporary files: $tmp"
# Note: not removing $tmp automatically for debugging. Remove manually if desired.

Write-Host "install_node.ps1 finished."
