# sandbox-fake-wings-agent
Fake Pterodactyl Wings-like agent that proxies requests to Windows for S&Box servers.

This repository contains simple PowerShell scripts in the `Agent` folder to create, install, start and stop a local S&Box server instance. The instructions below explain how to test each script locally using a fake server id `test1234`.

**Prerequisites**
- Run PowerShell as Administrator for actions that install runtimes or run installers.
- `steamcmd.exe` should be available at `C:\Tools\steamcmd.exe` for installer steps (the scripts copy it into server folders).

**Agent scripts**
- `Agent/create_server.ps1` — create server directories and metadata.
- `Agent/install_server.ps1` — run SteamCMD to install/update the server files.
- `Agent/start_server.ps1` — installs/updates via SteamCMD, launches the server binary, and persists runtime metadata to `server.json`.
- `Agent/stop_server.ps1` — stops the server by reading `server.json` (preferred) or falling back to `server.pid`.

Paths in this repo are relative to the repository root. See the script files in the `Agent` folder for implementation details.

**Quick test (using fake UUID `test1234`)**
Open an elevated PowerShell prompt and run the following commands (each command is independent):

Create a server layout:
```powershell
powershell -ExecutionPolicy Bypass -File C:\Agent\create_server.ps1 -ServerId test1234
```

Install/update server files (uses SteamCMD via `C:\Tools\steamcmd.exe`):
```powershell
powershell -ExecutionPolicy Bypass -File C:\Agent\install_server.ps1 -ServerId test1234
```

Start the server (S&Box startup accepts gamemode and hostname from envs/params; `STEAM_GAME_TOKEN` is not yet available and is ignored for now):

```powershell
# Example: set spoofed envs in PowerShell (temporary for this shell)
$env:STEAM_LOGIN = 'mysteamuser mypassword'  # steam login for install/update (steamcmd)
$env:SBOX_GAME = 'facepunch.walker'
$env:SBOX_HOSTNAME = 'My Dedicated Server'

powershell -ExecutionPolicy Bypass -File C:\Agent\start_server.ps1 -ServerId test1234
```

Stop the server (reads `C:\Servers\sbox-test1234\server.json` for the PID and stops it):

```powershell
powershell -ExecutionPolicy Bypass -File C:\Agent\stop_server.ps1 -ServerId test1234
```

**Notes & troubleshooting**
- If you see an error mentioning `-Port`, note that `Agent/start_server.ps1` no longer accepts a `-Port` parameter; ports are handled by S&Box unless you explicitly need to set one.
- The `start_server.ps1` script writes `server.json` metadata under `C:\Servers\sbox-test1234\server.json`. The metadata includes `pid`, `pid_start_time` and `instance_token` so the agent can validate that a running PID belongs to this instance (prevents killing/reusing the wrong process). If you want the script to also write a separate `server.pid` file, request that change.

**install_node.ps1**
To install required .NET runtimes and fetch the `Agent` folder from GitHub, run (from an elevated shell):
```powershell
Start-Process powershell -Verb runAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Agent\install_node.ps1'
```
Or run `install_node.ps1` from the repository root if you have it there.

If you'd like, I can extend the README with more details (expected `sbox-server.exe` arguments, `server.pid` format, or CI/test steps).
