# sandbox-fake-wings-agent
Fake Pterodactyl Wings-like agent that proxies requests to Windows for S&Box servers.

This repository contains simple PowerShell scripts in the `Agent` folder to create, install, start and stop a local S&Box server instance. The instructions below explain how to test each script locally using a fake server id `test1234`.

**Prerequisites**
- Run PowerShell as Administrator for actions that install runtimes or run installers.
- `steamcmd.exe` should be available at `C:\Tools\steamcmd.exe` for installer steps (the scripts copy it into server folders).

**Agent scripts**
- `Agent/create_server.ps1` — create server directories and metadata.
- `Agent/install_server.ps1` — run SteamCMD to install/update the server files.
- `Agent/start_server.ps1` — installs/updates via SteamCMD and persists metadata; can be extended to launch the server binary.
- `Agent/stop_server.ps1` — stops the server by reading `server.pid`.

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

Start the server (this script currently installs/updates and writes metadata; pass a port if desired):
```powershell
powershell -ExecutionPolicy Bypass -File C:\Agent\start_server.ps1 -ServerId test1234 -Port 27015
```

Stop the server (reads `C:\Servers\sbox-test1234\server.pid` and stops the process id listed there):
```powershell
powershell -ExecutionPolicy Bypass -File C:\Agent\stop_server.ps1 -ServerId test1234
```

**Notes & troubleshooting**
- If you see "A parameter cannot be found that matches parameter name 'Port'", ensure you're running the updated `Agent/start_server.ps1` that accepts `-Port`.
- The `start_server.ps1` script writes `server.json` metadata under `C:\Servers\sbox-test1234\server.json`. If you want the script to actually launch `sbox-server.exe` and write `server.pid`, request that change and it can be implemented.

**install_node.ps1**
To install required .NET runtimes and fetch the `Agent` folder from GitHub, run (from an elevated shell):
```powershell
Start-Process powershell -Verb runAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Agent\install_node.ps1'
```
Or run `install_node.ps1` from the repository root if you have it there.

If you'd like, I can extend the README with more details (expected `sbox-server.exe` arguments, `server.pid` format, or CI/test steps).
