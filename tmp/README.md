Test servers for local network testing

This folder contains a simple test harness to emulate S&Box network endpoints for quick local checks.

What it provides
- HTTPS server on port 8080 using a self-signed cert for `SBOX-GB-1.gameforge.gg`.
- A simple TCP "SFTP logger" on port 2022 that logs connection attempts and raw bytes (NOT a full SFTP server).

Logs
- Logs are written to `tmp/logs/https.log` and `tmp/logs/sftp.log`.

Run

Node daemon (mock Wings HTTPS on 8080)
1) From `tmp/` install node deps and run:
   cd tmp
   npm install
   npm start

This will auto-generate a self-signed cert if missing (2048-bit by default) and write logs to `tmp/logs/daemon.log`. If your OpenSSL/node rejects the generated key for being too small, the daemon will regenerate a 4096-bit certificate automatically.

If you prefer a proper CA-signed certificate in production or for broader testing, use a Windows ACME client like `win-acme` (https://www.win-acme.com/). Below are example steps to use `win-acme` to export PEM or PFX files and configure the daemon to use them.

API: /api/system
- The daemon exposes `GET /api/system` which returns basic node configuration and status. It will try to load a Wings config file (YAML or JSON) from the path set in the env var `WINGS_CONFIG_PATH` (defaults to `C:\Agent\wings.yml`). If a config is not present the daemon will return sensible defaults and any env variables it can find:
  - `WINGS_UUID` or `NODE_UUID` for `uuid`
  - `WINGS_TOKEN_ID` / `WINGS_TOKEN` for token fields
  - `PANEL_REMOTE` for the remote panel URL
- The daemon also properly responds to preflight `OPTIONS /api/system` requests and enables CORS so the panel browser integration can communicate with it.

Console Websocket (/api/servers/:serverId/ws)
- A console stub is available at `GET /api/servers/:serverId/ws` (WebSocket upgrade). The connection accepts either:
  - `Authorization: Bearer <token>` header, or
  - `?token=<token>` query parameter
- The daemon validates that the server has a `server.json` with a `pid` and that the PID appears to be running. It also accepts connections if the token matches the node token or the `instance_token` listed in `server.json`.
- Incoming messages are logged to `C:\Servers\sbox-<serverId>\console.log` and echoed back as a stubbed `stdout` JSON message.

Example using `wscat`:
```bash
wscat -c "wss://sbox-gb-1.gameforge.gg:8080/api/servers/test1234/ws?token=<token>" --no-check
```


If you want me to source the exact fields from the Panel/Wings repo I can parse the panel's expectations and adapt responses accordingly.

Using win-acme (exporting PEM files)
1) Download win-acme (wacs.exe) from https://www.win-acme.com/ and run it interactively or via command line.
2) Example command (manual host validation) to write PEM files to `C:\Agent\tmp`:
   - Open an elevated PowerShell prompt, cd to the folder containing `wacs.exe`, and run:
     ```powershell
     .\wacs.exe --target manual --host SBOX-GB-1.gameforge.gg --validation selfhosting --store pemfiles --pemfilespath "C:\Agent\tmp" --accepttos --installation none
     ```
   - This will create `certificate.pem` and `private.key` (names may vary); point the daemon at these files using env vars below.

Using win-acme (exporting PFX)
1) You can also export a PFX (PKCS#12) and provide a passphrase, then set `SSL_PFX_PATH` and `SSL_PFX_PASS` for the daemon to load the PFX directly.

Configure the Node daemon to use Win-ACME exported files
- Set environment variables for the daemon (example PowerShell):
  ```powershell
  $env:SSL_CERT_PATH = 'C:\Agent\tmp\certificate.pem'
  $env:SSL_KEY_PATH = 'C:\Agent\tmp\private.key'
  # Or, for PFX:
  $env:SSL_PFX_PATH = 'C:\Agent\tmp\certificate.pfx'
  $env:SSL_PFX_PASS = 'yourPfxPass'
  npm start
  ```

Notes
- After exporting certs with win-acme, restart the daemon so it picks up the files.
- For local dev trust, `mkcert` is simpler for creating locally trusted certs: https://github.com/FiloSottile/mkcert


Python test servers (HTTPS on 8080 and SFTP logger on 2022 - legacy)
1) Create a virtualenv and install requirements:
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r tmp/requirements.txt

2) Run the test servers:
   python tmp/run_test_servers.py

Notes
- The script auto-generates a self-signed certificate and key in `tmp/ssl_cert.pem` and `tmp/ssl_key.pem` when needed.
- The Node daemon will use `PANEL_TOKEN` env var if set to require Authorization: Bearer <token> for requests.
- If you want a full SFTP server, we can add a paramiko (python) or paramiko equivalent, or wire up OpenSSH on Windows.
