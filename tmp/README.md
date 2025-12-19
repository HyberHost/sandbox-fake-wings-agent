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

If you prefer a proper CA-signed certificate in production or for broader testing, consider using a Windows ACME client like `win-acme` (https://www.win-acme.com/) or Certbot via WSL/Docker. For local development, `mkcert` is convenient to produce locally trusted certs: https://github.com/FiloSottile/mkcert

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
