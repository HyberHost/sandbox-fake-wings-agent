/*
Node-based mock Wings daemon (HTTPS)
- Listens on 0.0.0.0:8080 (HTTPS; auto-generates a self-signed cert for SBOX-GB-1.gameforge.gg if missing)
- Endpoints:
  - GET /api/servers/:serverId
  - POST /api/servers/:serverId/power  -> { action: 'start'|'stop'|'restart' }
  - POST /api/servers/:serverId/command -> { command: '...' }

Usage:
  npm install
  npm start

Notes:
- On Windows this uses PowerShell scripts `start_server.ps1` and `stop_server.ps1` in the repository root to control servers.
*/

const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const morgan = require('morgan');
const child_process = require('child_process');
const selfsigned = require('selfsigned');

const BASE = path.resolve(__dirname);
const LOG_DIR = path.join(BASE, 'logs');
const SSL_CERT = path.join(BASE, 'ssl_cert.pem');
const SSL_KEY = path.join(BASE, 'ssl_key.pem');
const HOSTNAME = 'SBOX-GB-1.gameforge.gg';
const SERVERS_ROOT = 'C:/Servers';
const PANEL_TOKEN = process.env.PANEL_TOKEN || '';

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
const daemonLog = fs.createWriteStream(path.join(LOG_DIR, 'daemon.log'), { flags: 'a' });

function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.join(' ')}\n`;
  process.stdout.write(line);
  daemonLog.write(line);
}

function ensureCert(keySize = 2048, force = false) {
  if (!force && fs.existsSync(SSL_CERT) && fs.existsSync(SSL_KEY)) {
    log('Using existing SSL cert');
    return { cert: fs.readFileSync(SSL_CERT), key: fs.readFileSync(SSL_KEY) };
  }
  log('Generating self-signed cert for', HOSTNAME, `(keySize=${keySize})`);
  const attrs = [{ name: 'commonName', value: HOSTNAME }];
  // Generate a stronger key by default to avoid modern OpenSSL rejecting small keys
  const pems = selfsigned.generate(attrs, { days: 365, keySize: keySize, algorithm: 'sha256' });
  fs.writeFileSync(SSL_CERT, pems.cert);
  fs.writeFileSync(SSL_KEY, pems.private);
  return { cert: pems.cert, key: pems.private };
}

function requireAuth(req, res) {
  if (!PANEL_TOKEN) return true;
  const auth = req.get('authorization') || '';
  if (!auth.startsWith('Bearer ')) return false;
  const token = auth.split(' ')[1].trim();
  return token === PANEL_TOKEN;
}

function serverMetaPath(serverId) {
  return path.join(SERVERS_ROOT, `sbox-${serverId}`, 'server.json');
}

function readServerMeta(serverId) {
  const p = serverMetaPath(serverId);
  if (!fs.existsSync(p)) return null;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    log('Failed to read server.json', e.message);
    return null;
  }
}

function isRunning(meta) {
  if (!meta || !meta.pid) return false;
  const pid = parseInt(meta.pid, 10);
  if (Number.isNaN(pid)) return false;
  try {
    // Use tasklist to check process existence on Windows
    const out = child_process.execFileSync('tasklist', ['/FI', `PID eq ${pid}`], { encoding: 'utf8' });
    return out.includes(String(pid));
  } catch (e) {
    return false;
  }
}

function spawnPowershellScript(scriptPath, args = []) {
  const full = path.resolve(__dirname, '..', scriptPath);
  // Avoid blocking: spawn detached
  const ps = child_process.spawn('powershell', ['-ExecutionPolicy', 'Bypass', '-File', full, ...args], {
    detached: true,
    stdio: 'ignore'
  });
  ps.unref();
  return ps.pid;
}

const app = express();
app.use(express.json());
app.use(morgan('combined', { stream: { write: (s) => daemonLog.write(s) } }));

// Auth middleware
app.use((req, res, next) => {
  if (!requireAuth(req, res)) return res.status(401).json({ error: 'unauthorized' });
  next();
});

app.get('/api/servers/:serverId', (req, res) => {
  const meta = readServerMeta(req.params.serverId);
  if (!meta) return res.status(404).json({ error: 'not_found' });
  const status = isRunning(meta) ? 'running' : 'stopped';
  log('GET /api/servers/', req.params.serverId, '->', status);
  res.json({ server_id: req.params.serverId, status, meta });
});

app.post('/api/servers/:serverId/power', (req, res) => {
  const action = (req.body && req.body.action || '').toLowerCase();
  if (!['start', 'stop', 'restart'].includes(action)) return res.status(400).json({ error: 'invalid_action' });
  log('Power', action, 'for', req.params.serverId);
  if (action === 'start') {
    const pid = spawnPowershellScript('start_server.ps1', ['-ServerId', req.params.serverId]);
    return res.status(202).json({ result: 'starting', pid });
  }
  if (action === 'stop') {
    const pid = spawnPowershellScript('stop_server.ps1', ['-ServerId', req.params.serverId]);
    return res.status(202).json({ result: 'stopping', pid });
  }
  // restart: stop then delayed start
  spawnPowershellScript('stop_server.ps1', ['-ServerId', req.params.serverId]);
  setTimeout(() => spawnPowershellScript('start_server.ps1', ['-ServerId', req.params.serverId]), 1500);
  return res.status(202).json({ result: 'restarting' });
});

app.post('/api/servers/:serverId/command', (req, res) => {
  const cmd = (req.body && req.body.command) || '';
  if (!cmd) return res.status(400).json({ error: 'no_command' });
  log('Command for', req.params.serverId, cmd);
  const serverDir = path.join(SERVERS_ROOT, `sbox-${req.params.serverId}`);
  if (!fs.existsSync(serverDir)) fs.mkdirSync(serverDir, { recursive: true });
  const consoleLog = path.join(serverDir, 'console.log');
  fs.appendFileSync(consoleLog, `${new Date().toISOString()}Z CMD ${cmd}\n`, 'utf8');
  return res.status(202).json({ result: 'queued' });
});

// Start HTTPS server
let { cert, key } = ensureCert();
let httpsServer;
try {
  httpsServer = https.createServer({ key, cert }, app);
  httpsServer.listen(8080, '0.0.0.0', () => {
    log('Mock Wings daemon listening on https://0.0.0.0:8080');
  });
} catch (err) {
  log('Failed to start HTTPS server:', err && err.message);
  // Handle small key errors by regenerating a larger key and retrying
  if (err && (err.code === 'ERR_SSL_EE_KEY_TOO_SMALL' || (err.message && err.message.includes('ee key too small')))) {
    log('Regenerating certificate with 4096-bit key and retrying...');
    ({ cert, key } = ensureCert(4096, true));
    httpsServer = https.createServer({ key, cert }, app);
    httpsServer.listen(8080, '0.0.0.0', () => {
      log('Mock Wings daemon listening on https://0.0.0.0:8080 (using 4096-bit cert)');
    });
  } else {
    throw err;
  }
}

process.on('uncaughtException', (err) => {
  log('uncaughtException', err.stack || err.message || err);
});

process.on('SIGINT', () => {
  log('Shutting down');
  daemonLog.end(() => process.exit(0));
});
