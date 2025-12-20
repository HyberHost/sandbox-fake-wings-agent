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
const cors = require('cors');
const os = require('os');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// In-memory denylist for websocket JTIs: jti -> timestamp (ms)
const wsDenylist = new Map();

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

// Try loading cert/key from environment-configured paths (PEM or PFX exported by win-acme)
function loadCertFromEnv() {
  const certPath = process.env.SSL_CERT_PATH;
  const keyPath = process.env.SSL_KEY_PATH;
  const pfxPath = process.env.SSL_PFX_PATH;
  const pfxPass = process.env.SSL_PFX_PASS;

  if (pfxPath && fs.existsSync(pfxPath)) {
    try {
      log('Loading PFX from', pfxPath);
      const pfx = fs.readFileSync(pfxPath);
      return { pfx, passphrase: pfxPass };
    } catch (e) {
      log('Failed to load PFX:', e.message);
    }
  }

  if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      log('Loading PEM cert/key from', certPath, keyPath);
      const cert = fs.readFileSync(certPath);
      const key = fs.readFileSync(keyPath);
      return { cert, key };
    } catch (e) {
      log('Failed to load PEM files:', e.message);
    }
  }

  return null;
}

function ensureCert(keySize = 2048, force = false) {
  // If env-provided certs exist prefer them
  const envCert = loadCertFromEnv();
  if (envCert) {
    return envCert;
  }

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

let WINGS_CONFIG = null;
let WINGS_CONFIG_PATH_LOADED = null;

function loadWingsConfig() {
  // JSON-only config handling. Default to C:/Agent/wings.json unless overridden.
  const configured = process.env.WINGS_CONFIG_PATH || 'C:/Agent/wings.json';
  try {
    if (!fs.existsSync(configured)) return null;
    const raw = fs.readFileSync(configured, 'utf8');
    const parsed = JSON.parse(raw);
    log('Loaded wings config from', configured);
    WINGS_CONFIG_PATH_LOADED = configured;
    return parsed;
  } catch (e) {
    log('Failed to load or parse wings config at', configured, e.message);
    return null;
  }
} 

// Load config at startup if present

function writeWingsConfig(cfg) {
  const configured = process.env.WINGS_CONFIG_PATH || 'C:/Agent/wings.json';
  try {
    fs.writeFileSync(configured, JSON.stringify(cfg, null, 2), 'utf8');
    log('Persisted wings config to', configured);
    return true;
  } catch (e) {
    log('Failed to persist wings config to', configured, e.message);
    return false;
  }
} 

// Do NOT auto-generate node tokens here. Tokens should come from Panel via /api/update or environment variables.
WINGS_CONFIG = loadWingsConfig();

function getNodeToken() {
  // precedence: PANEL_TOKEN env (explicit), WINGS_TOKEN env, token in config
  if (process.env.PANEL_TOKEN && process.env.PANEL_TOKEN !== '') return process.env.PANEL_TOKEN;
  if (process.env.WINGS_TOKEN && process.env.WINGS_TOKEN !== '') return process.env.WINGS_TOKEN;
  if (WINGS_CONFIG && (WINGS_CONFIG.token || WINGS_CONFIG.api && WINGS_CONFIG.api.token)) return WINGS_CONFIG.token || (WINGS_CONFIG.api && WINGS_CONFIG.api.token);
  return '';
}

function requireAuth(req, res) {
  const nodeToken = getNodeToken();
  if (!nodeToken) return true; // no token configured -> allow for local testing
  const auth = req.get('authorization') || '';
  if (!auth.startsWith('Bearer ')) return false;
  const token = auth.split(' ')[1].trim();
  return token === nodeToken;
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
app.use(cors({ origin: true, methods: ['GET','POST','OPTIONS'], allowedHeaders: ['Authorization','Content-Type'] }));
app.use(morgan('combined', { stream: { write: (s) => daemonLog.write(s) } }));

// Ensure daemon log has an initial banner so file is created and easy to find
daemonLog.write(`[${new Date().toISOString()}] daemon starting\n`);

// Simple request logger that writes an entry immediately to requests.log (helps debugging 504s)
app.use((req, res, next) => {
  try {
    const entry = JSON.stringify({ t: new Date().toISOString(), ip: req.ip || req.socket.remoteAddress, method: req.method, url: req.originalUrl || req.url }) + '\n';
    fs.appendFileSync(path.join(LOG_DIR, 'requests.log'), entry, 'utf8');
  } catch (e) {
    daemonLog.write(`[${new Date().toISOString()}] failed to write requests.log ${e.message}\n`);
  }
  next();
});

// Allow preflight requests to pass without auth
app.options('/api/*', (req, res) => {
  res.set('Access-Control-Allow-Origin','*');
  res.set('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers','Authorization,Content-Type');
  res.sendStatus(204);
});

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

// Root and system endpoints
app.get('/', (req, res) => {
  res.send('Mock Wings daemon');
});

app.get('/api/system', (req, res) => {
  const config = WINGS_CONFIG; // loaded at startup if present

  // If ?v=2 request, return richer structured information (mirrors wings GetSystemInformation v=2)
  if (req.query.v === '2') {
    const sys = {
      version: '0.1.0-fake',
      docker: {
        version: { Version: 'unknown' },
        cgroups: { driver: 'unknown', version: 'unknown' },
        containers: { total: 0, running: 0, paused: 0, stopped: 0 },
        storage: { driver: 'unknown', filesystem: 'unknown' },
        runc: { version: 'unknown' }
      },
      system: {
        architecture: process.arch,
        cpu_threads: os.cpus() ? os.cpus().length : 1,
        memory_bytes: os.totalmem ? os.totalmem() : 0,
        kernel_version: os.release(),
        os: os.type(),
        os_type: os.platform()
      }
    };

    const response = {
      version: sys.version,
      docker: {
        version: sys.docker.version, // keep shape similar
        cgroups: { driver: sys.docker.cgroups.driver, version: sys.docker.cgroups.version },
        containers: sys.docker.containers,
        storage: sys.docker.storage,
        runc: sys.docker.runc
      },
      system: sys.system
    };

    log('GET /api/system?v=2 ->', config?.uuid || process.env.WINGS_UUID || 'no-uuid');
    return res.json(response);
  }

  // Provide both v1-style top-level system fields (used by Panel's SystemInformation view)
  // and the `system` object for v2-like consumers. This keeps compatibility with Pterodactyl Panel.
  const arch = process.arch;
  const cpuCount = os.cpus ? os.cpus().length : 1;
  const kernelVersion = os.release();
  const osName = (config && (config.system && config.system.os)) ? config.system.os : os.type();

  // Prefer token from configured sources (env/WINGS_CONFIG), but fall back to config.token if present
  const nodeToken = getNodeToken() || config?.token || null;
  const apiCfg = config?.api || { host: '0.0.0.0', port: 8080, ssl: { enabled: true } };
  const sslInfo = {
    enabled: apiCfg.ssl?.enabled ?? true,
    cert: apiCfg.ssl?.cert || process.env.SSL_CERT_PATH || (fs.existsSync(SSL_CERT) ? SSL_CERT : null),
    key: apiCfg.ssl?.key || process.env.SSL_KEY_PATH || (fs.existsSync(SSL_KEY) ? SSL_KEY : null)
  };

  const response = {
    // v1-style compatible fields
    version: '0.1.0-fake',
    os: osName,
    architecture: arch,
    kernel_version: kernelVersion,
    cpu_count: cpuCount,

    // identification and token fields
    debug: config?.debug ?? false,
    uuid: config?.uuid || process.env.WINGS_UUID || process.env.NODE_UUID || null,
    token_id: config?.token_id || process.env.WINGS_TOKEN_ID || null,
    token: nodeToken,

    // path to the loaded config file (JSON preferred)
    config_path: WINGS_CONFIG_PATH_LOADED || process.env.WINGS_CONFIG_PATH || 'C:/Agent/wings.json',

    api: { host: apiCfg.host, port: apiCfg.port, ssl: sslInfo, upload_limit: apiCfg.upload_limit || 100 },

    system: Object.assign({}, config?.system || {}, {
      data: (config?.system && config.system.data) ? config.system.data : path.join(SERVERS_ROOT),
      sftp: { bind_port: config?.system?.sftp?.bind_port || (process.env.SFTP_PORT ? parseInt(process.env.SFTP_PORT, 10) : 2022) }
    }),

    allowed_mounts: config?.allowed_mounts || [],

    remote: config?.remote || process.env.PANEL_REMOTE || null
  };

  log('GET /api/system ->', response.uuid || 'no-uuid');
  res.json(response);
});

app.options('/api/system', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Authorization,Content-Type');
  res.sendStatus(204);
});

// Allow the panel to POST new configuration (mirrors wings /api/update)
app.post('/api/update', (req, res) => {
  const cfg = req.body || {};
  const configPath = process.env.WINGS_CONFIG_PATH || 'C:/Agent/wings.json';

  try {
    fs.writeFileSync(configPath, JSON.stringify(cfg, null, 2), 'utf8');
    WINGS_CONFIG = cfg; // update in-memory copy
    WINGS_CONFIG_PATH_LOADED = configPath;
    log('Updated wings config and persisted to', configPath);
    return res.json({ applied: true });
  } catch (e) {
    log('Failed to write wings config to', configPath, e.message);
    return res.status(500).json({ applied: false, error: e.message });
  }
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
  }
}

// POST /api/servers/:serverId/ws/authorize -> issues a websocket JWT for a user
app.post('/api/servers/:serverId/ws/authorize', (req, res) => {
  const serverId = req.params.serverId;
  const body = req.body || {};
  const user_uuid = body.user_uuid || body.user || null;
  const permissions = Array.isArray(body.permissions) ? body.permissions : ['websocket.connect', 'control.console'];
  const ttl = parseInt(body.ttl || 3600, 10);

  const nodeToken = getNodeToken();
  if (!nodeToken) return res.status(500).json({ error: 'node token not configured' });

  if (!user_uuid) return res.status(400).json({ error: 'user_uuid required' });

  // jti is md5(user_id + server_uuid)
  const jti = crypto.createHash('md5').update(String(user_uuid) + String(serverId)).digest('hex');
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;

  const payload = {
    jti: jti,
    user_uuid: user_uuid,
    server_uuid: serverId,
    permissions: permissions,
    iat: iat,
    exp: exp,
  };

  const token = jwt.sign(payload, nodeToken, { algorithm: 'HS256' });
  return res.json({ token: token, socket: `wss://${req.headers.host}/api/servers/${serverId}/ws`, jti: jti, ttl: ttl });
});

// POST /api/servers/:serverId/ws/deny -> deny list JTIs
app.post('/api/servers/:serverId/ws/deny', (req, res) => {
  const data = req.body || {};
  const jtis = Array.isArray(data.jtis) ? data.jtis : [];
  const now = Date.now();
  for (const jti of jtis) {
    wsDenylist.set(jti, now);
  }
  log('Added JTIs to denylist for server', req.params.serverId, jtis);
  return res.status(204).send();
});

// Helper to verify websocket token
function verifyWsToken(tokenStr, serverId) {
  const nodeToken = getNodeToken();
  if (!nodeToken) return { valid: false, reason: 'node token not configured' };
  try {
    const payload = jwt.verify(tokenStr, nodeToken, { algorithms: ['HS256'] });
    // Check server uuid
    if (!payload.server_uuid || String(payload.server_uuid) !== String(serverId)) return { valid: false, reason: 'server uuid mismatch' };
    // Check permissions
    if (!Array.isArray(payload.permissions) || !payload.permissions.includes('websocket.connect')) return { valid: false, reason: 'missing websocket.connect permission' };
    // Check jti not denylisted
    if (payload.jti && wsDenylist.has(payload.jti)) {
      return { valid: false, reason: 'jti denylisted' };
    }
    return { valid: true, payload: payload };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// Setup a dedicated WebSocket handler that will be used for console connections.
const wss = new WebSocket.Server({ noServer: true });

httpsServer.on('upgrade', (req, socket, head) => {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const pathname = url.pathname;
    const match = pathname.match(/^\/api\/servers\/([^\/]+)\/ws$/);
    if (!match) {
      socket.destroy();
      return;
    }
    const serverId = match[1];

    // Simple token auth: check query param 'token' or Authorization header
    const tokenQuery = url.searchParams.get('token');
    const authHeader = req.headers['authorization'] || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1].trim() : '';

    // Read server metadata
    const metaPath = path.join('C:', 'Servers', `sbox-${serverId}`, 'server.json');
    let meta = null;
    if (fs.existsSync(metaPath)) {
      try { meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')); } catch (e) { meta = null; }
    }

    // Validate PID exists and is running
    const pidValid = meta && meta.pid && !isNaN(parseInt(meta.pid, 10)) && isRunning(meta);
    if (!pidValid) {
      // Reject upgrade
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }

    // Validate token: accept if matches node token or instance_token
    const nodeToken = getNodeToken();
    const instanceToken = meta && meta.instance_token ? meta.instance_token : '';
    if (nodeToken && bearer !== nodeToken && tokenQuery !== nodeToken && bearer !== instanceToken && tokenQuery !== instanceToken) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit('connection', ws, req, serverId, meta);
    });
  } catch (e) {
    socket.destroy();
  }
});

wss.on('connection', (ws, req, serverId, meta) => {
  log('WebSocket console connected for', serverId, 'from', req.socket.remoteAddress);
  // Send welcome message
  ws.send(JSON.stringify({ event: 'welcome', server_id: serverId, pid: meta.pid }));

  // Authenticated flag and user info
  ws._authenticated = false;
  ws._user = null;

  ws.on('message', (data) => {
    let text = data;
    if (Buffer.isBuffer(data)) text = data.toString('utf8');

    // Attempt to parse JSON message event
    let msg = null;
    try { msg = JSON.parse(text); } catch (e) { msg = null; }

    // Handle auth event: { event: 'auth', args: ['<token>'] }
    if (msg && msg.event === 'auth' && Array.isArray(msg.args) && msg.args.length > 0) {
      const token = msg.args[0];
      const verified = verifyWsToken(token, serverId);
      if (!verified.valid) {
        ws.send(JSON.stringify({ event: 'jwt error', args: [verified.reason || 'invalid token'] }));
        ws.close();
        return;
      }
      ws._authenticated = true;
      ws._user = verified.payload.user_uuid || null;
      ws.send(JSON.stringify({ event: 'auth success' }));
      return;
    }

    // If not authenticated, reject other messages
    if (!ws._authenticated) {
      ws.send(JSON.stringify({ event: 'jwt error', args: ['not authenticated'] }));
      return;
    }

    // Treat authenticated incoming messages as console input
    const serverDir = path.join('C:', 'Servers', `sbox-${serverId}`);
    const consoleLog = path.join(serverDir, 'console.log');
    const ts = new Date().toISOString();
    fs.appendFileSync(consoleLog, `${ts}Z WS ${text}\n`, 'utf8');
    // Echo back a stubbed response
    ws.send(JSON.stringify({ event: 'stdout', data: `Stub response: ${text}` }));
  });

  ws.on('close', () => {
    log('WebSocket console disconnected for', serverId);
  });
});
process.on('uncaughtException', (err) => {
  log('uncaughtException', err.stack || err.message || err);
});

process.on('SIGINT', () => {
  log('Shutting down');
  daemonLog.end(() => process.exit(0));
});
