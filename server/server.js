'use strict';
/**
 * Render tunnel server.
 *
 * Transports (all ride on Render's HTTPS/WSS on port 443, or HTTP on port 80):
 *   1. HTTP CONNECT proxy      -> used directly by Chrome (chrome.proxy API)
 *   2. Plain HTTP forward proxy -> same, for http:// sites
 *   3. WebSocket tunnel (/ws)  -> used by the optional local client when CONNECT
 *                                 is blocked by the network or edge
 *
 * Safety / resource controls:
 *   - TOKEN required for everything except /health, /ip, /echo
 *   - Hard session cap (MAX_SESSION_HOURS) and idle cap (IDLE_MINUTES)
 *   - Private/internal addresses are blocked (no SSRF into Render's network)
 *   - SMTP ports blocked (no spam relay)
 */
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const dns = require('dns').promises;
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 10000;
const TOKEN = process.env.TOKEN;
const LABEL = process.env.REGION_LABEL || process.env.RENDER_SERVICE_NAME || 'tunnel';
const MAX_MS = (Number(process.env.MAX_SESSION_HOURS) || 3) * 3600e3;
const IDLE_MS = (Number(process.env.IDLE_MINUTES) || 20) * 60e3;
const BLOCKED_PORTS = new Set([25, 465, 587]);

if (!TOKEN || TOKEN.length < 12) {
  console.error('Set a TOKEN env var of at least 12 characters.');
  process.exit(1);
}

const tunnels = new Set(); // objects with .destroy()
let session = null; // { start, last }
let bytes = 0;

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- auth ----------
function safeEq(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function basicOk(h) {
  if (!h || !h.startsWith('Basic ')) return false;
  const dec = Buffer.from(h.slice(6), 'base64').toString();
  return safeEq(dec.slice(dec.indexOf(':') + 1), TOKEN);
}
function bearerOk(req, url) {
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ') && safeEq(h.slice(7), TOKEN)) return true;
  return url && safeEq(url.searchParams.get('token') || '', TOKEN);
}

// ---------- session limits ----------
function allowed() {
  if (!session) session = { start: Date.now(), last: Date.now() };
  return Date.now() - session.start <= MAX_MS;
}
function touch() {
  if (session) session.last = Date.now();
}
function killAll() {
  for (const t of [...tunnels]) {
    try { t.destroy(); } catch {}
  }
  tunnels.clear();
}
setInterval(() => {
  if (!session) return;
  const now = Date.now();
  if (now - session.start > MAX_MS) {
    log('max session reached; closing tunnels');
    killAll();
  } else if (now - session.last > IDLE_MS && tunnels.size === 0) {
    session = null;
  } else if (now - session.last > IDLE_MS) {
    log('idle; closing tunnels');
    killAll();
    session = null;
  }
}, 30e3).unref();

// ---------- address safety ----------
function isPrivate(ip) {
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::') return true;
    if (l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb')) return true;
    const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return m ? isPrivate(m[1]) : false;
  }
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}
async function resolveSafe(host, port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad port');
  if (BLOCKED_PORTS.has(port)) throw new Error('port blocked');
  const { address } = await dns.lookup(host);
  if (isPrivate(address)) throw new Error('private address blocked');
  return address; // connect by IP: no DNS-rebinding window
}
function splitHostPort(s, defPort) {
  let host = s, port = defPort;
  const i = s.lastIndexOf(':');
  if (i > -1 && !s.endsWith(']')) { host = s.slice(0, i); port = Number(s.slice(i + 1)); }
  return [host.replace(/^\[|\]$/g, ''), port];
}
async function openUpstream(host, port) {
  const addr = await resolveSafe(host, port);
  return await new Promise((res, rej) => {
    const s = net.connect({ host: addr, port, timeout: 15e3 });
    s.setNoDelay(true);
    s.once('connect', () => { s.setTimeout(0); res(s); });
    s.once('error', rej);
    s.once('timeout', () => { s.destroy(); rej(new Error('upstream timeout')); });
  });
}
function track(...socks) {
  const t = { destroy: () => socks.forEach((s) => s.destroy()) };
  tunnels.add(t);
  const done = () => { tunnels.delete(t); socks.forEach((s) => s.destroy()); };
  socks.forEach((s) => { s.on('close', done); s.on('error', () => {}); });
}
function deny407(sock) {
  sock.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="tunnel"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
}

// ---------- HTTP server ----------
const server = http.createServer(async (req, res) => {
  // Forward-proxy request for plain http:// sites
  if (/^https?:\/\//i.test(req.url)) {
    if (!basicOk(req.headers['proxy-authorization'])) {
      res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="tunnel"' });
      return res.end();
    }
    if (!allowed()) { res.writeHead(429); return res.end('session limit reached'); }
    touch();
    try {
      const u = new URL(req.url);
      const port = Number(u.port) || 80;
      const addr = await resolveSafe(u.hostname, port);
      const headers = { ...req.headers };
      delete headers['proxy-authorization'];
      delete headers['proxy-connection'];
      const up = http.request({ host: addr, port, method: req.method, path: u.pathname + u.search, headers }, (r) => {
        res.writeHead(r.statusCode, r.headers);
        r.pipe(res);
        r.on('data', (d) => { bytes += d.length; });
      });
      up.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(up);
    } catch (e) {
      res.writeHead(502); res.end(String(e.message));
    }
    return;
  }

  const url = new URL(req.url, 'http://x');
  const json = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(obj));
  };

  if (url.pathname === '/health') {
    return json(200, { ok: true, label: LABEL, uptime: Math.round(process.uptime()), tunnels: tunnels.size });
  }
  if (url.pathname === '/ip') {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    return json(200, { ip });
  }
  if (url.pathname === '/echo') { // speed test payload, capped at 5 MB
    const n = Math.min(Number(url.searchParams.get('size')) || 1e6, 5e6);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': n, 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
    return res.end(Buffer.alloc(n));
  }
  if (url.pathname.startsWith('/session/') || url.pathname === '/status') {
    if (!bearerOk(req, url)) return json(401, { error: 'bad token' });
    if (url.pathname === '/session/start') {
      killAll();
      session = { start: Date.now(), last: Date.now() };
      return json(200, { ok: true, maxHours: MAX_MS / 3600e3, idleMinutes: IDLE_MS / 60e3 });
    }
    if (url.pathname === '/session/stop') {
      killAll(); session = null;
      return json(200, { ok: true });
    }
    return json(200, {
      label: LABEL, tunnels: tunnels.size, bytes, session,
      remainingMs: session ? Math.max(0, MAX_MS - (Date.now() - session.start)) : null,
    });
  }
  json(404, { error: 'not found' });
});

// HTTPS tunnelling via CONNECT
server.on('connect', async (req, sock, head) => {
  sock.on('error', () => {});
  if (!basicOk(req.headers['proxy-authorization'])) return deny407(sock);
  if (!allowed()) return sock.end('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
  touch();
  try {
    const [host, port] = splitHostPort(req.url, 443);
    const up = await openUpstream(host, port);
    sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) up.write(head);
    track(sock, up);
    up.pipe(sock);
    sock.pipe(up);
    up.on('data', (d) => { bytes += d.length; touch(); });
    sock.on('data', (d) => { bytes += d.length; touch(); });
  } catch (e) {
    sock.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
  }
});

// ---------- WebSocket tunnel (for the local client) ----------
const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 8 * 1024 * 1024 });
server.on('upgrade', (req, sock, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws' || !bearerOk(req, url) || !allowed()) {
    sock.end('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return;
  }
  wss.handleUpgrade(req, sock, head, (ws) => {
    let up = null;
    ws.on('message', async (data, isBinary) => {
      touch();
      if (up) { bytes += data.length; return up.write(data); }
      try { // first message: {"host":"example.com","port":443}
        const { host, port } = JSON.parse(data.toString());
        up = await openUpstream(String(host), Number(port));
        const t = { destroy: () => { up.destroy(); ws.terminate(); } };
        tunnels.add(t);
        up.on('close', () => { tunnels.delete(t); ws.close(); });
        up.on('error', () => ws.terminate());
        ws.on('close', () => { tunnels.delete(t); up.destroy(); });
        up.on('data', (d) => {
          bytes += d.length; touch();
          ws.send(d);
          if (ws.bufferedAmount > 4e6) {
            up.pause();
            const iv = setInterval(() => {
              if (ws.readyState !== 1) return clearInterval(iv);
              if (ws.bufferedAmount < 1e6) { clearInterval(iv); up.resume(); }
            }, 20);
          }
        });
        ws.send('ok');
      } catch (e) {
        ws.send('err:' + e.message);
        ws.close();
      }
    });
    ws.on('error', () => {});
  });
});

server.keepAliveTimeout = 65e3;
server.headersTimeout = 70e3;
server.listen(PORT, '0.0.0.0', () => log(`tunnel "${LABEL}" listening on ${PORT} (max ${MAX_MS / 3600e3}h, idle ${IDLE_MS / 60e3}m)`));
process.on('uncaughtException', (e) => log('uncaught', e.message));
