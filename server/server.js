'use strict';
/**
 * Render tunnel server.
 *
 * Transports:
 *   1. WebSocket tunnel (any path, token required) -> used by the local client.
 *      Optional obfuscation per connection: plain | pad | full
 *   2. HTTP CONNECT + HTTP forward proxy (Render's edge usually rejects CONNECT,
 *      kept for hosts that allow it)
 *
 * Resource / safety controls:
 *   - TOKEN required for everything except /health, /ip, /echo and the decoy page
 *   - Hard session cap (MAX_SESSION_HOURS) and idle cap (IDLE_MINUTES)
 *   - Private/internal addresses blocked; SMTP ports blocked
 *   - Unauthenticated probes see an ordinary-looking website / 404, not "401"
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
const VERBOSE = process.env.VERBOSE === '1'; // log destination hostnames in /logs
const BLOCKED_PORTS = new Set([25, 465, 587]);

if (!TOKEN || TOKEN.length < 12) {
  console.error('Set a TOKEN env var of at least 12 characters.');
  process.exit(1);
}

const tunnels = new Set();
let session = null; // { start, last }
let bytes = 0;
const events = [];

function ev(type, info = '') {
  const e = { t: new Date().toISOString(), type, info };
  events.push(e);
  if (events.length > 200) events.shift();
  console.log(e.t, type, info);
}

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
  return !!url && safeEq(url.searchParams.get('token') || '', TOKEN);
}
const clientIp = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

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
    ev('limit', 'max session reached; closing tunnels');
    killAll();
  } else if (now - session.last > IDLE_MS) {
    if (tunnels.size) ev('limit', 'idle; closing tunnels');
    killAll();
    session = null;
  }
}, 30e3).unref();

// ---------- address safety ----------
function isPrivate(ip) {
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l === '::') return true;
    if (/^(fc|fd|fe[89ab])/.test(l)) return true;
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
  if (isPrivate(address) && process.env.ALLOW_PRIVATE !== '1') throw new Error('private address blocked'); // ALLOW_PRIVATE=1 is for local testing only
  return address;
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

// ---------- frame codec (must match client/local-client.js) ----------
// plain : raw bytes in each WebSocket message
// pad   : [u16 len][payload][random padding 0-96]
// full  : same, padding 0-255, random chunk sizes, decoy frames
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
function makeCodec(obfs) {
  if (obfs !== 'pad' && obfs !== 'full') return { full: false, enc: (b) => [b], dec: (b) => b, decoy: () => null };
  const full = obfs === 'full';
  const padMax = full ? 255 : 96;
  const nextChunk = full ? () => rnd(400, 16000) : () => 60000;
  const frame = (p, padLen) => {
    const pl = padLen === undefined ? rnd(0, padMax) : padLen;
    const f = Buffer.alloc(2 + p.length + pl);
    f.writeUInt16BE(p.length, 0);
    p.copy(f, 2);
    crypto.randomFillSync(f, 2 + p.length);
    return f;
  };
  return {
    full,
    enc(b) {
      const out = [];
      for (let i = 0; i < b.length;) {
        const n = Math.min(b.length - i, nextChunk());
        out.push(frame(b.subarray(i, i + n)));
        i += n;
      }
      return out;
    },
    dec(b) {
      if (b.length < 2) return null;
      const n = b.readUInt16BE(0);
      return n ? b.subarray(2, 2 + n) : null;
    },
    decoy: () => frame(Buffer.alloc(0), rnd(60, 500)),
  };
}

// ---------- HTTP ----------
const DECOY = '<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body style="font-family:sans-serif;max-width:40em;margin:3em auto"><h1>Welcome</h1><p>Site under construction.</p></body></html>';

const server = http.createServer(async (req, res) => {
  if (/^https?:\/\//i.test(req.url)) { // plain HTTP forward proxy
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

  if (url.pathname === '/health') return json(200, { ok: true, label: LABEL, uptime: Math.round(process.uptime()), tunnels: tunnels.size });
  if (url.pathname === '/ip') return json(200, { ip: clientIp(req) });
  if (url.pathname === '/echo') {
    const n = Math.min(Number(url.searchParams.get('size')) || 1e6, 5e6);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': n, 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
    return res.end(Buffer.alloc(n));
  }
  if (url.pathname === '/session/start' || url.pathname === '/session/stop' || url.pathname === '/status' || url.pathname === '/logs') {
    if (!bearerOk(req, url)) {
      ev('auth_fail', `${url.pathname} from ${clientIp(req)}`);
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not Found');
    }
    if (url.pathname === '/session/start') {
      killAll();
      session = { start: Date.now(), last: Date.now() };
      ev('session', 'started');
      return json(200, { ok: true, maxHours: MAX_MS / 3600e3, idleMinutes: IDLE_MS / 60e3 });
    }
    if (url.pathname === '/session/stop') {
      killAll(); session = null;
      ev('session', 'stopped');
      return json(200, { ok: true });
    }
    if (url.pathname === '/logs') return json(200, { events });
    return json(200, {
      label: LABEL, tunnels: tunnels.size, bytes, session,
      remainingMs: session ? Math.max(0, MAX_MS - (Date.now() - session.start)) : null,
    });
  }
  if (url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(DECOY);
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// CONNECT (kept for hosts that allow it)
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
  } catch {
    sock.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
  }
});

// ---------- WebSocket tunnel (ANY path, token required) ----------
const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 8 * 1024 * 1024 });
server.on('upgrade', (req, sock, head) => {
  const url = new URL(req.url, 'http://x');
  if (!bearerOk(req, url)) {
    ev('auth_fail', `ws ${url.pathname} from ${clientIp(req)}`);
    sock.end('HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    return;
  }
  if (!allowed()) {
    sock.end('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    return;
  }
  wss.handleUpgrade(req, sock, head, (ws) => {
    let up = null;
    let cd = makeCodec('plain');
    let started = false;
    const deadline = setTimeout(() => { if (!up) ws.terminate(); }, 90e3); // unused warm sockets
    ws.on('error', () => {});
    ws.on('close', () => clearTimeout(deadline));
    ws.on('message', async (data) => {
      touch();
      if (up) {
        const p = cd.dec(data);
        if (p && p.length) { bytes += p.length; up.write(p); }
        return;
      }
      if (started) return;
      started = true;
      try {
        const m = JSON.parse(data.toString()); // {host, port, obfs, p: junk} or {probe:1}
        cd = makeCodec(m.obfs);
        if (m.probe) {
          ws.send('ok');
          setTimeout(() => ws.close(), 50);
          return;
        }
        up = await openUpstream(String(m.host), Number(m.port));
        const t = { destroy: () => { up.destroy(); ws.terminate(); } };
        tunnels.add(t);
        ev('open', `${m.obfs || 'plain'}${VERBOSE ? ' ' + m.host + ':' + m.port : ''}`);
        const finish = () => { tunnels.delete(t); up.destroy(); ws.terminate(); };
        up.on('close', finish);
        up.on('error', finish);
        ws.on('close', finish);
        up.on('data', (d) => {
          bytes += d.length; touch();
          for (const f of cd.enc(d)) ws.send(f);
          if (ws.bufferedAmount > 4e6) {
            up.pause();
            const iv = setInterval(() => {
              if (ws.readyState !== 1) return clearInterval(iv);
              if (ws.bufferedAmount < 1e6) { clearInterval(iv); up.resume(); }
            }, 20);
          }
        });
        ws.send('ok');
        if (cd.full) { ws.send(cd.decoy()); ws.send(cd.decoy()); }
      } catch (e) {
        ev('open_fail', e.message);
        try { ws.send('err:' + e.message); } catch {}
        ws.close();
      }
    });
  });
});
// keep long-lived tunnels from being dropped by idle middleboxes
setInterval(() => wss.clients.forEach((c) => { try { c.ping(); } catch {} }), 30e3).unref();

server.keepAliveTimeout = 65e3;
server.headersTimeout = 70e3;
server.listen(PORT, '0.0.0.0', () => ev('start', `tunnel "${LABEL}" on ${PORT} (max ${MAX_MS / 3600e3}h, idle ${IDLE_MS / 60e3}m)`));
process.on('uncaughtException', (e) => ev('uncaught', e.message));
