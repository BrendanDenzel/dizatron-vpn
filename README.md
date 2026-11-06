# Render Tunnel

A Chrome extension, a small Node server for Render, and a local client. Chrome's traffic goes to the local client, which relays it over a WebSocket (TLS) to your Render server, which opens the real connection.

```
Chrome  ->  local client (127.0.0.1)  ==WebSocket/TLS==>  Render server  ->  the internet
```

This is a TLS tunnel, not an OS-level VPN. Render's free tier only accepts HTTP(S) and WebSocket traffic, and its edge rejects the proxy `CONNECT` request, so Chrome can't talk to Render directly. The local client works around that. DNS is resolved on the server, so the local network doesn't see which sites you visit.

## Layout

```
server/      Node tunnel server (deploy to Render)
client/      Local client (runs on your computer)
extension/   Chrome extension (Manifest V3)
render.yaml  Render Blueprint (3 regions, shared token)
```

## Setup

### 1. Render
Push `server/` and `render.yaml` to GitHub, then Render -> New -> Blueprint. Copy the generated `TOKEN` from the `vpn-shared` env group and the URL of each service. After changing server code, push and let Render redeploy.

### 2. Local client
```bash
cd client
npm install
SERVERS=https://vpn-virginia-xxxx.onrender.com TOKEN=yourtoken node local-client.js
```
Or copy `config.example.json` to `config.json`, fill it in, and run `npm start`. Several servers can be listed with commas (`SERVERS=urlA,urlB`) for automatic failover. Leave the client running while you browse.

On start it wakes the servers, probes every strategy and picks one that works. Its log prints which strategy it chose, failures and live traffic. Set `LOG=verbose` to also print destination hostnames.

### 3. Extension
`chrome://extensions` -> Developer mode -> Load unpacked -> `extension/`. In Options, enter your server URLs, the token and your limits. Click the icon, select the same server the client uses, and click Connect.

## Connection modes (popup)

| Mode | Notes |
|---|---|
| Auto | Tries Local HTTP, Local SOCKS5, then direct HTTPS and HTTP; remembers the last one that worked |
| Local client - HTTP proxy | Default that works on Render |
| Local client - SOCKS5 | Same tunnel, SOCKS5 front door; other apps can use `127.0.0.1:1080` too |
| Direct HTTPS / HTTP proxy | Only for hosts that accept CONNECT; Render usually does not |

## Obfuscation (popup dropdown, applied live to the client)

| Level | What it does | Cost |
|---|---|---|
| Plain | Ordinary WebSocket messages over TLS | Fastest |
| Padded | Each message gets random padding | Tiny |
| Full | Padding, random chunk sizes and decoy messages at connection start | Small |

Every level is encrypted by TLS already. The extra levels only hide traffic patterns (message sizes) from a filter that looks at them.

Other disguises that are always on: the WebSocket path is varied (`/ws`, `/api/v1/stream`, a socket.io-style path), the client sends browser-like headers, the server shows an ordinary decoy page at `/`, and unauthenticated requests get a plain 404 instead of an "unauthorized" error.

Experimental: set `FRONT` (and `FRONT_SNI`) in the client to connect to a different host while keeping the real Host header. This only works if Render's edge accepts it, and may not.

## Speed

- **Warm sockets:** the client keeps 2 sockets ready (`WARM`), saving a handshake per new connection. It stops doing this after 5 idle minutes so it doesn't keep Render awake.
- Pick the nearest region.
- Split mode (Options -> tunnel only these domains) leaves everything else direct.
- The first request after Render sleeps takes 30-60 seconds.

## Debugging

- **Debug page:** direct tests, WebSocket test, token test, speed, DNS-over-HTTPS and each mode. It also has a local client panel (strategy list with probe results, "Probe all", "Use this", "Auto"), the client log and the Render server log.
- **Popup:** shows whether the client is running and which strategy it uses.
- **Server `/logs`:** needs your token. Shows `open`, `open_fail`, `auth_fail`, `session` and limit events.
- If all strategies fail: check the token and URL, wait a minute for Render to wake, then probe again.

## Saving Render hours

- Auto-disconnect after N hours (default 3) and after 20 idle minutes.
- Closing all Chrome windows, or restarting Chrome, clears the proxy and stops the session.
- The server also caps sessions and idle tunnels, and `/session/stop` is called on disconnect.
- Free services sleep about 15 minutes after the last inbound traffic. Stop the local client when you're done so nothing keeps connecting.
- Free instances share a monthly hour pool (check Render's pricing page for the current number).

## Security

- Keep the token secret. Rotate it in Render's env group if it leaks, then update the client and extension.
- The client's control API only answers requests from `localhost` that carry a special header, so ordinary web pages can't change its settings or read its log.
- The server blocks private/internal addresses and SMTP ports. `ALLOW_PRIVATE=1` disables the private-address block and exists for local testing only; never set it on Render.
- Chrome's WebRTC can reveal your real IP to sites that use it. The tunnel does not prevent that.

## Check the rules

Check your Render plan's acceptable-use terms before running a proxy there, and the rules of the network you're on. Getting around a school or workplace filter may break its policy.
