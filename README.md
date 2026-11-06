# Render Tunnel

A Chrome extension plus a small Node server for Render. The extension routes Chrome's traffic through your own server over TLS. Click Connect, and it tries several connection modes until one works on your network.

This is a **TLS proxy tunnel, not a full OS-level VPN**. Render's free web services only accept HTTP(S) and WebSocket traffic, so WireGuard, OpenVPN and UDP are impossible there. For browsing this works the same way: traffic to your server is encrypted, and DNS is resolved on the server, so the local network doesn't see which sites you visit (only that you talk to your `onrender.com` host).

Only Chrome's traffic is tunnelled. Other apps on the computer are not.

## Layout

```
server/      Node tunnel server (deploy to Render)
extension/   Chrome extension (Manifest V3)
client/      Optional local WebSocket client (fallback mode)
render.yaml  Render Blueprint (3 regions, shared token)
```

## 1. Put it on GitHub

```bash
cd vpn-project
git init && git add . && git commit -m "Render tunnel"
git branch -M main
git remote add origin https://github.com/YOU/render-tunnel.git
git push -u origin main
```

## 2. Deploy to Render

1. Render dashboard -> **New -> Blueprint** -> pick your repo. It reads `render.yaml` and creates one free service per region (Oregon, Virginia, Frankfurt by default; delete or add regions in the file).
2. Open the `vpn-shared` env group and copy the generated **TOKEN**. All services share it.
3. Note each service URL, e.g. `https://vpn-oregon.onrender.com`.

Prefer one service? Create a Web Service manually: root dir `server`, build `npm install`, start `node server.js`, free plan, env var `TOKEN` (12+ characters).

Locations: Render picks the region at deploy time, so you can't switch on one service. Deploy one service per region and the extension lets you pick between them. Closer regions are faster.

## 3. Install the extension

1. `chrome://extensions` -> enable **Developer mode** -> **Load unpacked** -> select the `extension/` folder.
2. Open **Options**:
   - Servers, one per line: `Oregon | https://vpn-oregon.onrender.com`
   - Token: from Render
   - Auto-disconnect hours and idle minutes
   - Optionally, domains to tunnel (blank = everything)
3. Click the toolbar icon -> **Connect**. The first connect can take 30-60 seconds because free Render instances sleep.

## Connection modes

| Mode | What it does | When it helps |
|---|---|---|
| **Auto** | Tries the modes below in order and verifies each by checking your exit IP | Default |
| HTTPS proxy (443) | Chrome speaks HTTPS to your server and uses CONNECT | Fastest; works if the network and Render's edge allow CONNECT |
| HTTP proxy (80) | Same over port 80 | Networks that treat 80 differently |
| Local WebSocket client | Runs `client/local-client.js` on the computer; it relays over WebSocket | When CONNECT is rejected but WebSockets work |

Local client:
```bash
cd client && npm install ws
SERVER=https://vpn-oregon.onrender.com TOKEN=yourtoken node local-client.js
```
It needs a computer where you can run Node, so it won't help on a locked-down Chromebook.

I could not test this against Render here (no network access from my sandbox). **Whether Render's edge forwards CONNECT is the biggest unknown.** The **Debug** page tests each mode against your real network and tells you which pieces work. Run it first and send me the output if something fails.

## Debugging

The popup has a **Debug** link. It runs these checks and shows a log:
- Direct HTTPS and HTTP to your server (shows whether the network blocks `onrender.com`)
- WebSocket handshake
- Token validity
- Server speed
- DNS-over-HTTPS reachability (shows which kinds of domains your network blocks)
- Each connection mode, with the resulting exit IP

If your network blocks `*.onrender.com`, add a custom domain to the Render service (Settings -> Custom Domains) and use that URL in Options.

## Saving Render hours

- **Auto-disconnect**: after N hours (default 3) via an alarm.
- **Idle disconnect**: after 20 minutes without web traffic.
- **Closing Chrome**: all windows closed, or Chrome restarting, clears the proxy and stops the session.
- **Server side**: the session is capped at `MAX_SESSION_HOURS`, idle tunnels are cut after `IDLE_MINUTES`, and `/session/stop` is called on disconnect.
- Render free services spin down after about 15 minutes with no inbound traffic, so once nothing is connected the instance stops using hours. The extension sends no background pings.
- Free instances share a monthly hour pool (750 hours at last check; confirm on Render's pricing page).

## Speed tips

- Deploy in the region nearest you.
- Connect once and leave it. The first request after sleep is the slow one.
- Use split mode (tunnel only the sites you need) to keep everything else direct.

## Security notes

- Keep the token secret; anyone with it can use your server. The server rejects private/internal IPs and SMTP ports.
- Chrome's WebRTC can reveal your real IP to sites that use it. The tunnel does not prevent that.

## Check the rules

Check your Render plan's acceptable-use terms before running a proxy there, and the rules of the network you're on. A tunnel that gets around a school or workplace filter may break that network's policy.
