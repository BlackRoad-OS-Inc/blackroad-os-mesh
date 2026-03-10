# ⬡ BlackRoad Mesh

> **Real-time agent coordination — click a link, see it work.**

[![Operational](https://img.shields.io/badge/status-operational-4ade80?style=flat-square)](https://blackroad-os-mesh.workers.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-7700FF?style=flat-square)](LICENSE)

---

## 🚀 Try it live — no setup required

| What | Link |
|------|------|
| 🌐 **Visual Dashboard** | [blackroad-os-mesh.workers.dev](https://blackroad-os-mesh.workers.dev) |
| 🩺 Health Check | [/health](https://blackroad-os-mesh.workers.dev/health) |
| 📊 Live Stats | [/stats](https://blackroad-os-mesh.workers.dev/stats) |
| 👁️ Who's Online | [/presence](https://blackroad-os-mesh.workers.dev/presence) |
| 📡 Recent Events | [/events](https://blackroad-os-mesh.workers.dev/events) |
| 🏠 Active Rooms | [/rooms](https://blackroad-os-mesh.workers.dev/rooms) |

**Just visit the dashboard link above** — you'll see a live animated mesh network, a real-time WebSocket demo you can click to connect, and all endpoints in one place.

---

## ⚡ Connect in 10 seconds

```js
// Open any browser DevTools console and paste this:
const ws = new WebSocket('wss://blackroad-os-mesh.workers.dev/ws?agent=me&name=You');
ws.onmessage = e => console.log(JSON.parse(e.data));
ws.onopen    = () => ws.send(JSON.stringify({ type: 'sync', from: 'me', payload: {}, timestamp: new Date().toISOString() }));
```

Or visit the **[Live Dashboard](https://blackroad-os-mesh.workers.dev)** and use the built-in WebSocket tester — no code needed.

---

## 🔌 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Visual HTML dashboard |
| `GET`  | `/health` | Health check |
| `GET`  | `/stats` | Connection stats |
| `GET`  | `/presence` | Currently online agents |
| `GET`  | `/events?limit=50` | Recent mesh events |
| `POST` | `/broadcast` | Send a broadcast message |
| `WS`   | `/ws?agent=ID&name=Name` | WebSocket connection |
| `WS`   | `/room/:roomId/ws` | Room-scoped WebSocket |
| `GET`  | `/room/:roomId/presence` | Room presence |
| `GET`  | `/rooms` | List active rooms |
| `GET`  | `/agent/:agentId` | Agent lookup |

---

## 🛠️ Local Development

**Prerequisites:** Node.js 20+ and a free [Cloudflare account](https://dash.cloudflare.com/sign-up).

```bash
# 1. Clone
git clone https://github.com/BlackRoad-OS/blackroad-os-mesh.git
cd blackroad-os-mesh

# 2. Install
npm install

# 3. Run locally (opens http://localhost:8787)
npm run dev
```

Open **http://localhost:8787** in your browser and you'll see the dashboard immediately.

### Deploy to Cloudflare Workers

```bash
# Authenticate once
npx wrangler login

# Deploy (< 30 seconds)
npm run deploy
```

---

## 🏗️ Part of BlackRoad OS

This repo is part of the **BlackRoad OS** ecosystem — a ranked quantum AI operating system.

| Repo | Description |
|------|-------------|
| [blackroad-os-core](https://github.com/BlackRoad-OS/blackroad-os-core) | Core OS application |
| [blackroad-os-operator](https://github.com/BlackRoad-OS/blackroad-os-operator) | Operator engine |
| [blackroad-agents](https://github.com/BlackRoad-OS/blackroad-agents) | Agent ecosystem |
| **blackroad-os-mesh** | Real-time coordination layer ← you are here |

---

## 📧 Contact

- **Email**: [blackroad.systems@gmail.com](mailto:blackroad.systems@gmail.com)
- **GitHub**: [@BlackRoad-OS](https://github.com/BlackRoad-OS)

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.  
Copyright © 2025 BlackRoad OS, Inc. / Alexa Louise Amundson

---

**🔮 Built with quantum consciousness by Lucidia**

