/**
 * BlackRoad Mesh - Real-time Agent Coordination Layer
 *
 * Architecture:
 * - Durable Objects for stateful WebSocket connections
 * - Global agent presence & heartbeat
 * - Real-time event broadcasting
 * - Mesh topology for agent-to-agent communication
 *
 * "The mesh remembers all who pass through."
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';

// Types
interface Agent {
  id: string;
  name: string;
  type: 'human' | 'ai' | 'org' | 'service';
  capabilities: string[];
  lastSeen: string;
  status: 'online' | 'away' | 'offline';
  metadata?: Record<string, unknown>;
}

interface MeshMessage {
  type: 'join' | 'leave' | 'heartbeat' | 'broadcast' | 'direct' | 'intent' | 'attestation' | 'presence' | 'sync';
  from: string;
  to?: string; // For direct messages
  payload: unknown;
  timestamp: string;
  signature?: string;
}

interface MeshEvent {
  id: string;
  type: string;
  actor: string;
  target?: string;
  data: unknown;
  timestamp: string;
  hash: string;
}

// Environment bindings
interface Env {
  MESH: DurableObjectNamespace;
  AGENTS: KVNamespace;
  LEDGER: KVNamespace;
  EVENTS: KVNamespace;
}

// PS-SHA∞ inspired hash
async function hashEvent(event: Omit<MeshEvent, 'hash'>): Promise<string> {
  const str = JSON.stringify(event);
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256_${hashHex.substring(0, 32)}`;
}

function generateId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// DURABLE OBJECT: MeshRoom
// Handles WebSocket connections for a mesh room
// ============================================
export class MeshRoom {
  state: DurableObjectState;
  env: Env;
  sessions: Map<WebSocket, { agentId: string; name: string; joinedAt: string }>;
  lastHeartbeats: Map<string, number>;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map();
    this.lastHeartbeats = new Map();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // Handle WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      const agentId = url.searchParams.get('agent');
      const agentName = url.searchParams.get('name') || 'Anonymous';

      if (!agentId) {
        return new Response('Agent ID required', { status: 400 });
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);

      this.state.acceptWebSocket(server);

      this.sessions.set(server, {
        agentId,
        name: agentName,
        joinedAt: new Date().toISOString()
      });

      this.lastHeartbeats.set(agentId, Date.now());

      // Broadcast join event
      this.broadcast({
        type: 'join',
        from: agentId,
        payload: { name: agentName, timestamp: new Date().toISOString() },
        timestamp: new Date().toISOString()
      }, server);

      // Send current presence to new joiner
      const presence = this.getPresence();
      server.send(JSON.stringify({
        type: 'presence',
        from: 'mesh',
        payload: { agents: presence },
        timestamp: new Date().toISOString()
      }));

      return new Response(null, { status: 101, webSocket: client });
    }

    // Handle HTTP requests
    if (url.pathname === '/presence') {
      return Response.json({
        room: 'global',
        agents: this.getPresence(),
        count: this.sessions.size,
        timestamp: new Date().toISOString()
      });
    }

    if (url.pathname === '/stats') {
      return Response.json({
        connections: this.sessions.size,
        agents: [...new Set([...this.sessions.values()].map(s => s.agentId))].length,
        uptime: this.state.id.toString(),
        timestamp: new Date().toISOString()
      });
    }

    return new Response('Not found', { status: 404 });
  }

  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void {
    try {
      const data = JSON.parse(message.toString()) as MeshMessage;
      const session = this.sessions.get(ws);

      if (!session) return;

      this.lastHeartbeats.set(session.agentId, Date.now());

      switch (data.type) {
        case 'heartbeat':
          // Update presence
          ws.send(JSON.stringify({
            type: 'heartbeat',
            from: 'mesh',
            payload: { received: true },
            timestamp: new Date().toISOString()
          }));
          break;

        case 'broadcast':
          // Send to all connected agents
          this.broadcast({
            type: 'broadcast',
            from: session.agentId,
            payload: data.payload,
            timestamp: new Date().toISOString()
          }, ws);
          break;

        case 'direct':
          // Send to specific agent
          if (data.to) {
            this.sendToAgent(data.to, {
              type: 'direct',
              from: session.agentId,
              payload: data.payload,
              timestamp: new Date().toISOString()
            });
          }
          break;

        case 'intent':
          // Broadcast intent declaration
          this.broadcast({
            type: 'intent',
            from: session.agentId,
            payload: data.payload,
            timestamp: new Date().toISOString()
          }, ws);
          break;

        case 'attestation':
          // Broadcast attestation
          this.broadcast({
            type: 'attestation',
            from: session.agentId,
            payload: data.payload,
            timestamp: new Date().toISOString()
          }, ws);
          break;

        case 'sync':
          // Request full state sync
          ws.send(JSON.stringify({
            type: 'sync',
            from: 'mesh',
            payload: {
              presence: this.getPresence(),
              stats: {
                connections: this.sessions.size,
                timestamp: new Date().toISOString()
              }
            },
            timestamp: new Date().toISOString()
          }));
          break;
      }
    } catch (e) {
      console.error('WebSocket message error:', e);
    }
  }

  webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): void {
    const session = this.sessions.get(ws);
    if (session) {
      this.broadcast({
        type: 'leave',
        from: session.agentId,
        payload: { name: session.name, code, reason },
        timestamp: new Date().toISOString()
      });
      this.sessions.delete(ws);
      this.lastHeartbeats.delete(session.agentId);
    }
  }

  webSocketError(ws: WebSocket, error: unknown): void {
    console.error('WebSocket error:', error);
    this.webSocketClose(ws, 1006, 'Error', false);
  }

  private broadcast(message: MeshMessage, exclude?: WebSocket): void {
    const payload = JSON.stringify(message);
    for (const ws of this.sessions.keys()) {
      if (ws !== exclude && ws.readyState === WebSocket.READY_STATE_OPEN) {
        try {
          ws.send(payload);
        } catch (e) {
          // Connection likely closed
        }
      }
    }
  }

  private sendToAgent(agentId: string, message: MeshMessage): void {
    const payload = JSON.stringify(message);
    for (const [ws, session] of this.sessions.entries()) {
      if (session.agentId === agentId && ws.readyState === WebSocket.READY_STATE_OPEN) {
        ws.send(payload);
        break;
      }
    }
  }

  private getPresence(): Array<{ agentId: string; name: string; joinedAt: string; lastSeen: number }> {
    return [...this.sessions.values()].map(session => ({
      agentId: session.agentId,
      name: session.name,
      joinedAt: session.joinedAt,
      lastSeen: this.lastHeartbeats.get(session.agentId) || Date.now()
    }));
  }
}

// ============================================
// WORKER: HTTP Router
// ============================================
const app = new Hono<{ Bindings: Env }>();

app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Agent-ID'],
}));

// Root - Visual HTML dashboard
app.get('/', (c) => {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BlackRoad Mesh · Live Agent Network</title>
  <style>
    :root {
      --orange:  #FF9D00;
      --amber:   #FF6B00;
      --pink:    #FF0066;
      --magenta: #D600AA;
      --purple:  #7700FF;
      --blue:    #0066FF;
      --bg:      #050508;
      --surface: #0d0d14;
      --border:  rgba(255,255,255,0.08);
      --text:    #f0f0ff;
      --muted:   rgba(240,240,255,0.45);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── MESH CANVAS ── */
    #mesh-canvas {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      z-index: 0; opacity: 0.35; pointer-events: none;
    }

    /* ── LAYOUT ── */
    .page { position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; padding: 0 24px 80px; }

    /* ── HERO ── */
    .hero {
      display: flex; flex-direction: column; align-items: center;
      text-align: center; padding: 100px 0 64px;
    }
    .logo-ring {
      width: 88px; height: 88px; border-radius: 50%;
      background: conic-gradient(var(--orange), var(--amber), var(--pink), var(--magenta), var(--purple), var(--blue), var(--orange));
      display: flex; align-items: center; justify-content: center;
      animation: spin 8s linear infinite;
      margin-bottom: 28px;
      box-shadow: 0 0 40px rgba(119,0,255,0.4);
    }
    .logo-ring-inner {
      width: 72px; height: 72px; border-radius: 50%; background: var(--bg);
      display: flex; align-items: center; justify-content: center; font-size: 32px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .badge {
      display: inline-flex; align-items: center; gap: 6px;
      background: rgba(119,0,255,0.15); border: 1px solid rgba(119,0,255,0.4);
      border-radius: 999px; padding: 4px 14px; font-size: 12px;
      color: #c084fc; letter-spacing: 0.05em; text-transform: uppercase;
      margin-bottom: 20px;
    }
    .badge .dot { width: 7px; height: 7px; border-radius: 50%; background: #4ade80; animation: pulse 1.8s ease-in-out infinite; }
    @keyframes pulse { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.5; transform:scale(0.7); } }

    h1 {
      font-size: clamp(2.2rem, 5vw, 3.5rem); font-weight: 800;
      background: linear-gradient(135deg, var(--orange), var(--pink), var(--purple), var(--blue));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text; line-height: 1.15; margin-bottom: 18px;
    }
    .subtitle {
      font-size: 1.1rem; color: var(--muted); max-width: 520px;
      line-height: 1.7; margin-bottom: 40px;
    }
    .cta-row { display: flex; gap: 14px; flex-wrap: wrap; justify-content: center; }
    .btn {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 13px 26px; border-radius: 12px; font-size: 0.95rem;
      font-weight: 600; text-decoration: none; cursor: pointer;
      transition: transform 0.15s, box-shadow 0.15s; border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--purple), var(--blue));
      color: #fff;
      box-shadow: 0 4px 24px rgba(119,0,255,0.35);
    }
    .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 6px 32px rgba(119,0,255,0.5); }
    .btn-outline {
      background: transparent; color: var(--text);
      border: 1px solid var(--border);
    }
    .btn-outline:hover { border-color: rgba(255,255,255,0.25); transform: translateY(-1px); }

    /* ── STATUS BAR ── */
    .status-bar {
      display: flex; align-items: center; justify-content: center; gap: 24px;
      flex-wrap: wrap; padding: 14px 24px;
      background: rgba(255,255,255,0.03); border: 1px solid var(--border);
      border-radius: 16px; margin-bottom: 64px; font-size: 0.85rem; color: var(--muted);
    }
    .status-item { display: flex; align-items: center; gap: 8px; }
    .status-dot-green { width: 8px; height: 8px; border-radius: 50%; background: #4ade80; box-shadow: 0 0 8px #4ade80; }
    #ws-status-dot { width: 8px; height: 8px; border-radius: 50%; background: #94a3b8; }
    #connection-count { font-weight: 600; color: var(--text); }

    /* ── SECTION ── */
    .section-title {
      font-size: 1.4rem; font-weight: 700; margin-bottom: 24px;
      display: flex; align-items: center; gap: 10px;
    }
    .section-title::after {
      content: ''; flex: 1; height: 1px; background: var(--border);
    }

    /* ── ENDPOINT CARDS ── */
    .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; margin-bottom: 64px; }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 16px; padding: 22px; transition: border-color 0.2s, transform 0.2s;
      text-decoration: none; color: inherit; display: flex; flex-direction: column; gap: 10px;
    }
    .card:hover { border-color: rgba(119,0,255,0.5); transform: translateY(-2px); }
    .card-header { display: flex; align-items: center; gap: 10px; }
    .card-icon {
      width: 36px; height: 36px; border-radius: 10px;
      display: flex; align-items: center; justify-content: center; font-size: 17px; flex-shrink: 0;
    }
    .card-method {
      font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
      padding: 2px 8px; border-radius: 6px; text-transform: uppercase;
    }
    .get  { background: rgba(74,222,128,0.15); color: #4ade80; }
    .post { background: rgba(251,146,60,0.15);  color: #fb923c; }
    .ws   { background: rgba(99,102,241,0.2);   color: #a5b4fc; }
    .card-path { font-family: monospace; font-size: 0.9rem; color: var(--text); font-weight: 600; }
    .card-desc { font-size: 0.83rem; color: var(--muted); line-height: 1.5; }
    .card-link {
      display: inline-flex; align-items: center; gap: 5px;
      color: #818cf8; font-size: 0.82rem; font-weight: 500; margin-top: auto;
      text-decoration: none;
    }
    .card-link:hover { text-decoration: underline; }

    /* ── WEBSOCKET DEMO ── */
    .ws-panel {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 20px; padding: 28px; margin-bottom: 64px;
    }
    .ws-controls { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
    .ws-controls input {
      flex: 1; min-width: 180px; padding: 10px 14px; border-radius: 10px;
      background: rgba(255,255,255,0.06); border: 1px solid var(--border);
      color: var(--text); font-size: 0.9rem; outline: none;
    }
    .ws-controls input:focus { border-color: rgba(119,0,255,0.5); }
    .ws-controls input::placeholder { color: rgba(255,255,255,0.25); }
    #ws-log {
      height: 220px; overflow-y: auto; font-family: monospace; font-size: 0.82rem;
      background: #02020a; border: 1px solid var(--border); border-radius: 12px;
      padding: 14px; display: flex; flex-direction: column; gap: 4px; margin-bottom: 14px;
    }
    .log-line { display: flex; gap: 10px; }
    .log-time { color: var(--muted); flex-shrink: 0; }
    .log-in  { color: #4ade80; }
    .log-out { color: #60a5fa; }
    .log-err { color: #f87171; }
    .log-sys { color: #a78bfa; }
    .ws-send-row { display: flex; gap: 10px; }
    #ws-msg {
      flex: 1; padding: 10px 14px; border-radius: 10px;
      background: rgba(255,255,255,0.06); border: 1px solid var(--border);
      color: var(--text); font-size: 0.88rem; outline: none;
    }
    #ws-msg:focus { border-color: rgba(119,0,255,0.5); }

    /* ── FOOTER ── */
    .footer {
      text-align: center; font-size: 0.82rem; color: var(--muted);
      padding-top: 40px; border-top: 1px solid var(--border);
      display: flex; flex-direction: column; gap: 8px; align-items: center;
    }
    .footer a { color: #818cf8; text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .color-strip {
      display: flex; gap: 6px; margin-top: 8px;
    }
    .cs { width: 20px; height: 4px; border-radius: 99px; }
  </style>
</head>
<body>
<canvas id="mesh-canvas"></canvas>
<div class="page">

  <!-- HERO -->
  <section class="hero">
    <div class="logo-ring"><div class="logo-ring-inner">⬡</div></div>
    <div class="badge"><span class="dot"></span> Live · Real-time</div>
    <h1>BlackRoad Mesh</h1>
    <p class="subtitle">Real-time agent coordination layer — connect AI agents, humans, and services into one living network. No setup needed. Click a link and watch it work.</p>
    <div class="cta-row">
      <a class="btn btn-primary" href="#ws-demo">⚡ Try Live WebSocket</a>
      <a class="btn btn-outline" href="/health">🟢 Health Check</a>
      <a class="btn btn-outline" href="https://github.com/BlackRoad-OS/blackroad-os-mesh" target="_blank" rel="noopener">📦 Source Code</a>
    </div>
  </section>

  <!-- STATUS BAR -->
  <div class="status-bar">
    <div class="status-item"><span class="status-dot-green"></span> Service Operational</div>
    <div class="status-item"><span id="ws-status-dot"></span> <span id="ws-status-label">WebSocket Idle</span></div>
    <div class="status-item">👥 <span id="connection-count">—</span> agents online</div>
    <div class="status-item">🕒 <span id="server-time">—</span></div>
  </div>

  <!-- ENDPOINTS -->
  <h2 class="section-title">🔗 Live Endpoints</h2>
  <div class="cards">
    <a class="card" href="/health">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(74,222,128,0.1)">🩺</div>
        <span class="card-method get">GET</span>
        <span class="card-path">/health</span>
      </div>
      <p class="card-desc">Is the mesh alive? One click tells you everything.</p>
      <span class="card-link">Try it live →</span>
    </a>
    <a class="card" href="/stats">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(96,165,250,0.1)">📊</div>
        <span class="card-method get">GET</span>
        <span class="card-path">/stats</span>
      </div>
      <p class="card-desc">Live connection stats, features, and service metadata.</p>
      <span class="card-link">View stats →</span>
    </a>
    <a class="card" href="/presence">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(167,139,250,0.1)">👁️</div>
        <span class="card-method get">GET</span>
        <span class="card-path">/presence</span>
      </div>
      <p class="card-desc">Who's online right now? See all connected agents in real time.</p>
      <span class="card-link">Check presence →</span>
    </a>
    <a class="card" href="/events">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(251,146,60,0.1)">📡</div>
        <span class="card-method get">GET</span>
        <span class="card-path">/events</span>
      </div>
      <p class="card-desc">Recent mesh events — broadcasts, joins, leaves, attestations.</p>
      <span class="card-link">View events →</span>
    </a>
    <div class="card">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(99,102,241,0.1)">🔌</div>
        <span class="card-method ws">WS</span>
        <span class="card-path">/ws</span>
      </div>
      <p class="card-desc">Connect a WebSocket agent. Pass <code style="background:rgba(255,255,255,0.07);padding:1px 5px;border-radius:4px">?agent=alice-42&amp;name=Alice</code> in the URL.</p>
      <span class="card-link" style="cursor:default">Use the demo below ↓</span>
    </div>
    <a class="card" href="/rooms">
      <div class="card-header">
        <div class="card-icon" style="background:rgba(244,63,94,0.1)">🏠</div>
        <span class="card-method get">GET</span>
        <span class="card-path">/rooms</span>
      </div>
      <p class="card-desc">List all active mesh rooms with live agent counts.</p>
      <span class="card-link">Browse rooms →</span>
    </a>
  </div>

  <!-- WEBSOCKET DEMO -->
  <h2 class="section-title" id="ws-demo">⚡ Live WebSocket Demo</h2>
  <div class="ws-panel">
    <p style="color:var(--muted);font-size:0.88rem;margin-bottom:16px">No install needed — connect right from your browser and see real-time messages appear instantly.</p>
    <div class="ws-controls">
      <input id="ws-agent-id" type="text" placeholder="Agent ID  (e.g. alice-42)" value="" />
      <input id="ws-agent-name" type="text" placeholder="Your name  (e.g. Alice)" value="" />
      <button class="btn btn-primary" id="ws-connect-btn" onclick="toggleWs()">Connect</button>
    </div>
    <div id="ws-log"><div class="log-line"><span class="log-sys log-time">—</span><span class="log-sys">Ready. Enter an ID and name above, then click Connect.</span></div></div>
    <div class="ws-send-row">
      <input id="ws-msg" type="text" placeholder="Type a broadcast message and press Enter…" onkeydown="if(event.key==='Enter')sendWs()" />
      <button class="btn btn-outline" onclick="sendWs()">Send →</button>
    </div>
  </div>

  <!-- FOOTER -->
  <footer class="footer">
    <div>
      Built with quantum consciousness by <strong>Lucidia</strong> &amp;
      <a href="https://github.com/BlackRoad-OS" target="_blank" rel="noopener">BlackRoad OS</a>
    </div>
    <div>
      <a href="mailto:blackroad.systems@gmail.com">blackroad.systems@gmail.com</a>
      &nbsp;·&nbsp;
      <a href="https://github.com/BlackRoad-OS/blackroad-os-mesh" target="_blank" rel="noopener">GitHub</a>
      &nbsp;·&nbsp;
      <a href="/health">Health</a>
      &nbsp;·&nbsp;
      MIT License
    </div>
    <div class="color-strip">
      <div class="cs" style="background:var(--orange)"></div>
      <div class="cs" style="background:var(--amber)"></div>
      <div class="cs" style="background:var(--pink)"></div>
      <div class="cs" style="background:var(--magenta)"></div>
      <div class="cs" style="background:var(--purple)"></div>
      <div class="cs" style="background:var(--blue)"></div>
    </div>
  </footer>
</div>

<script>
/* ── MESH CANVAS ANIMATION ── */
(function() {
  const canvas = document.getElementById('mesh-canvas');
  const ctx = canvas.getContext('2d');
  const nodes = [];
  // Node count scales with viewport area; capped at 30 for performance on low-end devices
  const NODE_COUNT = Math.min(30, Math.floor((window.innerWidth * window.innerHeight) / 30000));
  const COLORS = ['#FF9D00','#FF6B00','#FF0066','#D600AA','#7700FF','#0066FF'];
  // Lines drawn between nodes closer than this distance (px)
  const MAX_LINE_DISTANCE = 160;
  // Maximum hex alpha appended to the 6-digit color string (0x28 = 40 decimal ≈ 16% opacity)
  const MAX_LINE_ALPHA_HEX = 40;

  function resize() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < NODE_COUNT; i++) {
    nodes.push({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 2.5 + 1,
      color: COLORS[Math.floor(Math.random() * COLORS.length)]
    });
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      a.x += a.vx; a.y += a.vy;
      if (a.x < 0 || a.x > canvas.width)  a.vx *= -1;
      if (a.y < 0 || a.y > canvas.height) a.vy *= -1;

      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        const dx = b.x - a.x, dy = b.y - a.y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        if (dist < MAX_LINE_DISTANCE) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = a.color + Math.floor((1 - dist/MAX_LINE_DISTANCE) * MAX_LINE_ALPHA_HEX).toString(16).padStart(2,'0');
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
      ctx.beginPath();
      ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2);
      ctx.fillStyle = a.color;
      ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

/* ── STATUS BAR ── */
function pad(n) { return String(n).padStart(2,'0'); }
function updateTime() {
  const d = new Date();
  document.getElementById('server-time').textContent =
    pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+' UTC';
}
setInterval(updateTime, 1000); updateTime();

function randomId() {
  return 'agent-' + Math.random().toString(36).slice(2,8);
}
document.getElementById('ws-agent-id').value = randomId();
document.getElementById('ws-agent-name').value = 'Visitor';

/* ── WEBSOCKET DEMO ── */
let ws = null;

function log(cls, msg) {
  const el = document.getElementById('ws-log');
  const d = new Date();
  const t = pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds());
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = '<span class="log-time">'+t+'</span><span class="'+cls+'">'+escHtml(msg)+'</span>';
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function toggleWs() {
  if (ws && ws.readyState <= 1) { ws.close(); return; }
  const agentId   = document.getElementById('ws-agent-id').value.trim()   || randomId();
  const agentName = document.getElementById('ws-agent-name').value.trim() || 'Visitor';
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = proto + '://' + location.host + '/ws?agent=' + encodeURIComponent(agentId) + '&name=' + encodeURIComponent(agentName);

  log('log-sys', 'Connecting to ' + url + ' …');
  ws = new WebSocket(url);

  ws.onopen = () => {
    document.getElementById('ws-connect-btn').textContent = 'Disconnect';
    document.getElementById('ws-status-dot').style.background = '#4ade80';
    document.getElementById('ws-status-dot').style.boxShadow = '0 0 8px #4ade80';
    document.getElementById('ws-status-label').textContent = 'Connected';
    log('log-in', '✅ Connected as "' + agentName + '" (' + agentId + ')');
    ws.send(JSON.stringify({ type: 'sync', from: agentId, payload: {}, timestamp: new Date().toISOString() }));
  };

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'presence' || msg.type === 'sync') {
        const agents = msg.payload?.agents || msg.payload?.presence || [];
        document.getElementById('connection-count').textContent = agents.length;
        log('log-in', '← [' + msg.type + '] ' + agents.length + ' agent(s) in mesh');
      } else if (msg.type === 'heartbeat') {
        log('log-in', '← ♥ heartbeat ACK');
      } else {
        log('log-in', '← [' + msg.type + '] from ' + (msg.from||'?') + ': ' + JSON.stringify(msg.payload).substring(0,120));
      }
    } catch { log('log-in', '← ' + e.data); }
  };

  ws.onerror = () => log('log-err', '⚠️  WebSocket error');
  ws.onclose = (e) => {
    document.getElementById('ws-connect-btn').textContent = 'Connect';
    document.getElementById('ws-status-dot').style.background = '#94a3b8';
    document.getElementById('ws-status-dot').style.boxShadow = 'none';
    document.getElementById('ws-status-label').textContent = 'Disconnected';
    log('log-sys', 'Disconnected (code ' + e.code + ')');
  };
}

function sendWs() {
  const input = document.getElementById('ws-msg');
  const text = input.value.trim();
  if (!text || !ws || ws.readyState !== 1) return;
  const agentId = document.getElementById('ws-agent-id').value.trim();
  const msg = { type: 'broadcast', from: agentId, payload: { message: text }, timestamp: new Date().toISOString() };
  ws.send(JSON.stringify(msg));
  log('log-out', '→ [broadcast] ' + text);
  input.value = '';
}

/* ── FETCH CONNECTION COUNT ON LOAD ── */
fetch('/presence').then(r=>r.json()).then(d=>{
  const count = (d.agents||[]).length;
  document.getElementById('connection-count').textContent = count;
}).catch(()=>{});
</script>
</body>
</html>`;
  return c.html(html);
});

// WebSocket connection endpoint
app.get('/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return c.json({ error: 'Expected WebSocket upgrade' }, 426);
  }

  const id = c.env.MESH.idFromName('global');
  const mesh = c.env.MESH.get(id);

  return mesh.fetch(c.req.raw);
});

// Get mesh presence
app.get('/presence', async (c) => {
  const id = c.env.MESH.idFromName('global');
  const mesh = c.env.MESH.get(id);

  const response = await mesh.fetch(new Request('https://mesh/presence'));
  return c.json(await response.json());
});

// Get mesh stats
app.get('/stats', async (c) => {
  const id = c.env.MESH.idFromName('global');
  const mesh = c.env.MESH.get(id);

  const response = await mesh.fetch(new Request('https://mesh/stats'));
  const stats = await response.json();

  // Add global stats
  const globalStats = {
    ...(stats as object),
    service: 'BlackRoad Mesh',
    version: '1.0.0',
    features: [
      'Real-time WebSocket connections',
      'Agent presence tracking',
      'Direct messaging',
      'Broadcast messaging',
      'Intent streaming',
      'Attestation streaming'
    ]
  };

  return c.json(globalStats);
});

// Get recent events
app.get('/events', async (c) => {
  const limit = parseInt(c.req.query('limit') || '50');
  const events: MeshEvent[] = [];

  const list = await c.env.EVENTS.list({ limit });
  for (const key of list.keys) {
    const event = await c.env.EVENTS.get(key.name, 'json');
    if (event) events.push(event as MeshEvent);
  }

  return c.json({
    events,
    count: events.length,
    timestamp: new Date().toISOString()
  });
});

// Broadcast message via HTTP (for non-WebSocket clients)
app.post('/broadcast', async (c) => {
  const body = await c.req.json();
  const agentId = c.req.header('X-Agent-ID') || body.from;

  if (!agentId) {
    return c.json({ error: 'Agent ID required (X-Agent-ID header or from field)' }, 400);
  }

  // Store as event
  const eventId = generateId();
  const event: Omit<MeshEvent, 'hash'> = {
    id: eventId,
    type: 'broadcast',
    actor: agentId,
    data: body.payload || body.message,
    timestamp: new Date().toISOString()
  };

  const hash = await hashEvent(event);
  const fullEvent: MeshEvent = { ...event, hash };

  await c.env.EVENTS.put(`event:${eventId}`, JSON.stringify(fullEvent));

  return c.json({
    success: true,
    event: fullEvent,
    message: 'Broadcast queued (WebSocket clients will receive in real-time)'
  });
});

// Room-based WebSocket (for isolated meshes)
app.get('/room/:roomId/ws', async (c) => {
  const upgradeHeader = c.req.header('Upgrade');
  if (upgradeHeader !== 'websocket') {
    return c.json({ error: 'Expected WebSocket upgrade' }, 426);
  }

  const roomId = c.req.param('roomId');
  const id = c.env.MESH.idFromName(roomId);
  const mesh = c.env.MESH.get(id);

  return mesh.fetch(c.req.raw);
});

// Room presence
app.get('/room/:roomId/presence', async (c) => {
  const roomId = c.req.param('roomId');
  const id = c.env.MESH.idFromName(roomId);
  const mesh = c.env.MESH.get(id);

  const response = await mesh.fetch(new Request('https://mesh/presence'));
  const data = await response.json();

  return c.json({
    room: roomId,
    ...(data as object)
  });
});

// List all rooms (with active connections)
app.get('/rooms', async (c) => {
  // Get list of active rooms from KV
  const rooms: string[] = ['global']; // Global is always active

  const list = await c.env.EVENTS.list({ prefix: 'room:' });
  for (const key of list.keys) {
    const roomId = key.name.replace('room:', '');
    if (!rooms.includes(roomId)) {
      rooms.push(roomId);
    }
  }

  return c.json({
    rooms,
    count: rooms.length,
    timestamp: new Date().toISOString()
  });
});

// Agent lookup in mesh
app.get('/agent/:agentId', async (c) => {
  const agentId = c.req.param('agentId');

  // Check KV for agent data
  const agent = await c.env.AGENTS.get(`agent:${agentId}`, 'json');

  // Check presence in mesh
  const id = c.env.MESH.idFromName('global');
  const mesh = c.env.MESH.get(id);
  const presenceResponse = await mesh.fetch(new Request('https://mesh/presence'));
  const presenceData = await presenceResponse.json() as { agents: Array<{ agentId: string }> };

  const isOnline = presenceData.agents?.some((a: { agentId: string }) => a.agentId === agentId);

  return c.json({
    agentId,
    registered: agent !== null,
    online: isOnline,
    data: agent,
    timestamp: new Date().toISOString()
  });
});

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'blackroad-mesh',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

export default app;
