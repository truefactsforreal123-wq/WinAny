interface Env { HUB: DurableObjectNamespace; TURN_KEY_ID?: string; TURN_KEY_API_TOKEN?: string; TURN_DAILY_BUDGET?: string }
type Peer = { socket: WebSocket; nonce: string; deadline: number; id?: string; used: boolean; count: number; window: number };
type Session = { id: string; controller: string; target: string; state: "pending" | "accepted"; preset?: string; resumeBy?: Record<string, number>; expires: number; turnCounts?: { controller: number; target: number } };
const encoder = new TextEncoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const random = (size: number) => b64(crypto.getRandomValues(new Uint8Array(size)));
function decode(value: unknown, length: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error("invalid");
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4));
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (bytes.length !== length || b64(bytes) !== value) throw Error("invalid");
  return bytes;
}
const validId = (v: unknown): v is string => typeof v === "string" && /^\d{12}$/.test(v);
function send(socket: WebSocket, value: unknown) { try { socket.send(JSON.stringify(value)); } catch { /* disconnected */ } }
export default { fetch(request: Request, env: Env): Promise<Response> | Response {
  const url = new URL(request.url);
  if (url.pathname !== "/v1/ws" || request.method !== "GET") return new Response("Not found", { status: 404 });
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("WebSocket required", { status: 426 });
  return env.HUB.get(env.HUB.idFromName("global-v1")).fetch(request);
} };
export class SignalingHub {
  private peers = new Map<WebSocket, Peer>();
  private online = new Map<string, Peer>();
  private sessions = new Map<string, Session>();
  private queue: Promise<void> = Promise.resolve();
  private state: DurableObjectState; private env: Env;
  constructor(state: DurableObjectState, env: Env) {
    this.state = state; this.env = env;
    state.blockConcurrencyWhile(async () => {
      const saved = await state.storage.get<Session[]>("sessions") || [];
      for (const session of saved) this.sessions.set(session.id, session);
      for (const socket of state.getWebSockets()) {
        const attachment = socket.deserializeAttachment() as Omit<Peer, "socket"> | null;
        if (!attachment) { socket.close(1008, "missing state"); continue; }
        const peer = { ...attachment, socket }; this.peers.set(socket, peer);
        if (peer.id) this.online.set(peer.id, peer);
      }
      for (const session of this.sessions.values()) if ([session.controller, session.target].some(d => !this.online.has(d) && !session.resumeBy?.[d])) this.finish(session, "ended");
      await this.save();
    });
  }
  private async save() {
    for (const peer of this.peers.values()) { const { socket, ...attachment } = peer; socket.serializeAttachment(attachment); }
    await this.state.storage.put("sessions", [...this.sessions.values()]);
    const deadlines = [...this.sessions.values()].flatMap(s => [s.expires, ...Object.values(s.resumeBy || {})]).concat([...this.peers.values()].filter(p => !p.id).map(p => p.deadline));
    if (deadlines.length) await this.state.storage.setAlarm(Math.min(...deadlines)); else await this.state.storage.deleteAlarm();
  }
  private async run(action: () => Promise<void> | void) {
    this.queue = this.queue.catch(() => {}).then(async () => { try { await action(); } finally { await this.save(); } });
    await this.queue;
  }
  async alarm() { await this.run(async () => {
    const now = Date.now(); this.expire(now);
    for (const p of ["turn-ctrl:", "turn-target:"]) for (const [k, v] of await this.state.storage.list<number[]>({ prefix: p })) if (!v.some(t => t > now - 3600000)) await this.state.storage.delete(k);
    for (const peer of this.peers.values()) if (!peer.id && peer.deadline <= now) { this.disconnect(peer); peer.socket.close(1008, "authentication expired"); }
  }); }
  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    const peer = this.peers.get(socket); if (!peer) { socket.close(1008, "missing state"); return; }
    await this.run(async () => { if (this.peers.get(socket) !== peer) return; try { await this.message(peer, message); } catch { send(socket, { type: "error", code: "invalid" }); } });
  }
  async webSocketClose(socket: WebSocket) { const peer = this.peers.get(socket); if (peer) await this.run(() => this.disconnect(peer)); }
  async webSocketError(socket: WebSocket) { const peer = this.peers.get(socket); if (peer) await this.run(() => this.disconnect(peer)); }
  async fetch(request: Request): Promise<Response> {
    let response: Response | undefined;
    await this.run(async () => { response = await this.open(request); });
    return response!;
  }
  private async open(request: Request): Promise<Response> {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown", now = Date.now();
    // Fixed buckets bound storage growth; collisions intentionally share a limit.
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(ip)))[0];
    const key = `rate:${hash}`, minute = Math.floor(now / 60000);
    const previous = await this.state.storage.get<{ minute: number; count: number }>(key);
    const count = previous?.minute === minute ? previous.count + 1 : 1;
    await this.state.storage.put(key, { minute, count });
    if (count > 30) return new Response("Rate limited", { status: 429 });
    const pair = new WebSocketPair(), client = pair[0], socket = pair[1];
    this.state.acceptWebSocket(socket);
    const peer: Peer = { socket, nonce: random(32), deadline: now + 60000, used: false, count: 0, window: now };
    this.peers.set(socket, peer); await this.save(); send(socket, { type: "challenge", nonce: peer.nonce });
    return new Response(null, { status: 101, webSocket: client });
  }
  private async message(peer: Peer, raw: unknown) {
    const now = Date.now(); this.expire(now);
    if (now - peer.window >= 60000) { peer.window = now; peer.count = 0; }
    if (++peer.count > 120) { send(peer.socket, { type: "error", code: "rate_limited" }); peer.socket.close(1008, "rate limited"); return; }
    if (typeof raw !== "string" || encoder.encode(raw).length > 65536) throw Error("invalid");
    const m: any = JSON.parse(raw);
    if (!m || typeof m !== "object" || Array.isArray(m) || typeof m.type !== "string") throw Error("invalid");
    if (!peer.id) {
      if (peer.used || now > peer.deadline || (m.type !== "register" && m.type !== "authenticate")) throw Error("invalid");
      peer.used = true;
      let key: string | undefined;
      if (m.type === "register") { decode(m.publicKey, 32); key = m.publicKey; }
      else { if (!validId(m.deviceId)) throw Error("invalid"); key = await this.state.storage.get<string>(`device:${m.deviceId}`); }
      if (!key) throw Error("invalid");
      const publicKey = await crypto.subtle.importKey("raw", decode(key, 32), { name: "Ed25519" }, false, ["verify"]);
      if (!await crypto.subtle.verify("Ed25519", publicKey, decode(m.signature, 64), encoder.encode(`remote-signaling-v1:${peer.nonce}`))) throw Error("invalid");
      let id: string = m.deviceId;
      if (m.type === "register") {
        do { const n = crypto.getRandomValues(new Uint32Array(2)); id = (BigInt(n[0]) * 4294967296n + BigInt(n[1])).toString().padStart(20, "0").slice(-12); } while (await this.state.storage.get(`device:${id}`));
        await this.state.storage.put(`device:${id}`, key);
      }
      if (!this.peers.has(peer.socket)) return;
      const old = this.online.get(id); if (old) { this.disconnect(old); old.socket.close(1008, "replaced"); }
      peer.id = id; this.online.set(id, peer); send(peer.socket, { type: "authenticated", deviceId: id }); return;
    }
    const id = peer.id;
    if (m.type === "presence") {
      if (!validId(m.deviceId)) throw Error("invalid");
      send(peer.socket, { type: "presence", deviceId: m.deviceId, online: this.online.has(m.deviceId) }); return;
    }
    // Revoke (target -> server): {type:"revoke",controllerId} -> sender gets {type:"revoked",controllerId}; any session with that controller ends.
    //   Persisted per (target,controller) in DO storage. A later "request" from a revoked controller gets the generic {type:"error",code:"invalid"}
    //   (no leak) and the target gets {type:"revoked_attempt",controllerId}. Unrevoke is not supported in v1.
    if (m.type === "revoke") {
      if (!validId(m.controllerId) || m.controllerId === id) throw Error("invalid");
      const rk = `revoked:${id}:${m.controllerId}`;
      if (!await this.state.storage.get(rk) && (await this.state.storage.list({ prefix: `revoked:${id}:`, limit: 1000 })).size >= 1000) throw Error("invalid");
      await this.state.storage.put(rk, true);
      for (const s of this.sessions.values()) if (s.target === id && s.controller === m.controllerId) this.finish(s, "ended");
      send(peer.socket, { type: "revoked", controllerId: m.controllerId }); return;
    }
    // Unrevoke: {type:"unrevoke",controllerId} -> {type:"unrevoked",controllerId}. Max 1000 revoked keys per target, else error "invalid".
    if (m.type === "unrevoke") {
      if (!validId(m.controllerId)) throw Error("invalid");
      await this.state.storage.delete(`revoked:${id}:${m.controllerId}`);
      send(peer.socket, { type: "unrevoked", controllerId: m.controllerId }); return;
    }
    // Resume (after re-authenticating on a new socket): {type:"resume",sessionId} -> sender gets {type:"resumed",sessionId,preset,expiresAt},
    //   other peer gets {type:"peer_resumed",sessionId}. When a peer socket drops, the other gets {type:"peer_down",sessionId,resumeBy(ms)};
    //   an accepted session is kept 60s, then {type:"ended"}. Client must re-run WebRTC/ICE restart itself. Pending sessions end immediately.
    if (m.type === "request") {
      if (validId(m.targetId) && await this.state.storage.get(`revoked:${m.targetId}:${id}`)) { this.emit(m.targetId, { type: "revoked_attempt", controllerId: id }); throw Error("unavailable"); }
      if (!validId(m.targetId) || m.targetId === id || !this.online.has(m.targetId) || [...this.sessions.values()].some(s => s.controller === id || s.target === id || s.controller === m.targetId || s.target === m.targetId)) throw Error("unavailable");
      const session: Session = { id: random(18), controller: id, target: m.targetId, state: "pending", expires: now + 60000 };
      this.sessions.set(session.id, session); send(peer.socket, { type: "requested", sessionId: session.id });
      this.emit(session.target, { type: "incoming", sessionId: session.id, controllerId: id, controllerPublicKey: await this.state.storage.get<string>(`device:${id}`) }); return;
    }
    if (typeof m.sessionId !== "string") throw Error("invalid");
    const session = this.sessions.get(m.sessionId);
    if (!session || (session.controller !== id && session.target !== id)) throw Error("invalid");
    if (m.type === "resume") {
      if (!session.resumeBy?.[id]) throw Error("invalid");
      delete session.resumeBy[id]; if (!Object.keys(session.resumeBy).length) delete session.resumeBy;
      send(peer.socket, { type: "resumed", sessionId: session.id, preset: session.preset, expiresAt: session.expires });
      this.emit(id === session.controller ? session.target : session.controller, { type: "peer_resumed", sessionId: session.id }); return;
    }
    if (m.type === "accept" || m.type === "deny") {
      if (session.target !== id || session.state !== "pending") throw Error("invalid");
      if (m.type === "deny") { this.finish(session, "denied"); return; }
      if (!["basic", "normal", "full"].includes(m.preset) || (m.preset === "full" && m.confirmed !== true)) throw Error("invalid");
      session.state = "accepted"; session.preset = m.preset; session.expires = now + 3600000;
      this.broadcast(session, { type: "accepted", sessionId: session.id, preset: m.preset, expiresAt: session.expires }); return;
    }
    if (m.type === "end") { this.finish(session, "ended"); return; }
    if (session.state !== "accepted") throw Error("invalid");
    if (m.type === "signal") {
      if (!["offer", "answer", "ice"].includes(m.kind) || (m.kind === "offer" && id !== session.controller) || (m.kind === "answer" && id !== session.target) || !m.data || typeof m.data !== "object" || Array.isArray(m.data)) throw Error("invalid");
      this.emit(id === session.controller ? session.target : session.controller, { type: "signal", sessionId: session.id, kind: m.kind, data: m.data }); return;
    }
    if (m.type === "turn") {
      if (!this.env.TURN_KEY_ID || !this.env.TURN_KEY_API_TOKEN) throw Error("turn_unavailable");
      const budget = Number(this.env.TURN_DAILY_BUDGET || 0);
      const role = id === session.controller ? "controller" : "target";
      if (!Number.isSafeInteger(budget) || budget <= 0 || (session.turnCounts?.[role] || 0) >= 2) throw Error("turn_unavailable");
      const day = Math.floor(now / 86400000);
      const used = await this.state.storage.get<{day: number; count: number}>("turn-budget");
      const count = used?.day === day ? used.count : 0;
      if (count >= budget) throw Error("turn_unavailable");
      // Rolling-hour cap of 20 issuances per requester: own id as controller, own id as target (timestamps persisted; stale keys swept in alarm).
      const tk = `${role === "controller" ? "turn-ctrl" : "turn-target"}:${id}`, hits = ((await this.state.storage.get<number[]>(tk)) || []).filter(t => t > now - 3600000);
      if (hits.length >= 20) throw Error("turn_unavailable");
      await this.state.storage.put(tk, [...hits, now]);
      session.turnCounts ||= { controller: 0, target: 0 };
      session.turnCounts[role]++;
      await this.state.storage.put("turn-budget", {day, count: count + 1});
      await this.save();
      const response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(this.env.TURN_KEY_ID)}/credentials/generate-ice-servers`, { method: "POST", headers: { Authorization: `Bearer ${this.env.TURN_KEY_API_TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify({ ttl: 3600 }), signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw Error("turn_unavailable");
      const result: any = await response.json(); if (!Array.isArray(result.iceServers)) throw Error("turn_unavailable");
      if (this.sessions.get(session.id) === session && session.expires > Date.now()) send(peer.socket, { type: "turn", sessionId: session.id, iceServers: result.iceServers }); return;
    }
    throw Error("invalid");
  }
  private emit(id: string, message: unknown) { const peer = this.online.get(id); if (peer) send(peer.socket, message); }
  private broadcast(s: Session, message: unknown) { this.emit(s.controller, message); this.emit(s.target, message); }
  private finish(s: Session, type: string) { this.sessions.delete(s.id); this.broadcast(s, { type, sessionId: s.id }); }
  private expire(now: number) { for (const s of this.sessions.values()) if (s.expires <= now || Object.values(s.resumeBy || {}).some(t => t <= now)) this.finish(s, "ended"); }
  private disconnect(peer: Peer) {
    this.peers.delete(peer.socket);
    if (peer.id && this.online.get(peer.id) === peer) { for (const s of this.sessions.values()) if (s.controller === peer.id || s.target === peer.id) {
        if (s.state !== "accepted") { this.finish(s, "ended"); continue; }
        const until = Date.now() + 60000; (s.resumeBy ||= {})[peer.id] = until;
        this.emit(peer.id === s.controller ? s.target : s.controller, { type: "peer_down", sessionId: s.id, resumeBy: until });
      }
      this.online.delete(peer.id);
    }
  }
}
