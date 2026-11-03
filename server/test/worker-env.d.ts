// Minimal local check declarations; production typecheck uses @cloudflare/workers-types.
interface DurableObjectNamespace { idFromName(name: string): unknown; get(id: unknown): {fetch(request: Request): Promise<Response>}; }
interface DurableObjectStorage { get<T>(key: string): Promise<T | undefined>; put(key: string, value: unknown): Promise<void>; setAlarm(time: number): Promise<void>; deleteAlarm(): Promise<void>; }
interface DurableObjectState { storage: DurableObjectStorage; blockConcurrencyWhile<T>(f: () => Promise<T>): Promise<T>; getWebSockets(): WebSocket[]; acceptWebSocket(ws: WebSocket): void; }
interface WebSocket { serializeAttachment(value: unknown): void; deserializeAttachment(): unknown; }
interface ResponseInit { webSocket?: WebSocket; }
declare class WebSocketPair { 0: WebSocket; 1: WebSocket; }
