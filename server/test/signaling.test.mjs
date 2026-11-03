import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignalingHub } from '../src/index.ts';
const b64 = b => Buffer.from(b).toString('base64url');
async function setup(env = {}) {
 const db = new Map(), sockets = [];
 const storage={get: async k => db.get(k),put: async (k,v) => db.set(k,structuredClone(v)),delete: async k => db.delete(k),list: async ({prefix,limit}) => new Map([...db].filter(([k])=>k.startsWith(prefix)).slice(0,limit)),setAlarm: async v => db.set('alarm',v),deleteAlarm: async () => db.delete('alarm')};
 let ready; const state={storage,getWebSockets:()=>sockets,blockConcurrencyWhile:f=>{ready=f()}};
 const hub = new SignalingHub(state, env); await ready;
 function peer() { const socket = {messages:[],send(m){this.messages.push(JSON.parse(m))},close(){},serializeAttachment(a){this.attachment=structuredClone(a)},deserializeAttachment(){return this.attachment}}; sockets.push(socket); const p={socket,nonce:crypto.randomUUID(),deadline:Date.now()+60000,used:false,count:0,window:Date.now()}; hub.peers.set(socket,p); return p; }
 return {hub, peer, db, state, sockets};
}
async function register(hub,p) {
 const keys=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']);
 const pub=await crypto.subtle.exportKey('raw',keys.publicKey);
 const signature=await crypto.subtle.sign('Ed25519',keys.privateKey,new TextEncoder().encode('remote-signaling-v1:'+p.nonce));
 await hub.message(p,JSON.stringify({type:'register',publicKey:b64(pub),signature:b64(signature)})); return keys;
}
const msg=(hub,p,m)=>hub.message(p,JSON.stringify(m));
test('signed registration and connection-bound one-use challenge', async()=>{
 const {hub,peer}=await setup(), p=peer(); await register(hub,p); assert.match(p.id,/^\d{12}$/);
 const bad=peer(); await assert.rejects(msg(hub,bad,{type:'authenticate',deviceId:p.id,signature:b64(new Uint8Array(64))}));
 await assert.rejects(msg(hub,bad,{type:'authenticate',deviceId:p.id,signature:b64(new Uint8Array(64))}));
});
test('only target accepts, full requires confirmation, relay limited to accepted participants',async()=>{
 const {hub,peer}=await setup(), a=peer(), b=peer(), c=peer(); await register(hub,a); await register(hub,b); await register(hub,c);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId;
 await assert.rejects(msg(hub,a,{type:'signal',sessionId,kind:'offer',data:{sdp:'x'}}));
 await assert.rejects(msg(hub,a,{type:'accept',sessionId,preset:'basic'}));
 await assert.rejects(msg(hub,b,{type:'accept',sessionId,preset:'full'}));
 await msg(hub,b,{type:'accept',sessionId,preset:'full',confirmed:true});
 await assert.rejects(msg(hub,c,{type:'signal',sessionId,kind:'offer',data:{sdp:'x'}}));
 await msg(hub,a,{type:'signal',sessionId,kind:'offer',data:{sdp:'x'}}); assert.equal(b.socket.messages.at(-1).type,'signal');
 await msg(hub,b,{type:'end',sessionId}); await assert.rejects(msg(hub,a,{type:'signal',sessionId,kind:'ice',data:{}}));
});
test('expiry and disconnect invalidate sessions',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); let sessionId=a.socket.messages.at(-1).sessionId;
 hub.sessions.get(sessionId).expires=Date.now()-1; await assert.rejects(msg(hub,b,{type:'accept',sessionId,preset:'basic'}));
 await msg(hub,a,{type:'request',targetId:b.id}); sessionId=a.socket.messages.at(-1).sessionId; hub.disconnect(b); assert.equal(hub.sessions.has(sessionId),false);
});

async function signature(keys, nonce) { return b64(await crypto.subtle.sign('Ed25519',keys.privateKey,new TextEncoder().encode('remote-signaling-v1:'+nonce))); }
test('reauthentication uses fresh challenge and reconnect revokes old session',async()=>{
 const {hub,peer}=await setup(), a=peer(),b=peer(); const keys=await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId;
 const c=peer(); await assert.rejects(msg(hub,c,{type:'authenticate',deviceId:a.id,signature:await signature(keys,a.nonce)}));
 const d=peer(); await msg(hub,d,{type:'authenticate',deviceId:a.id,signature:await signature(keys,d.nonce)});
 assert.equal(d.id,a.id); assert.equal(hub.sessions.has(sessionId),false); assert.equal(b.socket.messages.at(-1).type,'ended');
});
test('invalid frames and unauthenticated or unrelated operations fail closed',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(),c=peer(),guest=peer(); await register(hub,a); await register(hub,b); await register(hub,c);
 for (const raw of [null,'null','[]','{}','{"type":"presence","deviceId":null}', 'x'.repeat(65537)]) await assert.rejects(hub.message(a,raw));
 await assert.rejects(msg(hub,guest,{type:'presence',deviceId:a.id}));
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId;
 await assert.rejects(msg(hub,c,{type:'turn',sessionId})); await assert.rejects(msg(hub,a,{type:'turn',sessionId}));
 await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 await assert.rejects(msg(hub,c,{type:'turn',sessionId})); await assert.rejects(msg(hub,a,{type:'signal',sessionId,kind:'bogus',data:{}}));
});
test('hibernation restores sockets and sessions; alarm ends expired session',async()=>{
 const {hub,peer,state,db}=await setup(),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId;
 await msg(hub,b,{type:'accept',sessionId,preset:'basic'}); await hub.save();
 let ready; state.blockConcurrencyWhile=f=>{ready=f()}; const revived=new SignalingHub(state,{}); await ready;
 assert.equal(revived.online.size,2); assert.equal(revived.sessions.has(sessionId),true);
 revived.sessions.get(sessionId).expires=Date.now()-1; await revived.alarm();
 assert.equal(revived.sessions.size,0); assert.equal(a.socket.messages.at(-1).type,'ended'); assert.equal(db.has('alarm'),false);
});
test('TURN requires secrets and budget, enforces cap and sends bounded TTL without leaking secret',async()=>{
 const {hub,peer,db}=await setup({TURN_KEY_ID:'key',TURN_KEY_API_TOKEN:'secret',TURN_DAILY_BUDGET:'1'}),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 const orig=globalThis.fetch; let seen; globalThis.fetch=async (url,opts)=>{seen={url,opts}; return new Response(JSON.stringify({iceServers:[{urls:['stun:example']}]}),{status:201})};
 try { await msg(hub,a,{type:'turn',sessionId}); assert.equal(JSON.parse(seen.opts.body).ttl,3600); assert.equal(seen.opts.headers.Authorization,'Bearer secret'); assert.equal(a.socket.messages.at(-1).type,'turn'); assert.ok(!JSON.stringify(a.socket.messages).includes('secret')); await assert.rejects(msg(hub,b,{type:'turn',sessionId})); assert.equal(db.get('turn-budget').count,1); } finally { globalThis.fetch=orig; }
});
test('TURN failure consumes reservation and missing secrets fail closed',async()=>{
 const {hub,peer}=await setup({TURN_KEY_ID:'key',TURN_KEY_API_TOKEN:'secret',TURN_DAILY_BUDGET:'3'}),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'normal'});
 const orig=globalThis.fetch; globalThis.fetch=async()=>new Response('',{status:500});
 try { await assert.rejects(msg(hub,a,{type:'turn',sessionId})); await assert.rejects(msg(hub,a,{type:'turn',sessionId})); await assert.rejects(msg(hub,a,{type:'turn',sessionId})); assert.equal(hub.sessions.get(sessionId).turnCounts.controller,2); hub.env.TURN_KEY_API_TOKEN=''; await assert.rejects(msg(hub,a,{type:'turn',sessionId})); } finally { globalThis.fetch=orig; }
});
test('websocket handler reports malformed messages and alarm closes unauthenticated sockets',async()=>{
 const {hub,peer}=await setup(), p=peer(); await hub.webSocketMessage(p.socket,'not json'); assert.deepEqual(p.socket.messages.at(-1),{type:'error',code:'invalid'});
 p.deadline=Date.now()-1; let closed=false; p.socket.close=()=>{closed=true}; await hub.alarm(); assert.equal(closed,true); assert.equal(hub.peers.has(p.socket),false);
});
test('persisted per-connection message limit survives hibernation',async()=>{
 const {hub,peer,state}=await setup(), p=peer(); await register(hub,p); p.count=120; await hub.save(); let ready; state.blockConcurrencyWhile=f=>{ready=f()}; const revived=new SignalingHub(state,{}); await ready;
 let closed=false; p.socket.close=()=>{closed=true}; await revived.webSocketMessage(p.socket,JSON.stringify({type:'presence',deviceId:p.id})); assert.equal(closed,true); assert.equal(p.socket.messages.at(-1).code,'rate_limited');
});

test('only one pending or accepted session per device',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(),c=peer(),d=peer(); for(const p of [a,b,c,d]) await register(hub,p);
 await msg(hub,a,{type:'request',targetId:b.id}); const sid=a.socket.messages.at(-1).sessionId;
 await assert.rejects(msg(hub,c,{type:'request',targetId:b.id}));
 await assert.rejects(msg(hub,a,{type:'request',targetId:c.id}));
 await assert.rejects(msg(hub,b,{type:'request',targetId:c.id}));
 await msg(hub,b,{type:'accept',sessionId:sid,preset:'basic'});
 await assert.rejects(msg(hub,a,{type:'request',targetId:d.id}));
 await assert.rejects(msg(hub,c,{type:'request',targetId:b.id}));
 await msg(hub,a,{type:'end',sessionId:sid}); await msg(hub,c,{type:'request',targetId:b.id});
});
test('only controller offers and only target answers; either can relay ICE',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 const signal=(p,kind)=>msg(hub,p,{type:'signal',sessionId,kind,data:{sdp:'x'}});
 await assert.rejects(signal(b,'offer')); await assert.rejects(signal(a,'answer'));
 await signal(a,'offer'); await signal(b,'answer'); await signal(a,'ice'); await signal(b,'ice');
});
test('TURN attempts are capped independently for each participant',async()=>{
 const {hub,peer}=await setup({TURN_KEY_ID:'key',TURN_KEY_API_TOKEN:'secret',TURN_DAILY_BUDGET:'10'}),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 const orig=globalThis.fetch; globalThis.fetch=async()=>new Response(JSON.stringify({iceServers:[]}),{status:201});
 try { await msg(hub,a,{type:'turn',sessionId}); await msg(hub,a,{type:'turn',sessionId}); await assert.rejects(msg(hub,a,{type:'turn',sessionId})); await msg(hub,b,{type:'turn',sessionId}); assert.equal(b.socket.messages.at(-1).type,'turn'); assert.deepEqual(hub.sessions.get(sessionId).turnCounts,{controller:2,target:1}); } finally { globalThis.fetch=orig; }
});
test('TURN upstream aborts at the deadline and releases the event queue',async()=>{
 const {hub,peer}=await setup({TURN_KEY_ID:'key',TURN_KEY_API_TOKEN:'secret',TURN_DAILY_BUDGET:'10'}),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 const orig=globalThis.fetch; globalThis.fetch=async (_url,opts)=>new Promise((_,reject)=>opts.signal.addEventListener('abort',()=>reject(new Error('aborted')),{once:true}));
 try { const start=Date.now(); await hub.webSocketMessage(a.socket,JSON.stringify({type:'turn',sessionId})); assert.ok(Date.now()-start<7000); assert.equal(a.socket.messages.at(-1).type,'error'); await hub.webSocketMessage(b.socket,JSON.stringify({type:'end',sessionId})); assert.equal(hub.sessions.size,0); } finally { globalThis.fetch=orig; }
});

test('accepted session survives drop; same identity resumes; expires after grace',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(); const keys=await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 hub.disconnect(a); assert.equal(b.socket.messages.at(-1).type,'peer_down'); assert.ok(hub.sessions.has(sessionId));
 const c=peer(); await assert.rejects(msg(hub,c,{type:'authenticate',deviceId:a.id,signature:b64(new Uint8Array(64))}));
 const d=peer(); await msg(hub,d,{type:'authenticate',deviceId:a.id,signature:await signature(keys,d.nonce)});
 const e=peer(); await register(hub,e); await assert.rejects(msg(hub,e,{type:'resume',sessionId}));
 await msg(hub,d,{type:'resume',sessionId}); assert.equal(d.socket.messages.at(-1).type,'resumed'); assert.equal(b.socket.messages.at(-1).type,'peer_resumed');
 await assert.rejects(msg(hub,d,{type:'resume',sessionId}));
 hub.disconnect(d); hub.sessions.get(sessionId).resumeBy[a.id]=Date.now()-1; await hub.alarm(); assert.equal(hub.sessions.size,0); assert.equal(b.socket.messages.at(-1).type,'ended');
});
test('pending session ends on drop; no resume',async()=>{
 const {hub,peer}=await setup(),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); hub.disconnect(a); assert.equal(hub.sessions.size,0);
});
test('revoked controller is refused, target notified, revoke persists and ends session',async()=>{
 const {hub,peer,db}=await setup(),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const sessionId=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId,preset:'basic'});
 await msg(hub,b,{type:'revoke',controllerId:a.id}); assert.deepEqual(b.socket.messages.at(-1),{type:'revoked',controllerId:a.id}); assert.equal(hub.sessions.size,0); assert.ok(db.get(`revoked:${b.id}:${a.id}`));
 await assert.rejects(msg(hub,a,{type:'request',targetId:b.id})); assert.deepEqual(b.socket.messages.at(-1),{type:'revoked_attempt',controllerId:a.id});
 await msg(hub,b,{type:'request',targetId:a.id}); // direction is independent
});

test('incoming carries registered controller key; unrevoke restores; revoke list capped at 1000',async()=>{
 const {hub,peer,db}=await setup(),a=peer(),b=peer(); const keys=await register(hub,a); await register(hub,b);
 await msg(hub,a,{type:'request',targetId:b.id}); const inc=b.socket.messages.at(-1);
 assert.equal(inc.controllerPublicKey,db.get(`device:${a.id}`)); assert.equal(inc.controllerPublicKey,b64(await crypto.subtle.exportKey('raw',keys.publicKey)));
 await msg(hub,b,{type:'end',sessionId:inc.sessionId});
 await msg(hub,b,{type:'revoke',controllerId:a.id}); await assert.rejects(msg(hub,a,{type:'request',targetId:b.id}));
 await msg(hub,b,{type:'unrevoke',controllerId:a.id}); assert.deepEqual(b.socket.messages.at(-1),{type:'unrevoked',controllerId:a.id}); assert.equal(db.has(`revoked:${b.id}:${a.id}`),false);
 await msg(hub,a,{type:'request',targetId:b.id});
 for(let i=0;i<1000;i++) db.set(`revoked:${b.id}:${'1'+String(i).padStart(11,'0')}`,true);
 await assert.rejects(msg(hub,b,{type:'revoke',controllerId:a.id})); await msg(hub,b,{type:'revoke',controllerId:'100000000001'});
});

test('TURN capped at 20/h per requester id by role; stale keys swept by alarm',async()=>{
 const {hub,peer,db}=await setup({TURN_KEY_ID:'key',TURN_KEY_API_TOKEN:'secret',TURN_DAILY_BUDGET:'1000'}),a=peer(),b=peer(); await register(hub,a); await register(hub,b);
 const orig=globalThis.fetch; globalThis.fetch=async()=>new Response(JSON.stringify({iceServers:[]}),{status:201});
 try {
  for(let i=0;i<10;i++){ await msg(hub,a,{type:'request',targetId:b.id}); const sid=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId:sid,preset:'basic'});
   await msg(hub,a,{type:'turn',sessionId:sid}); await msg(hub,a,{type:'turn',sessionId:sid}); await msg(hub,b,{type:'turn',sessionId:sid}); await msg(hub,a,{type:'end',sessionId:sid}); }
  assert.equal(db.get(`turn-ctrl:${a.id}`).length,20); assert.equal(db.get(`turn-target:${b.id}`).length,10);
  await msg(hub,a,{type:'request',targetId:b.id}); const sid=a.socket.messages.at(-1).sessionId; await msg(hub,b,{type:'accept',sessionId:sid,preset:'basic'});
  await assert.rejects(msg(hub,a,{type:'turn',sessionId:sid})); await msg(hub,b,{type:'turn',sessionId:sid});
  for(const k of [`turn-ctrl:${a.id}`,`turn-target:${b.id}`]) db.set(k,db.get(k).map(t=>t-3600001));
  await hub.alarm(); assert.equal(db.has(`turn-ctrl:${a.id}`),false); assert.equal(db.has(`turn-target:${b.id}`),false); assert.ok(db.has('turn-budget'));
 } finally { globalThis.fetch=orig; }
});
