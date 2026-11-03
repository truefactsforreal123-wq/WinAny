# Signaling protocol v1

Connect `GET /v1/ws` via WebSocket. JSON text messages only, max 65536 bytes. Binary is rejected. IDs are 12 decimal digits, public keys and signatures are unpadded base64url (raw Ed25519 public key 32 bytes, signature 64 bytes). Server sends `{type:"challenge",nonce}` immediately; sign UTF-8 `remote-signaling-v1:` followed by nonce. Within 60 seconds send `{type:"register",publicKey,signature}` for a new identity, or `{type:"authenticate",deviceId,signature}` for an existing identity. Server responds `{type:"authenticated",deviceId}`. Store the private key and returned ID locally. A challenge is one-use and connection-bound.

Authenticated messages:
- `{type:"request",targetId}` -> controller receives `{type:"requested",sessionId}`, target receives `{type:"incoming",sessionId,controllerId,controllerPublicKey}` (controllerPublicKey is the controller's registered Ed25519 key). Unavailable or busy targets return a generic error. Each device can participate in only one pending or accepted session.
- Target sends `{type:"accept",sessionId,preset:"basic"|"normal"|"full",confirmed:true}` or `{type:"deny",sessionId}`. `confirmed:true` is mandatory for full. Both receive `{type:"accepted",sessionId,preset,expiresAt}` or `{type:"denied",sessionId}`. The target must enforce permissions and perform its own real user confirmation; the server cannot verify a UI action.
- Either participant may send `{type:"signal",sessionId,kind:"offer"|"answer"|"ice",data}`; only accepted participants receive `{type:"signal",sessionId,kind,data}`. Only the controller may send an offer and only the target may send an answer; either may send ICE. `data` is an opaque JSON object.
- Either participant sends `{type:"end",sessionId}`; both receive `{type:"ended",sessionId}`. Pending requests expire after 60 seconds, accepted sessions after one hour; an alarm ends expired sessions and disconnect ends sessions. `expiresAt` is the accepted session deadline in Unix milliseconds. Clients must independently terminate the WebRTC connection by the deadline.
- `{type:"turn",sessionId}` returns `{type:"turn",sessionId,iceServers}` to an accepted participant; requires server-side Cloudflare TURN secrets and an enabled daily budget. Each participant has at most two issuance attempts per session. `{type:"presence",deviceId}` returns `{type:"presence",deviceId,online}` subject to rate limits.
- Revoke: target sends `{type:"revoke",controllerId}` -> `{type:"revoked",controllerId}` (ends live sessions with it; later requests from it fail generically and the target receives `{type:"revoked_attempt",controllerId}`). `{type:"unrevoke",controllerId}` -> `{type:"unrevoked",controllerId}`. Max 1000 revoked controllers per target, else `error invalid`.
- Resume: accepted sessions survive a socket drop for 60s. Peer gets `{type:"peer_down",sessionId,resumeBy}`; the dropped device re-authenticates and sends `{type:"resume",sessionId}` -> `{type:"resumed",sessionId,preset,expiresAt}`, peer gets `{type:"peer_resumed",sessionId}`.
- Errors: `{type:"error",code}`; no correlation IDs. Clients should serialize requests where correlation matters. Connections and session state are ephemeral; reconnect and request a new session after disconnect.

## Resume

- Client sends `{type:"resume",sessionId}` after re-authenticating on a new socket. Sender receives `{type:"resumed",sessionId,preset,expiresAt}`; the other participant receives `{type:"peer_resumed",sessionId}`.
- Only a participant that has a pending resume window may resume. Otherwise the server returns `{type:"error",code:"invalid"}`.
- When a participant's socket drops during an accepted session, the other participant receives `{type:"peer_down",sessionId,resumeBy}`. `resumeBy` is a Unix millisecond deadline (60 seconds after the drop).
- If the dropped participant does not resume by `resumeBy`, both participants receive `{type:"ended",sessionId}`. Pending sessions end immediately on disconnect with `{type:"ended",sessionId}`.
- Resuming does not restore WebRTC. The client must run ICE restart itself.

## Revoke

- Target sends `{type:"revoke",controllerId}`. The sender receives `{type:"revoked",controllerId}`. Any session between that controller and the target ends with `{type:"ended",sessionId}`.
- Revocation is stored per (target, controller) pair. Invalid IDs or revoking oneself return `{type:"error",code:"invalid"}`.
- A later `{type:"request"}` from a revoked controller returns the generic `{type:"error",code:"invalid"}` (no leak). The target receives `{type:"revoked_attempt",controllerId}`.
- Unrevoke is not supported in v1.



