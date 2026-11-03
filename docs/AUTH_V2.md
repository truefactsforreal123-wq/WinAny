# Unattended / trusted-device auth v2

Fixes the security review of v1: proofs were not bound to a session, trust lookup ignored the
signaling id, the signaling key was not tied to the proof key, nothing was bound to DTLS, and
password guessing was effectively unlimited.

## 1. Server (server/src/index.ts)

- `incoming` gains `controllerPublicKey`: the base64 Ed25519 key registered for the controller
  (`device:<id>`). The target treats it as the only acceptable proof key for that controller.
- New `{type:"unrevoke",controllerId}` -> `{type:"unrevoked",controllerId}`.
- At most 1000 `revoked:<target>:*` keys per target; beyond that `{type:"error",code:"invalid"}`.

## 2. Proof message (core/rust, single source of truth)

```
msg = "remote-link-unattended-v2\0"
      || lp(session_id) || lp(target_id) || lp(controller_id)
      || nonce (32 bytes)
      || lp(controller_dtls_fp) || lp(target_dtls_fp)
lp(x) = u16 big-endian byte length || utf8 bytes
```
DTLS fingerprints are the `a=fingerprint:` values from the local and remote SDP, as
`"sha-256 AB:CD:..."`, uppercase hex, exactly as in the SDP.

## 3. Core ops (JSON via remote_core_call)

- `unattended_proof_sign {session_id,target_id,controller_id,nonce,controller_dtls_fp,target_dtls_fp}`
  -> `{signature}`: signs msg with this device's identity key, in the same way the existing
  identity signing op does.
- `trust_verify {public_key,expected_public_key,controller_id,session_id,target_id,nonce,controller_dtls_fp,target_dtls_fp,signature}`
  -> `{device_id,permissions}`. Errors unless:
  - `public_key == expected_public_key`,
  - the key is trusted *for this controller_id* (the trust entry stores controller_id), and
  - the signature over msg verifies.
  The returned `permissions` are the only grant source.
- `trust_set` adds a required `controller_id`. The trust JSON format bumps to version 2, and
  v1 import is rejected.
- Password challenge: the target sends `salt` and `iterations` from its stored hash, plus nonce.
  - `unattended_password_proof {password,salt,iterations,...msg fields}` -> `{mac}`.
    `K = PBKDF2-HMAC-SHA256(password,salt,iterations)` and `mac = HMAC-SHA256(K, msg)`.
    It runs on the controller.
  - `unattended_password_check {hash,mac,...msg fields}` -> `{valid}` uses a constant-time
    compare and runs on the target.
  - `unattended_password_params {hash}` -> `{salt,iterations}`.
  - The plaintext password never leaves the controller.
- Lockout lives in the app (see 4), not in core global state. Remove the process-wide 5/60s
  lockout so other users cannot lock the owner out.

## 4. App (apps/flutter_app)

- Controller signs only when session_id/target_id equal the session it requested itself, and
  only during the first 30 s of that session. `enroll` replies require user confirmation.
- Target: a fresh nonce per session, expiring after 20 s, with a single challenge per session
  (no re-issue on `hello`). After the 20 s auth window, show the owner prompt; with no answer
  in 60 s, end the session.
- Max 3 password attempts per session, then end it. Lockout is persisted per controller_id in
  secure storage: after 3 failed sessions, lock for 1 min, doubling up to 24 h.
- PBKDF2 calls go through `Isolate.run`.
- Trust after attended accept: the dialog names the preset; trust is capped at `normal` unless
  the owner explicitly ticks "allow full unattended".
- Reject a remote DTLS fingerprint change on renegotiation/ICE restart (end the session).
- Revoke ends any live session from that device. The pending server-revoke queue is persisted.
  Clearing the unattended password ends password-granted sessions and deletes stored
  `unattended.preset`.
- While unauthenticated, the target sends only relay ICE candidates. After auth, keep relay
  (shortcut: no ICE restart to direct).
- On successful auth, clear the `incomingSession`/`incomingController` prompt. The unattended
  password field is cleared after sending.

## 5. Round 2 (re-review)

- Target-wide password budget: 10 password attempts per hour across all controllers, then
  exponential backoff (persisted). Blocks only the password path; trusted-key auth still works.
- Requests with no credentials count toward an owner-prompt rate limit (max 5 prompts / 10 min
  per target; extra requests are rejected silently).
- Server: TURN credentials capped per target id (20 issuances / hour).
- Core op `proof_verify {public_key, expected_public_key, ...MSG, signature}` -> `{device_id}`
  (no trust entry needed). Enroll = controller signs a v2 proof over a fresh nonce; target runs
  proof_verify, then trust_set.
- Re-trusting a revoked controller sends `unrevoke` first.

## 6. Accepted residual risks (no PAKE yet) - resolved in v3 (section 7)

- ~~`unattended.hash` is password-equivalent~~ Resolved: the target stores an OPAQUE record, which
  is not password-equivalent (7.3). Old `unattended.hash` values are deleted on load.
- ~~A malicious signaling server can collect a MAC for an offline dictionary attack~~ Resolved:
  OPAQUE messages give a network attacker nothing to test guesses against offline (7.3).

## 7. v3: purpose + OPAQUE

Sections 2 and 3 describe v2. v3 replaces the proof message and the whole password path.
v2 and v3 peers do not interoperate: proofs fail and the target falls back to the owner prompt.

### 7.1 Proof message

```
msg = "remote-link-auth-v3\0" || purpose (1 byte: 0x01 auth, 0x02 enroll)
      || lp(session_id) || lp(target_id) || lp(controller_id)
      || nonce (32 bytes)
      || lp(controller_dtls_fp) || lp(target_dtls_fp)
```
Every op that takes the MSG fields also requires `purpose`: `"auth"` or `"enroll"`.
`unattended_proof_sign` signs either purpose. The verify ops accept only their own purpose:
`trust_verify` and the `unattended_login_*` ops need `"auth"`, and `proof_verify` (enroll) needs
`"enroll"`. An enroll signature therefore never authenticates a session, and an auth signature
never enrolls a device.

### 7.2 Password: OPAQUE (RFC 9807)

Crate `opaque-ke` 4.0.1 (features `ristretto255`, `argon2`). The cipher suite uses a ristretto255
OPRF, 3DH with SHA-512, and an Argon2id KSF with the argon2 crate defaults (m=19 MiB, t=2, p=1).
The credential identifier is fixed (`remote-link-unattended`), because each target has one
password. The v3 MSG with purpose `auth` is the OPAQUE `context`, so both MACs and the session
key are bound to the session ids, the nonce and both DTLS fingerprints.

Core ops (JSON via remote_core_call; binary values are base64):
- `unattended_password_set {password}` -> `{record}`. It runs registration client and server
  in-process on the target. `record` is a JSON string `{version:3, setup, record}` (the server
  setup and the registration record). The app keeps it in secure storage as `unattended.record`.
- `unattended_login_start {password}` -> `{ke1, state}` runs on the controller.
- `unattended_login_respond {record, ke1, purpose, ...MSG}` -> `{ke2, state}` runs on the target.
- `unattended_login_finish {password, state, ke2, purpose, ...MSG}` -> `{ke3}` runs on the
  controller. It errors on a wrong password, a fake target or a different MSG. Argon2 runs here,
  through `Isolate.run`.
- `unattended_login_verify {state, ke3, purpose, ...MSG}` -> `{valid}` runs on the target.
- The v2 ops `unattended_password_params/proof/check/verify` and `password_create/verify` are
  removed. PBKDF2 is gone from the core.

Data channel flow (ChallengeGate, the 3-attempt cap, PasswordBudget and the per-controller
lockout are unchanged):
1. Target -> `auth_challenge {nonce, session_id, target_id, password:true?}`. The `password`
   flag is set only when a record exists and the budget allows an attempt.
2. Controller -> `auth {public_key, signature, ke1?}`. The signature covers the v3 auth MSG. KE1
   is a blinded value. The typed password stays in memory until KE2 arrives, then it is dropped.
3. Target: `trust_verify` runs first. Otherwise, with KE1, it counts the budget attempt, records
   a failed session for the controller (the controller may just stop), runs
   `unattended_login_respond`, and sends `auth_opaque {ke2}`.
4. Controller -> `auth_finish {ke3}`, sent only if `unattended_login_finish` succeeds.
5. Target: if the gate is still live (inside the 20 s window, no extra attempt counted),
   `unattended_login_verify` runs. `valid` grants the stored preset, and the lockout is reset.
The app validates exact sizes: KE1 96 bytes, KE2 320 bytes, KE3 64 bytes.

Migration: if the old `unattended.hash` (v2 PBKDF2) is found on load, the app deletes it and
Settings shows "Set the unattended password again". There is no fallback to v2.

### 7.3 Security properties and residual risks

- The stored record is not password-equivalent. An attacker who holds it cannot log in. They
  must run one Argon2 computation per offline guess (inherent in any augmented PAKE). Keep it in
  secure storage anyway.
- A malicious signaling server or a DTLS MITM sees, at most, a blinded KE1 and a KE2 that it
  cannot open without the password. A guess needs a live exchange with the real target, so it is
  capped by the gate, the budget and the lockout. A MITM with different DTLS fingerprints on each
  side produces different contexts, so the login fails.
- Remaining: the Argon2 parameters are the OWASP minimum, not the RFC 9807 recommended profile
  (2 GiB, too heavy for mobile controllers). They are fixed at registration and can only change
  through a new registration and a version bump.
- Remaining: the OPAQUE session key is not used beyond authentication. The data channel itself is
  protected by DTLS, which the context binds.
