# Secure desktop and pre-logon access: design (deferred)

Status: designed on 2026-11-03 and deferred by the owner until real-machine testing of the rest is done.

## Problems
1. The remote user cannot see the lock screen, UAC or Ctrl+Alt+Del screen (the Winlogon desktop).
   Input there already works through the service helper, gated by admin opt-in.
2. There is no access before any user logs on, because the app is only launched after logon.

## Chosen option: split model (option b)
- The SYSTEM helper captures and injects on the Winlogon desktop and never touches the network.
  It sends frames to the user-session app through a read-only shared-memory section using a seqlock
  and I420. It captures with GDI BitBlt at 10 fps. `shortcut: GDI 10fps, upgrade to DXGI if fps matters.`
- The network-facing Flutter peer never runs as SYSTEM. It swaps the video track with `replaceTrack`,
  so there is no reconnect and no DTLS fingerprint change.
- flutter_webrtc 1.6.3 exposes no frame injection to Dart. libwebrtc m150 has
  `CreateCustomVideoSource` and `RTCVideoSource::OnCapturedFrame`, so we need a vendored fork of the
  plugin with a `createSharedMemoryTrack(handle)` method. Section size, width, height and stride must be
  validated because the section is a trust boundary.
- Gating: frames and input go out only when the session grant has `elevated`, and only when the admin
  opt-in `HKLM\SOFTWARE\RemoteLink\Service\AllowSecureDesktop` is 1.
- Pre-logon (Phase 2): the service launches `remote_link.exe --logon-host` under a LocalService
  token, never SYSTEM. It uses a machine identity and a machine trust list in
  `%ProgramData%\RemoteLink` (ACL: SYSTEM and Administrators only), passed to the host on stdin.
  Password auth is off pre-logon. The host is killed on user logon and the controller reconnects
  to the user ID.

Rejected:
- (a) A SYSTEM Flutter instance on Winlogon: all network-parsing code would run as SYSTEM.
- (c) A webrtc-rs peer in the service: 6–10 weeks of work, and the network code still runs as SYSTEM.

## Implementation steps (Phase 1)
1. core/service protocol.rs: add the `secure_capture {on}` op and its tests.
2. core/service service.rs: create the section, add the helper capture thread, use `DuplicateHandle`
   with FILE_MAP_READ to give the app read access, add the registry gate, and add tests for the
   seqlock and the BGRA-to-I420 conversion.
3. core/rust lib.rs: add `service_secure_capture`, `service_desktop_input` (which wraps
   `switch_desktop_input`, not yet called anywhere) and `secure_desktop_active`.
4. Vendored flutter_webrtc: add `createSharedMemoryTrack` and wire it in with `dependency_overrides`.
5. signaling.dart: in elevated sessions only, poll `secure_desktop_active`, swap the track and route
   input. Non-elevated sessions get a "secure desktop hidden" notice.
6. Run a security review on Opus.

Phase 2 depends on Phase 1. Its effort is about 1.5–2 weeks; Phase 1 is about 1–1.5 weeks.

## Residual risk
While the opt-in is on, other code running as the same user can read Winlogon frames and drive
input there. Same-user code could therefore watch UAC prompts.

## Admin test checklist (real Windows 11)
- The controller sees a UAC prompt and clicks Yes.
- After Win+L, the controller sees the lock screen and types a PIN.
- The Ctrl+Alt+Del screen shows.
- With the opt-in set to 0, the screen goes black or the notice appears.
- A Normal (non-elevated) session cannot see the secure desktop.
- A second process running as the same user is rejected on the pipe.
- Neither the service nor the helper has sockets (`netstat -abno`).
