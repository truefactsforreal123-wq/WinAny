# Handoff: WinAny (AnyDesk-style remote desktop)

Session date: 2026-11-03. Read this first in the next session, together with `plan.md`, `DESIGN.md`,
`docs/AUTH_V2.md`, `docs/SECURE_DESKTOP.md` and `docs/ANDROID.md`.

## 1. Where things stand

- **Repo:** https://github.com/truefactsforreal123-wq/WinAny (public, branch `main`). Commit after every change.
- **Scope:** Windows and Android only. Linux and macOS are deferred by the owner.
- **plan.md coverage:** about 85% coded (about 92% of the Windows scope). Most features are unit-tested only.
- **Real-device test (2026-11-03):** phone controlling a PC works. PC controlling a phone fails (bug B).
  The phone controlling the PC again crashed the phone app (bug C). The highest quality preset errors (bug D).

### Live infrastructure

| What | Where |
|---|---|
| Signaling server (Cloudflare Worker `remote-signaling`, Durable Object `SignalingHub`) | `wss://signal.mixed-tools.site/v1/ws` (fallback `remote-signaling.mohamedelmahrouky04.workers.dev`) |
| TURN | Cloudflare Realtime TURN. Secrets `TURN_KEY_ID` and `TURN_KEY_API_TOKEN` are set with `wrangler secret put` |
| Updates | R2 bucket `remote-link-updates` at `https://updates.mixed-tools.site/update-<platform>.json` (r2.dev is disabled) |
| Domain | `mixed-tools.site`: Namecheap registrar, Cloudflare DNS. Vercel site records are DNS-only, and the Namecheap email-forward MX records are kept |
| Update signing | Ed25519 public key in `apps/flutter_app/lib/update_check.dart`. The private key `~/update_signing.pem` stays offline and is never committed |
| Android signing | `C:\Users\Mohamed\upload-keystore.jks`, alias `upload`, configured in `apps/flutter_app/android/key.properties` (git-ignored) |

### Build and run

- Windows: `cd apps/flutter_app && flutter build windows --release`, which outputs `build/windows/x64/runner/Release/`.
  It needs Developer Mode, VS 2022 Build Tools and the C++ ATL component.
- Android:
  1. `scripts/build-android-core.ps1` builds the Rust `.so` into `jniLibs`, using cargo-ndk with the Android targets.
  2. `flutter build apk --release` builds a signed APK of about 94 MB. If R8 runs out of memory, run `./gradlew --stop` and retry.
- Tests:
  - `flutter analyze`
  - `flutter test`
  - `dart --enable-asserts test/*_standalone.dart`
  - `cargo test` in `core/rust` and in `core/service`
  - `npm test` and `npm run typecheck` in `server/`
  - each tv_bridge script with `dart test/<file>.dart`
  - All of these passed at the last run.
- Server deploy: `cd server && npx wrangler deploy`.
- Builds for testing are copied to `C:\Users\Mohamed\Desktop\WinAny\`.
  - The Windows build uses the domain URL.
  - The APK predates the domain switch, so rebuild it.
- **Gotcha:** the owner's VPN uses fake-IP DNS (`198.20.x.x`), which breaks Cloudflare domains. Test with the VPN off.

## 2. What this session did

1. **Audit:** plan coverage was about 55% at the start. Implemented in waves through sonnet and haiku agents, with Opus for security work.
2. **Phase 3 and 5:** reconnect with backoff, keys bar (Ctrl/Alt/Win, F-keys, Ctrl+Alt+Del, text), trackpad mode,
   and TV discovery (Roku, Samsung, LG, Android TV, Vizio, Fire TV).
   Added adapters: Android TV Remote v2, Vizio, ADB/Fire TV with companion APK install. Apple TV is marked unsupported.
3. **Rust core:** new keys, Unicode text, multi-monitor (`monitors`, `display` on input), trust store, and `service_send_sas`.
4. **Windows service** (`core/service`, `remote_link-service.exe`):
   - It launches the app and a SYSTEM helper that injects input only on the Winlogon desktop.
   - Secure-desktop input requires the admin opt-in `HKLM\SOFTWARE\RemoteLink\Service\AllowSecureDesktopInput=1`.
   - The pipe is ACL-locked. The install path check uses an allowlist over every ancestor, refuses UNC paths, and checks Win32 normalization.
   - Hardened through several Opus and automated security reviews.
5. **Server:** session resume (60 s grace), revoke and unrevoke, revoke cap, TURN per-requester caps, and the `controllerPublicKey` in `incoming`.
6. **Unattended auth:** now at v3 (see `docs/AUTH_V2.md` sections 5–7).
   - Signed proofs are bound to the session, both ids, a nonce, both DTLS fingerprints, and a purpose byte.
   - The password uses OPAQUE (`opaque-ke` 4.0.1, Argon2id), so the stored record is not password-equivalent.
   - Limits: a target-wide password budget, per-controller lockout, a per-controller owner-prompt rate limit, and relay-only ICE before auth.
   - Opus verdict: ship.
7. **App:**
   - trusted devices and unattended password settings
   - monitor picker with video switching (`replaceTrack`)
   - system audio (Windows loopback), UPnP for direct mode, update check (signed manifest with version and platform in the signature)
   - Android capture foreground service
8. **Packaging:** Inno Setup script (service task, SAS policy, opt-in task), Linux scripts (untested), update manifest script, build-release scripts.
9. **Deferred by the owner:** secure-desktop capture and pre-logon access. The design is in `docs/SECURE_DESKTOP.md` (split model with a SYSTEM capture helper).

## 3. Bugs from the real-device test (fix these first)

Diagnosis below is from code reading only; there are no device logs. Before fixing, connect the phone with USB debugging
and capture `adb logcat | findstr /i "flutter AndroidRuntime FATAL remote"` while reproducing.

### B. PC controls phone: "Could not authorize session: PlatformException(remote_platform, Enable accessibility locally before allowing input)"
- **Thrown at:** `apps/flutter_app/android/app/src/main/kotlin/com/remotelink/app/MainActivity.kt:83`
  (`require(!input || RemoteAccessibilityService.instance != null)`).
- **Called from:** `signaling.dart:225` (`_authorize`). The catch at `signaling.dart:716-727` denies the session and sets the banner.
  There is no fallback, and the second `_authorize` paths (around `:809` and `:1235`) have the same problem.
- **Fix:**
  1. Add a `isAccessibilityEnabled` channel method.
  2. Before authorizing input, if accessibility is off, show a dialog with an "Open settings" button (`openAccessibilitySettings`), or downgrade to view-only with a visible notice.
  3. Never fail the whole session for this. Keep the Kotlin `require` as a safety net.

### C. Phone app crashes when connecting to the PC again (after B)
Ranked causes:
1. `android/remote-platform/src/main/AndroidManifest.xml:12-15` declares `.CaptureService` **twice**. Remove the duplicate.
2. Stale state after the failed session. `_revoke()` (`signaling.dart:2245`) must:
   - always stop CaptureService and SessionIndicatorService
   - call `revokeSession`
   - reset `target`, `_captureServiceOn`, `_accepting`, `_peerReady` and the session or generation fields
   A leftover `target = true` (set at `:690`) would make the phone try to capture while it is the controller.
3. On Android 14+, CaptureService calls `startForeground(MEDIA_PROJECTION)` before the user consents to projection.
   This throws SecurityException inside `onStartCommand` (`CaptureService.kt:21`) and kills the process, and Dart cannot catch it.
   Fix: wrap it in try/catch with `stopSelf()`, and start the service only after `getDisplayMedia` consent succeeds.
4. Add `runZonedGuarded` and `FlutterError.onError` in `main()` and log to the audit log, so that future crashes are visible.

### D. Highest quality preset fails ("Video quality controls unavailable/rejected")
- **Where:** `signaling.dart:1366-1381`. `sender.parameters.encodings` is read right after `addTrack`, before negotiation,
  so it is empty on some devices. In addition, 5 Mbps or 30 fps can be rejected, and `getDisplayMedia` sets a mandatory `frameRate: 30` at `:1347`.
- **Fix:**
  - Apply the encodings after `setLocalDescription`.
  - On failure, step down to the next preset (5M, then 2M, then 800k) instead of showing an error.
  - Use `ideal` frame rate rather than a mandatory one.
  - Treat missing encodings as a non-fatal audit note.

## 4. Changes the owner asked for

- **Full-screen remote view on the phone that follows device orientation**, landscape or portrait.
  - The view is currently boxed by `AspectRatio(16/9)` (`main.dart:817-818`) inside cards and a scroll list, behind an AppBar.
  - There is no `SystemChrome` use, and the manifest has no orientation lock.
  - Fix: when the session starts as controller, push a full-screen route:
    - `SizedBox.expand(RTCVideoView(objectFit: contain))`
    - `SystemChrome.setEnabledSystemUIMode(immersiveSticky)` and `setPreferredOrientations(DeviceOrientation.values)`
    - a floating, auto-hiding toolbar (keys, trackpad toggle, monitor picker, quality, mute, disconnect)
    - restore the system UI on exit
  - `mapVideoPointer` already handles letterboxing.
- Apply the same full-screen treatment on desktop, with an F11 or "Full screen" button.

## 5. Design proposal (next session: run `ui-designer` first, then build)

The current UI is a stock Material scroll of cards and doesn't look professional. Proposed direction:

- **Look:** dark-first, calm, "pro tool".
  - Colors: near-black background `#0E1116`, raised surfaces `#161B22` and `#1F2630`, one accent (electric teal `#2DD4BF`),
    danger red `#F05252`, success green `#3FB950`. Also provide a light theme.
  - Type: Inter or the system UI font.
  - The 12-digit ID is shown large in a monospace font, grouped `429 819 871 016`.
  - 8-pt spacing, radius 12, subtle 1-px borders instead of heavy shadows.
- **Home screen:**
  - Left (desktop) or top (phone): a "This device" card with a big ID, copy and share buttons, an online dot, and the unattended status.
  - Main area: a "Connect" field with ID formatting and a primary button. Below it, a recent and trusted devices grid
    (name, last seen, one-tap connect).
  - Settings live in a separate screen or drawer, not inline cards: server URL, unattended password, trusted devices,
    TV, updates, and the audit log.
- **Incoming request:** a modal sheet with the requester ID or name, the requested permissions as toggle chips
  (view, input, clipboard, files, audio, elevated), a quality choice, and Accept or Deny with a countdown.
- **Session:**
  - Full-screen video with a floating, auto-hiding toolbar pill at the top: connection quality dot, latency, monitor picker,
    keys menu, trackpad or touch toggle, quality, audio, file transfer, and a red disconnect button.
  - On a phone: a bottom keys bar that slides up, plus gesture hints.
- **States:** clear empty, loading, reconnecting and error states with plain-language messages.
  For example: "Turn on Remote Link in Accessibility settings to allow control", with a button, instead of raw PlatformException text.
- **Brand:** pick a name (the repo is "WinAny", the app title is "Remote Link"), then add an icon and a splash screen.
- **Process:** `ui-designer` (sonnet) writes the spec into `DESIGN.md` (tokens, screens, states, copy), then `flutter-dev` builds it
  as a theme file plus refactored screens. Keep `signaling.dart` logic untouched.

## 6. Open items (owner)

- **Rotate the TURN API token** (it was exposed in chat), then run `npx wrangler secret put TURN_KEY_API_TOKEN` from `server/`.
- Back up `~/update_signing.pem`, `upload-keystore.jks` and their passwords offline.
- `keytool.exe` in Android Studio's `jbr` is a 0-byte file. Use
  `java -m java.base/sun.security.tools.keytool.Main ...` or reinstall Android Studio.
- Code-signing certificate (Certum, Azure Trusted Signing, or OV). The installer's signing step must be adapted to the provider (hardware or cloud HSM).
- Install Inno Setup (`winget install JRSoftware.InnoSetup`) to build the installer.
- Real-machine tests: service install and Ctrl+Alt+Del, unattended between two PCs, audio after a monitor switch,
  multi-monitor input, TVs, UPnP.
- For Play publishing: `flutter build appbundle` and a Play Console account.

## 7. Suggested order for the next session

1. Fix bugs C, B and D, plus the full-screen and orientation change (`flutter-dev`, sonnet). Get `adb logcat` first if the phone is connected.
2. Rebuild both apps, copy them to the Desktop, and have the owner retest PC↔phone.
3. Design: `ui-designer` writes the spec, then `flutter-dev` implements it, then code review, then a `test-runner` pass.
4. Commit and push after each step.
