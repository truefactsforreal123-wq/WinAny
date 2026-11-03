# Remote Link Flutter client (prototype)

The responsive app implements Worker WSS challenge registration/authentication with an Ed25519 key in secure storage, explicit incoming consent and preset selection, WebRTC offer/answer/ICE signaling, OS screen-capture prompt, video rendering, and an input/clipboard-text data channel checked against target-side native session permissions. Saved device IDs and minimal audit entries use local Drift/SQLite. Full access requires a separate confirmation. Android uses `remote_link/android` for local grant, injection, revocation and the visible session indicator; stopping the indicator ends the session. A server TURN response is used where configured; otherwise negotiation attempts direct ICE without relay. These paths are **not runtime validated** and are not production ready.

Build `core/rust` as a cdylib and package `remote_core.dll` on Windows or `libremote_core.so` on Linux/Android alongside the app using the platform's native library packaging. The current runner skeleton does not automate packaging. Supply a deployed Worker URL ending in `/v1/ws`. Secure-storage support and screen capture vary by platform. No production signaling service is included.

After installing Flutter and dependencies, run `flutter pub get`, `flutter analyze`, `flutter test`, and a platform build. Android TV uses the same app: `flutter build apk --target lib/tv_main.dart`. Android screen capture/accessibility require explicit OS/user consent; secure content can be blocked.

Limitations: no peer key pinning or end-to-end identity verification independent of signaling, direct IP, comprehensive audit UI, file transfer and TV UI, monitor or quality selection, audio, keyboard/gesture coverage, production native library packaging, or physical-device testing. Mouse position currently uses the full viewport and may not match letterboxed video. Do not rely on this prototype for sensitive access or present it as a completed remote access product.

