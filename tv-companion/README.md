# Android TV / Fire TV companion

The companion reuses the Flutter target implementation, signaling identity and WebRTC capture pipeline; it is not a separate unauthenticated server.

```powershell
cd apps/flutter_app
flutter pub get
flutter build apk --release --target lib/tv_main.dart
```

Install the signed APK on an Android-based TV that permits MediaProjection. Start the app, connect to the same signaling deployment and accept the request **on the TV**. Capture still requires the system consent dialog. Input needs the separately disclosed AccessibilityService enabled by the owner. The app declares touchscreen optional and Leanback launcher support. Actual D-pad focus and capture need testing on the target firmware before distribution.

This is Tier A only where firmware permits it. It does not add screen capture to Samsung, LG or Apple TV. Tier B ADB capture and Tier C HDMI hardware capture are not implemented; enabling ADB should never be an automatic remote operation. Secure/DRM content remains unavailable.

## Tier B: ADB (Fire TV / Android TV)

Select **Fire TV (ADB)** in the TV panel. Desktop only: install Android platform-tools so `adb` is on PATH. Enable ADB debugging on the TV by hand, then pair and accept the RSA prompt shown on the TV. Keys, text (limited to `A-Za-z0-9 .,_@:/+=-`) and app launch run as `adb -s <ip>:5555 shell ...` with argument lists, never a shell string. `AdbAdapter.installApk(path)` runs `adb install -r` for the Tier A companion APK; it has no UI yet. ADB screen capture is not implemented.
