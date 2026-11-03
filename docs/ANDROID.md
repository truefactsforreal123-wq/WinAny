# Android build

Requirements: Flutter SDK, JDK 17, Android SDK (compileSdk 36), minSdk 26.

## Build
1. (Optional, native core) `cargo install cargo-ndk`, `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`, install an NDK, then `scripts/build-android-core.ps1`. It writes `libremote_core.so` into `apps/flutter_app/android/app/src/main/jniLibs/`.
2. `cd apps/flutter_app && flutter build apk --debug` (or `--release`).

## Signing
Create a keystore: `keytool -genkey -v -keystore %USERPROFILE%\upload-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload`.
Copy `android/key.properties.example` to `android/key.properties` (gitignored) and fill it in. Without it, release builds use debug signing.

## Enable the accessibility service (phone as target)
Settings > Accessibility > Installed apps > Remote Link > turn on. Needed only to allow remote input; the app opens this screen after you accept the disclosure. Android 13+ sideloaded apps: App info > menu > Allow restricted settings first.

## Known limits
- Screen capture needs the MediaProjection consent dialog every session; Android 14 needs the capture foreground service (`CaptureService`) running.
- Secure windows (banking, DRM) appear black. No arbitrary key events, only taps, swipes, nav actions and text.
- Without `libremote_core.so`, native-core features are unavailable on Android.
- Gradle needs access to Google Maven (dl.google.com).
