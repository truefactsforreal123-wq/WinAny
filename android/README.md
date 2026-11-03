# Android platform module

`remote-platform` is linked into the Flutter Android runner. It provides a user-enabled AccessibilityService and a foreground, stop-enabled session indicator. It never enables accessibility automatically, starts at boot, or persists an input grant. Grants expire after one hour and are revoked on disconnect/process/service death.

Screen streaming uses `flutter_webrtc`'s MediaProjection implementation, not a second projection token. The OS capture consent dialog is required on every capture session; secure/DRM content cannot be captured. The app must stop both the WebRTC stream and this input grant when the notification's Stop action fires.

The local Flutter MethodChannel is a trusted application boundary; do not dispatch remote JSON operations directly to it. Only a local accept dialog can create a grant. Remote input is checked against the session on both Dart and Android sides. Android supports taps/swipes, selected global navigation and focused text entry, not arbitrary desktop keyboard injection.

Direct APK distribution first. Accessibility disclosure and user confirmation are mandatory. A Google Play release additionally needs the current accessibility/foreground-service declarations and review; approval is not implied.

References: [MediaProjection lifecycle](https://developer.android.com/media/grow/media-projection), [AccessibilityService](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService), [foreground service requirements](https://developer.android.com/develop/background-work/services/fgs/service-types).
