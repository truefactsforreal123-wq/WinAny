# Design

Status: Active build spec. Date: 2026-11-03. Supersedes the earlier indigo/navy light-canvas direction. Source: `HANDOFF.md` section 5 plus inventory of `apps/flutter_app/lib/main.dart`.

Build rules:
- `signaling.dart` logic stays untouched. UI only reads state and calls the methods that exist today.
- Every control below maps to an existing control (section 8). No new features. Items marked "(if exposed)" render only when `state` already has the value; otherwise omit them.
- Build as one theme file (`lib/theme.dart`) plus screen refactors of `main.dart`.

## 1. Brand

Name: **Remote Link**. Rationale: it is already the app title, the service exe (`remote_link-service.exe`), the registry key (`RemoteLink`) and the update bucket, it fits Android too, and "WinAny" implies Windows-only and an AnyDesk pun. Keep "WinAny" as the repo name or rename the repo later (owner's call).

Voice: calm, technical, consent-first. Plain language. Never claim invisible access. Do not imitate AnyDesk branding.

Icon brief: rounded square (Android adaptive icon, 108dp canvas, 66dp safe zone), background `#0E1116`, a single teal `#2DD4BF` glyph made of two linked chain-links forming a monitor outline. One color, no gradient, readable at 16px. Windows .ico sizes 16, 24, 32, 48, 256. Monochrome Android 13 themed layer: same glyph.

Splash brief: `#0E1116` fill, centered glyph at 96dp, no text, no animation beyond a 150ms fade. Android 12+ uses the SplashScreen API with the same background and glyph. Light mode keeps the dark splash (the app ships dark-first).

## 2. Tokens (ThemeData-ready)

Names map 1:1 to a `ColorScheme` / `ThemeExtension`. Build `ThemeData(useMaterial3: true, colorScheme: ..., extensions: [RlColors(...)])`. Default `themeMode: ThemeMode.system`, but first launch with no OS preference uses dark.

### Colors

| Token | ThemeData slot | Dark | Light |
|---|---|---|---|
| bg | `scaffoldBackgroundColor`, `colorScheme.surface` | `#0E1116` | `#F6F8FA` |
| surface1 | `cardColor`, `surfaceContainer` | `#161B22` | `#FFFFFF` |
| surface2 | `surfaceContainerHigh` (inputs, chips, sheets) | `#1F2630` | `#EEF1F5` |
| border | `dividerColor`, card `BorderSide` | `#2A313C` | `#D0D7DE` |
| borderStrong | `InputDecorationTheme` enabled border | `#667085` | `#6E7781` |
| text | `onSurface` | `#E6EDF3` | `#1F2328` |
| textMuted | `onSurfaceVariant` | `#9AA4B2` | `#57606A` |
| accent | `primary` | `#2DD4BF` | `#0F766E` |
| onAccent | `onPrimary` | `#04201C` | `#FFFFFF` |
| danger | `error` (text, icons) | `#F05252` | `#C53030` |
| dangerFill | End/Disconnect/Deny button fill | `#C53030` | `#C53030` |
| onDangerFill | text on dangerFill | `#FFFFFF` | `#FFFFFF` |
| success | extension `success` | `#3FB950` | `#1A7F37` |
| warning | extension `warning` | `#D29922` | `#9A6700` |
| scrim | `scrim`, sheet barrier | `#000000` at 60% | `#000000` at 40% |
| toolbarPill | session toolbar fill | `#161B22` at 88% | `#FFFFFF` at 92% |

### Type

Font: Inter (bundle `Inter` variable, weights 400/500/600) with system UI fallback (Segoe UI Variable on Windows, Roboto on Android). Monospace: `JetBrains Mono` bundled, fallback `Consolas` / `RobotoMono`; use `fontFeatures: [FontFeature.tabularFigures()]`. If bundling is deferred, system fonts are acceptable.

| Token | TextTheme slot | Size / height / weight |
|---|---|---|
| display | `displaySmall` | 32 / 40 / 600 |
| title | `titleLarge` | 20 / 28 / 600 |
| titleSm | `titleMedium` | 16 / 24 / 600 |
| body | `bodyLarge` | 16 / 24 / 400 |
| bodySm | `bodyMedium` | 14 / 20 / 400 |
| label | `labelLarge` (buttons, chips) | 14 / 20 / 500 |
| caption | `bodySmall` | 12 / 16 / 400 |
| idLarge (mono) | extension `idLarge` | 32 / 40 / 500, letter-spacing 1 |
| idInput (mono) | extension `idInput` | 20 / 28 / 500 |
| idSmall (mono) | extension `idSmall` | 14 / 20 / 400 |

ID format: 12 digits grouped 3-3-3-3 with thin spaces as normal spaces, for example `429 819 871 016`. Display only. The value stored, copied to clipboard, passed to `state.request(...)` and saved is the raw 12 digits (strip spaces). Use one `TextInputFormatter` for the Connect field and a helper for display.

### Spacing, shape, motion

| Token | Value |
|---|---|
| space1..space6 | 4, 8, 16, 24, 32, 48 (8-pt grid, 4 for icon gaps only) |
| page padding | 16 phone, 24 desktop |
| radius | 12 for cards, inputs, buttons, chips, sheets (top corners 16 for bottom sheets) |
| radiusPill | 999 (toolbar pill, status dot chips) |
| border | 1px solid `border`; no elevation shadows on cards. Sheets and dialogs may use `elevation: 0` plus `border` |
| icon | 24 default, 20 inside the toolbar pill |
| motion | 150ms ease-out for fades, 200ms for sheet slide. Honor `MediaQuery.disableAnimations` |

Component themes to set: `CardTheme` (surface1, radius 12, border), `InputDecorationTheme` (filled surface2, border `borderStrong`, focused border `accent` 2px), `FilledButtonTheme` (accent, min height 48, radius 12), `OutlinedButtonTheme`, `TextButtonTheme`, `ChipTheme` (surface2, selected tinted accent at 16% with accent border), `SwitchTheme`, `ListTileTheme` (min height 56), `BottomSheetTheme`, `DialogTheme`, `SnackBarTheme` (floating), `VisualDensity.standard`, `focusColor` accent at 24%.

## 3. Layout shell

Breakpoint 720dp (matches the earlier doc).
- Phone (<720): single column, `AppBar` with title "Remote Link" and a settings icon button (tooltip "Settings").
- Desktop (>=720): two panes, left pane 320 fixed ("This device"), right pane flexible (max content width 720, left-aligned). Same app bar, settings icon at right.
- Settings, Incoming request and Session are separate routes or sheets, not inline cards.

## 4. Screens

### 4.1 Home

Purpose: show my ID and connect to another device.

Order (phone, top to bottom; on desktop the first block is the left pane, the rest the right pane):

1. **Error banner** (only if `state.error != null`): surface2 with danger left border, plain-language text (section 6), a recovery button and a dismiss icon.
2. **This device card** (surface1, 16 padding):
   - Header row: "This device" (`titleSm`) and status chip at right: dot + "Online" (success) / "Offline" (textMuted) / "Connecting" (warning). Never color-only: dot plus word.
   - ID: `idLarge` mono, grouped, selectable. If `state.deviceId == null`: "Go online to get your ID" in textMuted.
   - Row of two buttons: "Copy ID" (outlined, copies raw digits, snackbar "ID copied") and "Share" (outlined, shares text "My Remote Link ID: 429 819 871 016"). Share only if the share plugin is already a dependency; otherwise omit and keep Copy.
   - Primary button: "Go online" / "Go offline" (maps to `state.connect(endpoint)` / `state.disconnect()`; uses the saved server URL from Settings).
   - Android only: warning row "Control is off. Turn on Remote Link in Accessibility settings." with button "Set up control" (existing accessibility dialog and `openAccessibilitySettings`). Hide when already on (if exposed).
   - Unattended status line: "Unattended access: on" / "off" (if exposed), tap goes to Settings.
3. **Connect card** (surface1):
   - Title "Connect to a device", helper text "The other device has to approve your request." 
   - ID field (mono `idInput`, numeric keypad, label "Device ID", hint `000 000 000 000`, auto-group while typing, max 12 digits, clear icon). Enter key submits.
   - Optional "Unattended password" field (obscured, label "Password (optional)", show/hide eye) in a collapsed "Have a password?" row to reduce clutter.
   - Primary button "Connect" (maps to `state.request(peer)`; enabled when online, no session, and 12 digits). Disabled reason shown as helper text: "Go online first" or "Enter all 12 digits".
   - Secondary text button "Save device" (maps to `_saveDevice`).
   - While a session is active, replace the primary with a dangerFill "End session" (`state.end`).
4. **Saved devices grid** ("Recent and trusted", title `titleSm`): source is the existing saved IDs list plus trusted devices list. Grid: 1 column list on phone, 2 to 3 columns on desktop (min tile width 220). Tile: monitor icon, name or grouped ID (`idSmall`), a "Trusted" badge if trusted (icon plus word), last seen only if stored. One tap fills the Connect field (existing `peer.text = id`); a "Connect" icon button on the tile does fill plus request. Long-press or overflow menu: "Remove" only if remove already exists; otherwise omit.
5. **TV and direct IP** entries: two compact list rows "TV controls" and "Direct IP" (existing "Open TV controls" and "Open direct IP controls"), shown below the grid. Move from inline cards to rows that open their existing screens.

Reconnecting overlay and Trust prompt: see states and Session.

### 4.2 Settings (separate route)

AppBar "Settings" with back. Single column list of grouped sections (section header `caption` uppercase textMuted, cards with 1px border), max width 640 on desktop.

1. **Connection**: "Server URL" field (existing Signaling URL, hint `wss://your-server/v1/ws`, disabled while online with helper "Go offline to change this").
2. **Unattended access**: "Unattended password" (existing unattended password setting) with "Set password" button; helper "Lets a trusted device connect without you approving each time."
3. **Trusted devices**: list of trusted devices with "Remove trust" (existing trust store UI), empty text in section 6.
4. **TV devices**: row "TV devices" opens existing TV discovery/controls.
5. **Updates**: row "Check for updates" with current version, result line. Uses existing update check.
6. **Audit log**: row "Activity log" opens a list of the existing local audit entries (monospace `idSmall` for timestamps), empty state in section 6.
7. **About**: app name, version.

Phone vs desktop: phone is full-screen pushed route; desktop is the same route centered, or a right-side panel if the dev prefers. Keep route for simplicity.

### 4.3 Incoming request (modal)

Phone: modal bottom sheet, not dismissible by tap outside (only by Deny), max height 90%. Desktop: centered dialog 480 wide. Replaces the current "Allow this device?" `AlertDialog`.

Content top to bottom:
1. Title "Allow this device?" and the requester ID (`idLarge` smaller: use `idInput`, grouped) plus name if known; "Trusted" badge if trusted.
2. Countdown: text "Auto-deny in 0:42" with a thin progress bar (accent, turns warning under 10s). If the current code has no timeout, show no countdown (do not invent a timer in `signaling.dart`; a UI-only timer that calls the existing Decline path is allowed).
3. "Permissions" with toggle chips (`FilterChip`, 48 high): View (always on, locked, disabled look with lock icon), Input, Clipboard, Files, Audio, Elevated. These map onto the existing Basic / Normal / Full selector: Basic = View; Normal = View plus Input (plus Clipboard, Audio, Files per what each level grants today); Full = all, including Elevated. Selecting a chip beyond the current level moves the level up; deselecting moves it down. Keep the existing level value as the single source of truth. If chip-to-level mapping would require new permission logic, fall back to the three-option segmented control labelled Basic, Normal, Full with one-line descriptions (see copy).
4. Elevated chip is danger-tinted. Turning it on keeps the existing "Confirm elevated access" dialog.
5. "Screen to share" dropdown (existing system screen picker) and "Quality" segmented control: "Low latency", "Balanced", "High quality" (existing).
6. Footer buttons, full width, 48 high: "Deny" (dangerFill) left and "Accept" (primary) right on desktop; stacked with Accept on top on phone. Deny is the default focus action on desktop? No: focus starts on neither; Tab order is chips, quality, Deny, Accept.

Receive-file dialog ("Receive file?"): same dialog styling, buttons "Decline" and "Receive".

### 4.4 Session

Purpose: see and control the remote screen with minimum chrome.

- **Video**: full-screen route, `SizedBox.expand` with the existing video view, contain fit, black letterbox `#000000`. Phone follows device orientation (portrait and landscape), immersive mode, restored on exit (per HANDOFF section 4). Desktop: full-window, F11 or the "Full screen" toolbar button toggles OS full screen.
- **Toolbar pill** (top center, 8 from the safe area top, height 48, radius pill, fill `toolbarPill`, 1px border). Auto-hides after 4s without interaction; shows again on tap (phone), mouse move to the top 64px (desktop), or Esc/F10 key. Never hides while a menu is open. Items, left to right:
  1. Connection dot + latency "42 ms" (latency if exposed; dot is success / warning / danger by quality, with a content description). Tap opens a small popover with the quality note.
  2. Monitor picker (existing monitor dropdown; icon `monitor`; hidden when only one monitor).
  3. Keys menu (existing key set: Ctrl, Alt, Win sticky modifiers, Esc, Tab, Enter, Backspace, arrows, Ctrl+Alt+Del, More keys F1 to F12, Home, End, PageUp, PageDown, Delete, Insert, type-text field).
  4. Input mode toggle: Touch / Trackpad (existing Trackpad mode switch). Phone only visible by default; on desktop it lives in the keys overflow.
  5. Quality menu (existing three presets).
  6. Audio: mute/unmute (existing, only when `hasAudio`).
  7. Files: "Offer file" and "Send clipboard text" (existing), only when Full access allows.
  8. Disconnect: dangerFill circular button with "End session" tooltip (existing `state.end`). Always the last, always visible while the pill is shown.
  On phone landscape the pill may overflow: items 4 to 7 collapse into a "More" overflow (3-dot) menu. Minimum targets stay 48.
- **Phone bottom keys bar**: slides up from the bottom (200ms) when "Keys" is toggled; height 56 for one row of sticky modifiers (Ctrl, Alt, Win) and horizontal scroll of Esc, Tab, Enter, Backspace, arrows, Ctrl+Alt+Del, More; a second row with the "Type text" field and send button appears when the system keyboard is up. It sits above the keyboard and respects bottom insets. Hides together with the pill unless pinned.
- **Gesture hints** (first session only, dismissed on tap, stored once): touch mode "Tap to click. Two-finger tap to right-click. Drag to scroll." / trackpad mode "Drag to move the pointer. Tap to click." Text shown in a toast over the video bottom. Use only gestures the existing input mapping supports; edit the hint text if the mapping differs.
- **Target side persistent indicator**: while this device is being controlled, a top bar chip "Being controlled by 429 819 871 016" with an "End" button (maps to the existing session indicator and `state.end`).
- **Trust prompt** ("Trust this device?", Agree, Decline, Trust) uses the same dialog style.

Desktop differences: pill is draggable? No (not needed). Keyboard events go to the remote while the video has focus; Esc is not forwarded when the pill is focused. `Ctrl+Alt+Del` button instead of key combo.

## 5. Components inventory

AppShell (two-pane/one-pane), StatusChip, DeviceIdText (grouped mono, selectable), IdField (formatter), DeviceCard, DeviceTile, PermissionChip, QualitySegment, CountdownBar, ErrorBanner (message, action, dismiss), ToolbarPill, KeysBar, SettingsSection, EmptyState. Reuse Material `FilterChip`, `SegmentedButton`, `ListTile`, `SwitchListTile`, `showModalBottomSheet`, `PopupMenuButton`. No new packages beyond fonts.

## 6. States and copy

Buttons are verb-first. Error text says what happened and what to do. No raw exception text in the UI: map `PlatformException` and codes to the lines below and write the raw text to the audit log.

| State | Message | Action |
|---|---|---|
| Empty: no ID yet | "Go online to get your device ID." | "Go online" |
| Empty: no saved devices | "No devices yet. Enter an ID above and tap Save device to keep it here." | none |
| Empty: no trusted devices | "No trusted devices. Trusted devices can connect without a prompt after you approve them once." | none |
| Empty: audit log | "No activity yet. Connections and changes appear here." | none |
| Empty: TV | "No TVs found. Check that your TV is on and on the same Wi-Fi network." | "Search again" |
| Loading: going online | "Connecting to server..." (status chip "Connecting") | button disabled with spinner |
| Loading: requesting | "Waiting for the other device to accept..." | "Cancel" |
| Loading: checking updates | "Checking for updates..." | none |
| Reconnecting | "Connection lost. Reconnecting..." with elapsed seconds, over the video with 40% scrim | "Cancel" (existing) and "End session" |
| Reconnected | "Back online." snackbar 2s | none |
| Offline (device) | "You're offline. Check your internet connection." | "Try again" |
| Server unreachable | "Can't reach the server. Check the server address in Settings." | "Open settings" / "Try again" |
| ID invalid | "Enter all 12 digits of the device ID." | none |
| Peer not found | "That device isn't online. Check the ID and ask them to open Remote Link." | "Try again" |
| Request denied | "The other device declined your request." | "Try again" |
| Request timed out | "The other device didn't answer. Ask them to check their screen." | "Try again" |
| Wrong password | "Wrong password. Check it and try again." | "Try again" |
| Too many attempts | "Too many attempts. Wait a few minutes and try again." | none |
| Session ended | "Session ended." | none |
| Android accessibility off (target) | "Turn on Remote Link in Accessibility settings to allow control" | "Open settings" |
| View-only notice (controller) | "View only. The other device hasn't allowed control." (persistent chip in the pill) | none |
| View-only notice (target) | "Control is off, so this session is view only. Turn on Remote Link in Accessibility settings to allow control." | "Open settings" |
| Quality auto-lowered | "Quality lowered to keep the connection smooth." (snackbar 4s, then pill dot turns warning) | "Undo" if the preset can be re-applied, else none |
| Quality preset rejected | "This device can't use that quality. Using High quality instead." | none |
| Screen capture refused | "Screen sharing wasn't allowed, so the session can't start." | "Try again" |
| Update available | "Version 1.x is ready." | "Download" |
| Update failed | "Couldn't check for updates. Try again later." | "Try again" |
| Storage error | "Couldn't save this device. Try again." | "Try again" |
| Unexpected | "Something went wrong. Try again. If it keeps happening, check the activity log in Settings." | "Try again" |

Permission descriptions (Incoming request): Basic "View only. They can see your screen." / Normal "View and control. They can see and use your device." / Full "Full access. Includes admin-level actions and file transfer." Chips: "View", "Input", "Clipboard", "Files", "Audio", "Elevated".

Dialog button labels: "Accept", "Deny" (replaces "Allow" and "Decline" in the request sheet); "Receive" and "Decline" for files; "Cancel" and "Confirm full access" for elevated.

Offline behaviour: disable Connect and show the offline row; the saved list stays usable; Settings stays reachable; the audit log works offline.

## 7. Accessibility

Contrast (WCAG 2.2 AA; computed ratios are approximate, verify with a checker in a widget test):

| Pair | Dark | Light |
|---|---|---|
| text on bg | about 15:1 | about 15:1 |
| text on surface1/surface2 | at least 12:1 | at least 14:1 |
| textMuted on surface1 | about 6.8:1 | about 6.5:1 |
| accent on bg/surface1 | about 10:1 | about 5.5:1 (on white) |
| onAccent on accent | about 9:1 | about 5.5:1 |
| danger text on bg | about 5.4:1 | about 5.5:1 |
| white on dangerFill `#C53030` | about 5.5:1 | about 5.5:1 |
| success on bg | about 7.4:1 | about 5:1 |
| warning on bg | about 7:1 | about 5:1 |
| borderStrong (input outline, 3:1 non-text) | about 3.2:1 | about 4.5:1 |

Rules: do not put white text on `#F05252` (about 3.5:1); use `dangerFill`. Decorative `border` is exempt from 3:1; interactive outlines use `borderStrong`. Status is never color-only: always dot plus word or icon plus word.

Targets: 48dp minimum on Android and on touch, 44pt minimum iOS rule not needed (no iOS). Desktop controls 40px minimum height, 48 for primary buttons; toolbar pill buttons 48 on phone, 40 on desktop with 8 gaps.

Keyboard (desktop): full Tab order top to bottom, left pane then right pane; visible focus ring 2px accent with 2px offset on every focusable (chips, tiles, pill buttons); Enter submits Connect; Esc closes menus and sheets, and in a session shows the pill (never forwarded to the remote while the pill has focus); F11 toggles full screen; Ctrl+L focuses the ID field; Ctrl+, opens Settings. The incoming request dialog traps focus and starts on the first chip. Remote keyboard capture is scoped to the video widget only.

Screen reader: every icon button has a tooltip and `Semantics(label)`: "Copy device ID", "Share device ID", "Monitor picker", "Keys menu", "Trackpad mode, on/off", "Quality, current: Balanced", "Mute audio", "Send file", "End session". Device ID reads digit groups: `Semantics(label: '4 2 9, 8 1 9, 8 7 1, 0 1 6')`. Status chip and countdown use `liveRegion: true` (announce "Auto-deny in 10 seconds" at 30, 10 and 5 seconds only). Reconnecting overlay and errors are live regions. Toolbar pill auto-hide is disabled when a screen reader is on (`MediaQuery.accessibleNavigation`).

Text scaling: support up to 200%. Use `Wrap`, no fixed heights on text containers; the pill collapses extra items into "More" as width runs out; the ID uses `FittedBox(scaleDown)` on one line so it never wraps mid-group. Respect `disableAnimations` and `highContrast` (swap border to borderStrong).

## 8. Mapping to existing controls (inventory of `main.dart`)

| Existing | Where it goes |
|---|---|
| "This device" card, `deviceId`, `status` | Home: This device card |
| Android "Set up Android input" and Accessibility dialog, `openAccessibilitySettings` | Home warning row, Incoming/view-only notice button |
| Signaling URL field, "Go online"/"Disconnect" | Server URL in Settings; Go online/offline button on Home |
| "12-digit device ID" field, "Save device ID", saved-ID list | Connect field with formatting, Save device, saved devices grid |
| "Unattended password (optional)" in Connect | Collapsed "Have a password?" row in Connect; the setting itself in Settings |
| "Request access", "End session" | Connect; End session in pill |
| Error banner (`state.error`) | ErrorBanner with plain-language mapping |
| "Reconnecting..." with Cancel | Session overlay |
| "Allow this device?" dialog (screen picker, quality, Basic/Normal/Full, Decline, elevated confirm, Allow) | Incoming request sheet |
| "Receive file?" dialog | Same style dialog |
| "Trust this device?" dialog | Same style dialog |
| Monitor dropdown, quality presets | Pill: monitor picker, quality menu |
| Offer file, Send clipboard text | Pill: Files menu |
| Ctrl/Alt/Win chips, Esc/Tab/Enter/Backspace/arrows, Ctrl+Alt+Del, More keys, type-text field + send | Pill keys menu; phone bottom keys bar |
| Mute remote audio, Trackpad mode switches | Pill audio and input-mode toggles |
| "Open direct IP controls", "Open TV controls" | Home rows and Settings |
| "Local audit" list | Settings: Activity log |
| AppBar "Remote Link" | App bar |

## 9. Constraints and open items

- Platforms: Windows and Android only. Linux/macOS deferred.
- Not in this spec (no existing feature): custom device names or rename, last-seen times unless already stored, remove-from-recents unless it exists, session recording, chat.
- Needs a developer decision during build: whether `state` exposes latency, accessibility-enabled flag (bug B adds `isAccessibilityEnabled`), and a request timeout for the countdown. Omit the element if not available.
- Visual QA needed on a real phone (landscape pill overflow) and a Windows machine at 125% and 150% scaling.
- Open from before: TV hardware compatibility matrix; production Cloudflare spend controls; signing certificates and secure-desktop helper review.
