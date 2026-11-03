# Design

## Source of truth
Status: Active. Date: 2026-11-03. Surfaces: Flutter Windows/Linux/Android controller and target, TV bridge. Evidence: `plan.md`; no existing code, assets, brand guide or screenshots. Visual decisions below are explicit implementation assumptions.

## Brand
Product name: Remote Link. Calm, technical and consent-first. Trust signals are local device identity, verified fingerprints, permission summaries and persistent session indicators. Avoid impersonating AnyDesk branding, invisible access or claims that unsupported device features work.

## Product goals
Connect two devices with an anonymous ID, local acceptance and visible control; provide safe file transfer and TV controls when supported. Success: understandable connection state and end-session action, target-enforced capabilities, clear failures. Non-goals: bypassing platform permission prompts, hiding sessions, promising universal TV capture or zero hosting cost.

## Personas and jobs
Device owners assisting family, controlling their own desktop from Android, or operating a TV through a trusted LAN bridge. Targets must understand who is requesting access and what it permits.

## Information architecture
Dashboard: local ID/status, connect form, saved devices. Session: video, input tools, permissions, quality, files and disconnect. Devices/TV: discovered or manually added devices, capabilities, pairing and remote. Settings: signaling URL, native capabilities, direct-IP warning, local security. Audit: local events.

## Design principles
Consent before capability. Target policy is authoritative. Make offline/unsupported states explicit. Keep disconnect prominent. Prefer progressive disclosure over dense technical forms.

## Visual language
Light neutral canvas, dark navy text, indigo primary actions, teal connected state, amber warnings and red disconnect. Material 3, system font, 8px spacing unit, 12–20px card radii. Icons from Material; no invented bitmap assets required. Minimal motion.

## Components
App shell/navigation rail or bottom bar; status badge; device identity card; connect form; incoming request dialog with Basic/Normal/Full selector and separate elevated confirmation; session banner; video canvas; toolbar; permission checklist; TV remote pad; capability badges; audit list. Theme and tokens live in Flutter app theme.

## Accessibility
Aim for WCAG 2.2 AA. Named controls, visible keyboard focus, no color-only status, selectable IDs, >=48px touch controls, sufficient contrast, scalable text. Capture/input is never activated by mere navigation. Keep remote keyboard handling scoped to the session canvas.

## Responsive behavior
Under 720px: stacked cards, bottom navigation, touch trackpad/direct input. At/above 720px: navigation rail and two-column dashboard. Session canvas fits without cropping by default. TV controls remain reachable on small phones.

## Interaction states
Show disconnected/connecting/authenticated/requesting/awaiting consent/negotiating/active/ended/error states. Never substitute demo video for real capture. Empty lists explain prerequisites. Unsupported operations remain disabled with reasons. Network errors offer retry without silently granting previous sessions.

## Content voice
Plain, direct language: “Allow this device?”, “View only”, “End session”, “Requires local permission”. Explain elevated permissions and relay cost risk at point of use. No fabricated success messages.

## Implementation constraints
Flutter + Riverpod + flutter_webrtc. Rust native bridge owns native operations and target permissions; signaling never grants input. SQLite/secure storage for persistent metadata/keys where supported. Android MediaProjection and Accessibility require explicit OS/user consent. Physical cross-platform and TV testing is required before a release claim. Unit/widget tests and analyzer precede delivery.

## Open questions
- [ ] Actual TV hardware/firmware compatibility; owner: release validation; impact: capability support matrix.
- [ ] Production Cloudflare account, hostname and spend controls; owner: deployment; impact: internet availability and relay cost.
- [ ] Signing certificates and secure-desktop helper security review; owner: release; impact: privileged service distribution.
