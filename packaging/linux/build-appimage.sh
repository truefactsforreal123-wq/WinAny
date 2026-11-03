#!/usr/bin/env bash
# Usage: build-appimage.sh <version>  (run after `flutter build linux --release`)
# Needs appimagetool on PATH and packaging/linux/remote_link.png (256x256 icon).
set -euo pipefail
VER="${1:?version}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUNDLE="$ROOT/apps/flutter_app/build/linux/x64/release/bundle"
APPDIR="$ROOT/dist/RemoteLink.AppDir"
rm -rf "$APPDIR"; mkdir -p "$APPDIR/usr/bin" "$ROOT/dist"
cp -a "$BUNDLE/." "$APPDIR/usr/bin/"   # includes lib/libremote_core.so installed by Flutter CMake
cp "$HERE/remote_link.desktop" "$APPDIR/"
cp "$HERE/remote_link.png" "$APPDIR/remote_link.png"
cat > "$APPDIR/AppRun" <<'RUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/remote_link" "$@"
RUN
chmod +x "$APPDIR/AppRun"
ARCH=x86_64 appimagetool "$APPDIR" "$ROOT/dist/RemoteLink-$VER-x86_64.AppImage"
