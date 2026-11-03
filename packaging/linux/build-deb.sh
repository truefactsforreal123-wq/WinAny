#!/usr/bin/env bash
# Usage: build-deb.sh <version>  (run after `flutter build linux --release`)
set -euo pipefail
VER="${1:?version}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUNDLE="$ROOT/apps/flutter_app/build/linux/x64/release/bundle"
PKG="$ROOT/dist/deb/remote-link_${VER}_amd64"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/remote-link" "$PKG/usr/bin" "$PKG/usr/share/applications"
cp -a "$BUNDLE/." "$PKG/opt/remote-link/"   # includes lib/libremote_core.so
ln -s /opt/remote-link/remote_link "$PKG/usr/bin/remote_link"
cp "$HERE/remote_link.desktop" "$PKG/usr/share/applications/"
cat > "$PKG/DEBIAN/control" <<CTL
Package: remote-link
Version: $VER
Section: net
Priority: optional
Architecture: amd64
Depends: libgtk-3-0, libpipewire-0.3-0, xdg-desktop-portal
Maintainer: RemoteLink <noreply@example.com>
Description: Consent-first remote access client
CTL
dpkg-deb --build --root-owner-group "$PKG" "$ROOT/dist/remote-link_${VER}_amd64.deb"
