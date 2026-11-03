#!/usr/bin/env bash
# Linux release: core + app + AppImage + .deb. Usage: scripts/build-release.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(sed -n 's/^version: *\([0-9.]*\).*/\1/p' "$ROOT/apps/flutter_app/pubspec.yaml" | head -1)"
cargo build --locked --release --manifest-path "$ROOT/core/rust/Cargo.toml"
(cd "$ROOT/apps/flutter_app" && flutter build linux --release)
bash "$ROOT/packaging/linux/build-appimage.sh" "$VER"
bash "$ROOT/packaging/linux/build-deb.sh" "$VER"
echo "Artifacts in $ROOT/dist"
