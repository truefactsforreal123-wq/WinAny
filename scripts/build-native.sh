#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-linux}" in
  linux) cargo build --locked --release --manifest-path "$root/core/rust/Cargo.toml" ;;
  android) cargo ndk -t arm64-v8a -t x86_64 -o "$root/apps/flutter_app/android/app/src/main/jniLibs" build --locked --release --manifest-path "$root/core/rust/Cargo.toml" ;;
  *) echo "Usage: $0 [linux|android]" >&2; exit 2 ;;
esac
