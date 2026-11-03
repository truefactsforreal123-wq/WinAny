# Builds libremote_core.so for Android ABIs into the Flutter app's jniLibs.
# Needs: cargo install cargo-ndk; rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; Android NDK.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $env:ANDROID_NDK_HOME) {
    $ndk = Get-ChildItem "$env:LOCALAPPDATA\Android\sdk\ndk" -Directory | Sort-Object Name | Select-Object -Last 1
    if (-not $ndk) { throw 'Android NDK not found; set ANDROID_NDK_HOME' }
    $env:ANDROID_NDK_HOME = $ndk.FullName
}
cargo ndk --version | Out-Null
if ($LASTEXITCODE) { throw 'cargo-ndk missing: cargo install cargo-ndk' }
Push-Location "$root\core\rust"
try {
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$root\apps\flutter_app\android\app\src\main\jniLibs" build --release
    if ($LASTEXITCODE) { throw 'cargo ndk build failed' }
} finally { Pop-Location }
