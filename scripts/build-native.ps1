[CmdletBinding()]
param(
    [ValidateSet('windows', 'android')][string]$Platform = 'windows',
    [ValidateSet('debug', 'release')][string]$Profile = 'release'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'core/rust/Cargo.toml'
$profileArgs = @()
if ($Profile -eq 'release') { $profileArgs += '--release' }
if ($Platform -eq 'windows') {
    & cargo build --locked --manifest-path $manifest @profileArgs
    if ($LASTEXITCODE -ne 0) { throw 'Native Windows build failed' }
    Write-Host "Built core/rust/target/$Profile/remote_core.dll. Flutter CMake also builds and installs this library."
} else {
    # cargo-ndk and the requested Rust targets must be installed by the developer.
    # No SDK or Rust installation is modified by this script.
    $output = Join-Path $root 'apps/flutter_app/android/app/src/main/jniLibs'
    & cargo ndk -t arm64-v8a -t x86_64 -o $output build --locked --manifest-path $manifest @profileArgs
    if ($LASTEXITCODE -ne 0) { throw 'Android native build failed. Install cargo-ndk, Android NDK and aarch64-linux-android/x86_64-linux-android targets first.' }
    Write-Host "Packaged Android libraries in $output"
}
