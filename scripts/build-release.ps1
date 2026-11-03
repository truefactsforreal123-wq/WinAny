# Windows release: core + app + Inno Setup installer. The service exe (core/service) is optional.
[CmdletBinding()]
param([string]$Iscc = 'iscc')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pub = Get-Content (Join-Path $root 'apps/flutter_app/pubspec.yaml') -Raw
if ($pub -notmatch '(?m)^version:\s*([0-9.]+)') { throw 'version not found in pubspec.yaml' }
$ver = $Matches[1]
& cargo build --locked --release --manifest-path (Join-Path $root 'core/rust/Cargo.toml')
if ($LASTEXITCODE -ne 0) { throw 'core build failed' }
Push-Location (Join-Path $root 'apps/flutter_app')
try { & flutter build windows --release "--dart-define=APP_VERSION=$ver"; if ($LASTEXITCODE -ne 0) { throw 'flutter build failed' } } finally { Pop-Location }
$src = Join-Path $root 'apps/flutter_app/build/windows/x64/runner/Release'
$svc = Join-Path $root 'core/service/target/release/remote_link-service.exe'
if (Test-Path $svc) { Copy-Item $svc $src -Force } else { Write-Warning 'remote_link-service.exe not found; service option will be a no-op.' }
& $Iscc "/DAppVersion=$ver" "/DSourceDir=$src" (Join-Path $root 'packaging/windows/installer.iss')
if ($LASTEXITCODE -ne 0) { throw 'iscc failed' }
Write-Host "Installer in $(Join-Path $root 'dist')"
