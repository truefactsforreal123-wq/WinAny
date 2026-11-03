[CmdletBinding()]
param([switch]$Full)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Invoke-Check([string]$Name, [scriptblock]$Command) {
    Write-Host "`n== $Name =="
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Name failed ($LASTEXITCODE)" }
}
Push-Location $root
try {
    Invoke-Check 'Rust locked tests' { cargo test --locked --offline --manifest-path core/rust/Cargo.toml }
    Invoke-Check 'Rust locked check' { cargo check --locked --offline --manifest-path core/rust/Cargo.toml }
    Invoke-Check 'Signaling tests' { node --test server/test/signaling.test.mjs }
    if ($Full) {
        Push-Location server
        try { Invoke-Check 'Worker production typecheck' { npm.cmd run typecheck } } finally { Pop-Location }
        Invoke-Check 'Rust formatting' { cargo fmt --manifest-path core/rust/Cargo.toml --check }
        Invoke-Check 'Rust Clippy' { cargo clippy --locked --manifest-path core/rust/Cargo.toml -- -D warnings }
        Push-Location apps/flutter_app
        try {
            Invoke-Check 'Flutter dependencies' { flutter pub get }
            Invoke-Check 'Flutter analyzer' { flutter analyze }
            Invoke-Check 'Flutter tests' { flutter test }
        } finally { Pop-Location }
    }
} finally { Pop-Location }
