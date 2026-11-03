# Usage: make-update-manifest.ps1 -File <installer> -Version 0.1.0 -Url https://host/RemoteLink-Setup-0.1.0.exe
#        [-Platform windows] [-PrivateKeyFile ed25519.pem (needs openssl 3)] [-Out update.json]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$File,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Url,
    [string]$Platform = 'windows',
    [string]$PrivateKeyFile = $env:UPDATE_SIGNING_KEY,
    [string]$Out = 'update.json'
)
$ErrorActionPreference = 'Stop'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLower()
$sig = ''
if ($PrivateKeyFile) {
    # Signs the 32 raw sha256 bytes; signature stored base64.
    $tmp = (New-TemporaryFile).FullName
    try {
        $bytes = [byte[]]::new(32)
        for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($sha.Substring(2 * $i, 2), 16) }
        [IO.File]::WriteAllBytes($tmp, $bytes)
        & openssl pkeyutl -sign -inkey $PrivateKeyFile -rawin -in $tmp -out "$tmp.sig"
        if ($LASTEXITCODE -ne 0) { throw 'openssl signing failed' }
        $sig = [Convert]::ToBase64String([IO.File]::ReadAllBytes("$tmp.sig"))
    } finally { Remove-Item $tmp, "$tmp.sig" -ErrorAction SilentlyContinue }
} else { Write-Warning 'No signing key: signature left empty (clients must reject).' }
[ordered]@{ version = $Version; platform = $Platform; url = $Url; sha256 = $sha; signature = $sig } |
    ConvertTo-Json | Set-Content -Encoding utf8 $Out
Write-Host "Wrote $Out"
