# Auto-update

Static JSON manifest hosted anywhere over HTTPS. One file per platform, e.g. `update-windows.json`.

```json
{ "version": "0.2.0", "platform": "windows",
  "url": "https://example.com/RemoteLink-Setup-0.2.0.exe",
  "sha256": "<64 lowercase hex of the installer file>",
  "signature": "<base64 Ed25519 signature>" }
```

Signature = Ed25519 over the bytes `UTF-8("remote-link-update-v1\0") || version || "\0" || platform || "\0" || 32 raw sha256 bytes`
(`version` and `platform` UTF-8, exactly as in the manifest), so they cannot be altered, made with the release private key
(never in repo; env `UPDATE_SIGNING_KEY` = PEM path). The matching 32-byte public key is compiled into the app.
Generate: `scripts/make-update-manifest.ps1 -File dist\RemoteLink-Setup-0.2.0.exe -Version 0.2.0 -Url <url>`.

## Client contract
1. GET the manifest over HTTPS. Stop if `version` (semver) is not greater than the running version (no downgrades).
2. Download `url` to a temp file.
3. Compute sha256 of the file; it must equal `sha256` (case-insensitive). Else delete and abort.
4. Verify `signature` (base64) as Ed25519 over the message above, rebuilt from the manifest `version`, `platform` and the computed sha256, with the embedded public key. Else delete and abort.
5. Only after both pass, run the installer (`/SILENT` on Windows; on Linux prompt the user for the .deb or AppImage). Any failure leaves the current install untouched.
6. A missing or empty `signature` is a failure.
