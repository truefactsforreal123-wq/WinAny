; Build: iscc /DAppVersion=0.1.0 /DSourceDir=<flutter windows release dir> installer.iss
; SourceDir must contain remote_link.exe, remote_core.dll (installed there by Flutter CMake) and,
; optionally, remote_link-service.exe (built by core/service).
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\apps\flutter_app\build\windows\x64\runner\Release"
#endif
#define AppName "RemoteLink"
#define AppExe "remote_link.exe"
#define SvcExe "remote_link-service.exe"

[Setup]
AppId={{8F1D2B7A-4C3E-4B6A-9E55-1A2B3C4D5E6F}
AppName={#AppName}
AppVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
; Fixed admin-only folder: the service runs binaries from {app} as SYSTEM.
DisableDirPage=yes
DefaultGroupName={#AppName}
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=RemoteLink-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\{#AppExe}
; Signing placeholder (no certs in repo): define a sign tool named "signtool" via
;   iscc /Ssigntool="signtool sign /f %SIGN_PFX% /p %SIGN_PASSWORD% /tr http://timestamp.digicert.com /td sha256 /fd sha256 $f"
; then uncomment:
; SignTool=signtool

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "service"; Description: "Install unattended-access service (login screen / UAC support)"; Flags: unchecked
; SECURITY RISK: lets any program running as the logged-on user click through UAC prompts via the SYSTEM helper.
Name: "service\secureinput"; Description: "Allow remote control of UAC/lock screen (security risk)"; Flags: unchecked

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Needed so the service can send Ctrl+Alt+Del (SendSAS). 1 = services only.
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; ValueType: dword; ValueName: "SoftwareSASGeneration"; ValueData: "1"; Flags: uninsdeletevalue createvalueifdoesntexist; Tasks: service
; Read by the service on every switch_desktop_input request; 0 (or absent) disables it.
Root: HKLM64; Subkey: "SOFTWARE\RemoteLink\Service"; ValueType: dword; ValueName: "AllowSecureDesktopInput"; ValueData: "1"; Flags: uninsdeletekey; Tasks: service\secureinput
Root: HKLM64; Subkey: "SOFTWARE\RemoteLink\Service"; ValueType: dword; ValueName: "AllowSecureDesktopInput"; ValueData: "0"; Flags: uninsdeletekey; Tasks: not service\secureinput

[Run]
Filename: "{app}\{#SvcExe}"; Parameters: "install"; Flags: runhidden; Tasks: service; Check: SvcPresent
Filename: "{app}\{#SvcExe}"; Parameters: "uninstall"; Flags: runhidden; Tasks: not service; Check: SvcPresent
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#SvcExe}"; Parameters: "uninstall"; Flags: runhidden; RunOnceId: "RemoveService"; Check: SvcPresent

[Code]
function SvcPresent: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\{#SvcExe}'));
end;

// Upgrade: stop the old service (waits for STOPPED) so its files can be replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Rc: Integer;
begin
  if SvcPresent then Exec(ExpandConstant('{app}\{#SvcExe}'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, Rc);
  Result := '';
end;
