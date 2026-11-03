//! Service (session 0, LocalSystem):
//! - launches `remote_link.exe` (sibling of this exe) as the console user, and
//!   `remote_link-service.exe helper` as SYSTEM in the console session (can open the
//!   Winlogon/secure desktop); relaunches both on console connect / logon.
//! - serves PIPE for exactly the app process it launched; `send_sas` runs here,
//!   `switch_desktop_input` events are forwarded to the helper over its stdin.
//! SendSAS needs policy HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
//!   SoftwareSASGeneration (DWORD) = 1 (services) or 3; unset/0 makes send_sas a silent no-op.
use crate::protocol::{self, Button, InputEvent, Request};
use std::{ffi::c_void, mem::{size_of, size_of_val, zeroed}, path::Path, ptr::{null, null_mut}, sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock}, time::Duration};
use windows_sys::core::PWSTR;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authentication::Identity::SendSAS, Authorization::*, *},
    Storage::FileSystem::*,
    System::{Environment::*, Pipes::*, Registry::*, RemoteDesktop::*, Services::*, StationsAndDesktops::*, Threading::*},
    UI::{Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};

const NAME: &str = "RemoteLinkService";
const PIPE: &str = r"\\.\pipe\remote_link-service";
const APP_EXE: &str = "remote_link.exe";

fn w(s: &str) -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() }
fn last(what: &str) -> String { format!("{what} failed: {}", unsafe { GetLastError() }) }

struct Handle(HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle { fn drop(&mut self) { if !self.0.is_null() { unsafe { CloseHandle(self.0) }; } } }
struct Sc(SC_HANDLE);
impl Drop for Sc { fn drop(&mut self) { if !self.0.is_null() { unsafe { CloseServiceHandle(self.0) }; } } }

struct Launched { helper: Option<Handle>, helper_stdin: Option<Arc<Handle>>, app: Option<Handle>, app_pid: u32 }
static STATE: Mutex<Launched> = Mutex::new(Launched { helper: None, helper_stdin: None, app: None, app_pid: 0 });
static EVENTS: OnceLock<Mutex<mpsc::Sender<bool>>> = OnceLock::new(); // true = stop, false = session change
static STATUS: OnceLock<usize> = OnceLock::new();

fn state() -> MutexGuard<'static, Launched> { STATE.lock().unwrap_or_else(|e| e.into_inner()) }

pub fn main() -> i32 {
    let result = match std::env::args().nth(1).as_deref() {
        Some("install") => install(),
        Some("uninstall") => uninstall(),
        Some("stop") => stop(),
        Some("run") => run(),
        Some("helper") => helper(),
        _ => Err("usage: remote_link-service install|uninstall|stop".into()),
    };
    match result { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } }
}

fn install() -> Result<(), String> {
    // canonicalize = GetFinalPathNameByHandleW: junctions/symlinks resolved before checking.
    let exe = std::env::current_exe().and_then(std::fs::canonicalize).map_err(|e| e.to_string())?;
    let exe = match exe.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(s) if !s.starts_with("UNC\\") && win32_stable(s) => std::path::PathBuf::from(s),
        _ => return Err("install from a plain local path (UNC, non-UTF-8 and names ending in '.' or ' ' are refused)".into()),
    };
    // The stripped path is re-parsed by Win32 (and by the SCM at start): it must resolve to the same file.
    if std::fs::canonicalize(&exe).map_err(|e| e.to_string())?.to_str().and_then(|s| s.strip_prefix(r"\\?\")) != exe.to_str() {
        return Err("install path changes under Win32 normalization".into());
    }
    // The service runs this folder's binaries as SYSTEM: refuse folders non-admins can write.
    unsafe {
        let dir = exe.parent().ok_or("no install folder")?;
        check_acl(dir, false)?;
        check_acl(&exe, false)?;
        for p in ancestors_of(dir) { check_acl(p, true)?; }
    }
    let cmd = w(&format!("\"{}\" run", exe.display()));
    unsafe {
        let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_CREATE_SERVICE));
        if scm.0.is_null() { return Err(last("OpenSCManager")); }
        let mut svc = Sc(CreateServiceW(scm.0, w(NAME).as_ptr(), w("RemoteLink Service").as_ptr(), SERVICE_START,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.as_ptr(), null(), null_mut(), null(), null(), null()));
        if svc.0.is_null() && GetLastError() == ERROR_SERVICE_EXISTS {
            svc = Sc(OpenServiceW(scm.0, w(NAME).as_ptr(), SERVICE_CHANGE_CONFIG | SERVICE_START));
            if svc.0.is_null() { return Err(last("OpenService")); }
            if ChangeServiceConfigW(svc.0, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.as_ptr(),
                null(), null_mut(), null(), null(), null(), null()) == 0 { return Err(last("ChangeServiceConfig")); }
        }
        if svc.0.is_null() { return Err(last("CreateService")); }
        if StartServiceW(svc.0, 0, null()) == 0 && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING { return Err(last("StartService")); }
    }
    Ok(())
}

const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Allowlist: only SYSTEM, Administrators and TrustedInstaller (plus CREATOR OWNER on
/// inherit-only ACEs) may hold write rights; `owner` ids must be SYSTEM/Administrators/TrustedInstaller.
fn sid_may_write(sid: &str, inherit_only: bool) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544") || sid == TRUSTED_INSTALLER || (inherit_only && sid == "S-1-3-0")
}
fn sid_may_own(sid: &str) -> bool { sid_may_write(sid, false) }

/// Every folder above `dir`, nearest first, up to the drive root.
fn ancestors_of(dir: &Path) -> Vec<&Path> { dir.ancestors().skip(1).collect() }

/// False if Win32 path parsing would rewrite `path` (a name ending in '.' or ' ', or a '.'/'..' component).
fn win32_stable(path: &str) -> bool {
    path.split('\\').skip(1).all(|c| !c.is_empty() && !c.ends_with('.') && !c.ends_with(' '))
}

unsafe fn sid_string(sid: PSID) -> Result<String, String> {
    let mut s: PWSTR = null_mut();
    if ConvertSidToStringSidW(sid, &mut s) == 0 { return Err(last("ConvertSidToStringSid")); }
    let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, (0..).take_while(|&i| *s.add(i) != 0).count()));
    LocalFree(s as HLOCAL);
    Ok(out)
}

/// Fails if the owner of `path` or any ACCESS_ALLOWED ACE (inherit-only included, it applies to
/// the files inside) grants write/delete/re-ACL to a SID outside the allowlist. For the parent
/// folder (`parent`) only rename/delete/re-ACL rights on non-inherit-only ACEs matter.
/// shortcut: deny ACEs are not evaluated; allow ACEs for other SIDs are rejected even if a deny cancels them.
unsafe fn check_acl(path: &Path, parent: bool) -> Result<(), String> {
    const WRITE: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
    const PARENT_WRITE: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
    let (mut dacl, mut sd, mut owner): (*mut ACL, PSECURITY_DESCRIPTOR, PSID) = (null_mut(), null_mut(), null_mut());
    let err = GetNamedSecurityInfoW(w(&path.to_string_lossy()).as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        &mut owner, null_mut(), &mut dacl, null_mut(), &mut sd);
    if err != 0 { return Err(format!("GetNamedSecurityInfo failed: {err}")); }
    let result = (|| {
        if dacl.is_null() { return Err(format!("{} has no DACL", path.display())); }
        if owner.is_null() { return Err(format!("{} has no owner", path.display())); }
        let o = sid_string(owner)?;
        if !sid_may_own(&o) { return Err(format!("{} is owned by {o}; install into Program Files", path.display())); }
        for i in 0..(*dacl).AceCount as u32 {
            let mut ace = null_mut();
            if GetAce(dacl, i, &mut ace) == 0 { return Err(last("GetAce")); }
            let hdr = &*(ace as *const ACE_HEADER);
            if hdr.AceType != 0 { continue; } // 0 = ACCESS_ALLOWED_ACE_TYPE
            let inherit_only = hdr.AceFlags & INHERIT_ONLY_ACE as u8 != 0;
            if parent && inherit_only { continue; }
            let ace = &*(ace as *const ACCESS_ALLOWED_ACE);
            if ace.Mask & if parent { PARENT_WRITE } else { WRITE } == 0 { continue; }
            let sid = sid_string(&ace.SidStart as *const u32 as PSID)?;
            if !sid_may_write(&sid, inherit_only) {
                return Err(format!("{} is writable by {sid}; install into Program Files", path.display()));
            }
        }
        Ok(())
    })();
    LocalFree(sd as HLOCAL);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ancestors_reach_drive_root() {
        let a = ancestors_of(Path::new(r"C:\Program Files\RemoteLink"));
        assert_eq!(a, [Path::new(r"C:\Program Files"), Path::new(r"C:\")]);
        assert!(ancestors_of(Path::new(r"C:\")).is_empty());
    }
    #[test]
    fn win32_stable_paths() {
        assert!(win32_stable(r"C:\Program Files\RemoteLink\remote_link-service.exe"));
        for bad in [r"C:\Evil.\svc.exe", r"C:\Evil \svc.exe", r"C:\a\..\svc.exe", r"C:\a\\svc.exe"] {
            assert!(!win32_stable(bad), "{bad}");
        }
    }
    #[test]
    fn sid_allowlist() {
        for s in ["S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER] { assert!(sid_may_write(s, false) && sid_may_own(s)); }
        assert!(sid_may_write("S-1-3-0", true));
        assert!(!sid_may_write("S-1-3-0", false) && !sid_may_own("S-1-3-0"));
        for s in ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-32-547", "S-1-5-21-1-2-3-1001"] {
            assert!(!sid_may_write(s, false) && !sid_may_write(s, true) && !sid_may_own(s));
        }
    }
}

/// Stops the service and waits (max 30 s) for STOPPED so installers can replace files.
unsafe fn stop_and_wait(svc: SC_HANDLE) {
    let mut status: SERVICE_STATUS = zeroed();
    ControlService(svc, SERVICE_CONTROL_STOP, &mut status); // may already be stopped
    for _ in 0..300 {
        if QueryServiceStatus(svc, &mut status) == 0 || status.dwCurrentState == SERVICE_STOPPED { return; }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn open_existing(access: u32) -> Result<Option<Sc>, String> {
    unsafe {
        let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT));
        if scm.0.is_null() { return Err(last("OpenSCManager")); }
        let svc = Sc(OpenServiceW(scm.0, w(NAME).as_ptr(), access));
        if !svc.0.is_null() { Ok(Some(svc)) } else if GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST { Ok(None) } else { Err(last("OpenService")) }
    }
}

fn stop() -> Result<(), String> {
    if let Some(svc) = open_existing(SERVICE_STOP | SERVICE_QUERY_STATUS)? { unsafe { stop_and_wait(svc.0) }; }
    Ok(())
}

fn uninstall() -> Result<(), String> {
    let Some(svc) = open_existing(SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)? else { return Ok(()) };
    unsafe {
        stop_and_wait(svc.0);
        if DeleteService(svc.0) == 0 { return Err(last("DeleteService")); }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let mut name = w(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 { return Err(last("StartServiceCtrlDispatcher")); }
    Ok(())
}

fn set_status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32) {
    let Some(&handle) = STATUS.get() else { return };
    let mut s: SERVICE_STATUS = unsafe { zeroed() };
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwWin32ExitCode = exit_code;
    if state == SERVICE_RUNNING { s.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE; }
    unsafe { SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &s) };
}

unsafe extern "system" fn service_main(_: u32, _: *mut PWSTR) {
    let (tx, rx) = mpsc::channel();
    let _ = EVENTS.set(Mutex::new(tx));
    let handle = RegisterServiceCtrlHandlerExW(w(NAME).as_ptr(), Some(control_handler), null());
    if handle.is_null() { return; }
    let _ = STATUS.set(handle as usize);
    let pipe = match create_pipe() { Ok(p) => p, Err(code) => return set_status(SERVICE_STOPPED, code) };
    set_status(SERVICE_RUNNING, 0);
    relaunch();
    std::thread::spawn(move || pipe_server(pipe));
    while let Ok(false) = rx.recv() { relaunch(); }
    let helper = { let mut st = state(); st.helper_stdin = None; st.helper.take() }; // EOF makes the helper exit
    if let Some(h) = helper { WaitForSingleObject(h.0, 5000); } // release the exe file before STOPPED
    set_status(SERVICE_STOPPED, 0);
}

unsafe extern "system" fn control_handler(control: u32, event: u32, data: *mut c_void, _: *mut c_void) -> u32 {
    let send = |stop| if let Some(tx) = EVENTS.get() { let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send(stop); };
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => { set_status(SERVICE_STOP_PENDING, 0); send(true) }
        // Only console changes; an RDP logon must not restart the console user's app.
        SERVICE_CONTROL_SESSIONCHANGE => if (event == WTS_CONSOLE_CONNECT || event == WTS_SESSION_LOGON)
            && (*(data as *const WTSSESSION_NOTIFICATION)).dwSessionId == WTSGetActiveConsoleSessionId() { send(false) },
        SERVICE_CONTROL_INTERROGATE => {}
        _ => return ERROR_CALL_NOT_IMPLEMENTED,
    }
    NO_ERROR
}

fn relaunch() {
    let mut st = state();
    if let Some(app) = st.app.take() { unsafe { TerminateProcess(app.0, 0) }; }
    st.helper = None;
    st.helper_stdin = None;
    st.app_pid = 0;
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX { return; } // no console session (switching)
    let Ok(exe) = std::env::current_exe() else { return };
    if let Ok((process, stdin)) = unsafe { launch_helper(&exe, session) } {
        st.helper = Some(process);
        st.helper_stdin = Some(Arc::new(stdin));
    }
    // Fails with no logged-on user (login screen): nothing runs as the user then.
    if let Ok((app, pid)) = unsafe { launch_app(&exe.with_file_name(APP_EXE), session) } {
        st.app = Some(app);
        st.app_pid = pid; // we hold the process handle, so this PID cannot be reused
    }
}

unsafe fn spawn(token: HANDLE, exe: &Path, args: &str, env: *const c_void, stdin: HANDLE) -> Result<PROCESS_INFORMATION, String> {
    let mut desktop = w("winsta0\\default");
    let mut si: STARTUPINFOW = zeroed();
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = desktop.as_mut_ptr();
    if !stdin.is_null() { si.dwFlags = STARTF_USESTDHANDLES; si.hStdInput = stdin; }
    let app = w(&exe.to_string_lossy());
    let mut cmd = w(&format!("\"{}\" {args}", exe.display()));
    let mut pi: PROCESS_INFORMATION = zeroed();
    if CreateProcessAsUserW(token, app.as_ptr(), cmd.as_mut_ptr(), null(), null(), (!stdin.is_null()) as i32,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, env, null(), &si, &mut pi) == 0 {
        return Err(last("CreateProcessAsUser"));
    }
    CloseHandle(pi.hThread);
    Ok(pi)
}

/// SYSTEM token moved into `session` (needs SeTcbPrivilege, which LocalSystem has).
unsafe fn launch_helper(exe: &Path, session: u32) -> Result<(Handle, Handle), String> {
    let mut own = null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &mut own) == 0 { return Err(last("OpenProcessToken")); }
    let own = Handle(own);
    let mut token = null_mut();
    if DuplicateTokenEx(own.0, TOKEN_ALL_ACCESS, null(), SecurityImpersonation, TokenPrimary, &mut token) == 0 { return Err(last("DuplicateTokenEx")); }
    let token = Handle(token);
    if SetTokenInformation(token.0, TokenSessionId, &session as *const u32 as *const c_void, 4) == 0 { return Err(last("SetTokenInformation")); }
    let (mut read, mut write) = (null_mut(), null_mut());
    if CreatePipe(&mut read, &mut write, null(), 0) == 0 { return Err(last("CreatePipe")); }
    let (read, write) = (Handle(read), Handle(write));
    // Only the read end is inheritable; the service creates no other inheritable handles.
    if SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) == 0 { return Err(last("SetHandleInformation")); }
    let pi = spawn(token.0, exe, "helper", null(), read.0)?;
    Ok((Handle(pi.hProcess), write))
}

unsafe fn launch_app(exe: &Path, session: u32) -> Result<(Handle, u32), String> {
    let mut token = null_mut();
    if WTSQueryUserToken(session, &mut token) == 0 { return Err(last("WTSQueryUserToken")); }
    let token = Handle(token);
    let mut env = null_mut();
    if CreateEnvironmentBlock(&mut env, token.0, 0) == 0 { return Err(last("CreateEnvironmentBlock")); }
    let result = spawn(token.0, exe, "", env, null_mut());
    DestroyEnvironmentBlock(env);
    let pi = result?;
    Ok((Handle(pi.hProcess), pi.dwProcessId))
}

/// Single pipe instance. DACL: SYSTEM full; INTERACTIVE read/write without
/// FILE_CREATE_PIPE_INSTANCE (0x12019B); medium no-write-up label. Each connection is
/// further restricted to the exact app process the service launched. Remote clients rejected.
/// FIRST_PIPE_INSTANCE makes start fail if someone squatted the name.
unsafe fn create_pipe() -> Result<usize, u32> {
    let mut sd = null_mut();
    if ConvertStringSecurityDescriptorToSecurityDescriptorW(w("D:P(A;;GA;;;SY)(A;;0x0012019B;;;IU)S:(ML;;NW;;;ME)").as_ptr(),
        SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
        return Err(GetLastError());
    }
    let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    let size = protocol::MAX_MESSAGE as u32;
    let pipe = CreateNamedPipeW(w(PIPE).as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, size, size, 0, &sa);
    LocalFree(sd as HLOCAL);
    if pipe == INVALID_HANDLE_VALUE { Err(GetLastError()) } else { Ok(pipe as usize) }
}

fn pipe_server(pipe: usize) {
    let pipe = pipe as HANDLE;
    loop {
        unsafe {
            if ConnectNamedPipe(pipe, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED { serve(pipe); }
            else { std::thread::sleep(Duration::from_millis(100)); } // back off on unexpected errors
            DisconnectNamedPipe(pipe);
        }
    }
}

fn is_app(pid: u32) -> bool { pid != 0 && pid == state().app_pid }

/// shortcut: no read timeout (needs overlapped I/O); only the launched app gets past the
/// PID check, so only it can hold the single instance.
unsafe fn serve(pipe: HANDLE) {
    let mut pid = 0;
    // Unauthorized clients are disconnected before anything is read.
    if GetNamedPipeClientProcessId(pipe, &mut pid) == 0 || !is_app(pid) { return; }
    let mut buf = [0u8; protocol::MAX_MESSAGE];
    loop {
        let mut n = 0;
        // Oversized messages fail with ERROR_MORE_DATA and drop the connection.
        if ReadFile(pipe, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) == 0 || !is_app(pid) { return; }
        let out = protocol::reply(&protocol::parse(&buf[..n as usize]).and_then(handle));
        let mut written = 0;
        if WriteFile(pipe, out.as_ptr(), out.len() as u32, &mut written, null_mut()) == 0 { return; }
    }
}

/// Admin-only opt-in (HKLM\SOFTWARE\RemoteLink\Service AllowSecureDesktopInput = 1), read on
/// every request. SECURITY RISK when enabled: the PID gate is no boundary against other code
/// running as the console user, so such code can drive SYSTEM SendInput on the secure desktop,
/// e.g. click "Yes" on a UAC consent prompt (UAC bypass) or type on the lock screen.
fn secure_input_allowed() -> bool {
    let (mut value, mut size) = (0u32, 4u32);
    unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE, w(r"SOFTWARE\RemoteLink\Service").as_ptr(), w("AllowSecureDesktopInput").as_ptr(),
            RRF_RT_REG_DWORD, null_mut(), &mut value as *mut u32 as *mut c_void, &mut size) == ERROR_SUCCESS && value == 1
    }
}

fn handle(req: Request) -> Result<(), String> {
    match req {
        // Needs SoftwareSASGeneration policy (see module doc).
        Request::SendSas {} => { unsafe { SendSAS(0) }; Ok(()) }
        Request::SwitchDesktopInput { event } => {
            if !secure_input_allowed() { return Err("secure desktop input disabled by administrator policy".into()); }
            let stdin = state().helper_stdin.clone().ok_or("helper not running")?; // lock released before the write
            let line = serde_json::to_string(&event).map_err(|e| e.to_string())? + "\n";
            let mut written = 0;
            if unsafe { WriteFile(stdin.0, line.as_ptr(), line.len() as u32, &mut written, null_mut()) } == 0 { return Err("helper unavailable".into()); }
            Ok(())
        }
    }
}

unsafe fn desktop_name(desk: HDESK) -> String {
    let mut buf = [0u16; 64];
    let mut needed = 0;
    if GetUserObjectInformationW(desk as HANDLE, UOI_NAME, buf.as_mut_ptr() as *mut c_void, size_of_val(&buf) as u32, &mut needed) == 0 { return String::new(); }
    String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)])
}

/// Runs as SYSTEM in the console session. Reads newline-delimited InputEvents from
/// stdin (only the service holds the write end) and injects them only while the input
/// desktop is Winlogon (lock/login screen, UAC prompt); anything else is dropped, since
/// the user's own desktop is handled by the app itself.
fn helper() -> Result<(), String> {
    let mut current: HDESK = null_mut();
    for line in std::io::stdin().lines() {
        let Ok(line) = line else { break };
        let Ok(event) = serde_json::from_str::<InputEvent>(&line) else { continue };
        if event.validate().is_err() { continue; }
        unsafe {
            let input = OpenInputDesktop(0, 0, GENERIC_ALL);
            if input.is_null() { continue; }
            if !desktop_name(input).eq_ignore_ascii_case("Winlogon") || SetThreadDesktop(input) == 0 { CloseDesktop(input); continue; }
            if !current.is_null() { CloseDesktop(current); }
            current = input;
            let _ = inject(&event);
        }
    }
    Ok(())
}

unsafe fn inject(event: &InputEvent) -> Result<(), ()> {
    // Same guard as remote_core: presses need a single-display topology for coordinate mapping.
    let press = !matches!(event, InputEvent::MouseBtn { down: false, .. } | InputEvent::Key { down: false, .. });
    if press && GetSystemMetrics(SM_CMONITORS) != 1 { return Err(()); }
    let input = match event {
        InputEvent::Key { code, down } => {
            let (vk, extended) = protocol::key_vk(code).ok_or(())?;
            let flags = if *down { 0 } else { KEYEVENTF_KEYUP } | if extended { KEYEVENTF_EXTENDEDKEY } else { 0 };
            INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
        }
        _ => {
            let mut mouse: MOUSEINPUT = zeroed();
            match *event {
                InputEvent::MouseMove { x, y } => {
                    mouse.dx = (x * 65535.0).round() as i32;
                    mouse.dy = (y * 65535.0).round() as i32;
                    mouse.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
                }
                InputEvent::Wheel { dy } => { mouse.dwFlags = MOUSEEVENTF_WHEEL; mouse.mouseData = dy as u32; }
                InputEvent::MouseBtn { b, down } => mouse.dwFlags = match (b, down) {
                    (Button::Left, true) => MOUSEEVENTF_LEFTDOWN, (Button::Left, false) => MOUSEEVENTF_LEFTUP,
                    (Button::Right, true) => MOUSEEVENTF_RIGHTDOWN, (Button::Right, false) => MOUSEEVENTF_RIGHTUP,
                    (Button::Middle, true) => MOUSEEVENTF_MIDDLEDOWN, (Button::Middle, false) => MOUSEEVENTF_MIDDLEUP,
                },
                InputEvent::Key { .. } => unreachable!(),
            }
            INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: mouse } }
        }
    };
    if SendInput(1, &input, size_of::<INPUT>() as i32) == 1 { Ok(()) } else { Err(()) }
}
