pub mod x11;
mod stream_hash;
pub mod auth;
pub mod tv;
use tv::TvAdapter;
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519}};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, ffi::{CStr, CString}, fs::{File, OpenOptions}, io::Write, os::raw::c_char, path::{Component, Path}, sync::{Mutex, OnceLock}};

const MAX_CHUNK: usize = 256 * 1024;
const MAX_FILE: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Permissions {
    pub view: bool, pub input: bool, pub clipboard_text: bool, pub clipboard_images: bool,
    pub clipboard_files: bool, pub file_transfer: bool, pub audio: bool, pub lock: bool,
    pub power: bool, pub elevated: bool, pub tv_keys: bool, pub tv_apps: bool, pub adb: bool,
}
impl Permissions {
    pub fn preset(name: &str) -> Result<Self, String> {
        let mut p = Self { view: true, audio: true, ..Self::default() };
        match name {
            "basic" => (),
            "normal" | "full" => { p.input=true; p.clipboard_text=true; p.clipboard_images=true; p.tv_keys=true; },
            _ => return Err("unknown preset".into()),
        }
        if name == "full" { p.clipboard_files=true; p.file_transfer=true; p.lock=true; p.power=true; p.elevated=true; p.tv_apps=true; p.adb=true; }
        Ok(p)
    }
    fn sensitive(&self) -> bool { self.clipboard_files || self.file_transfer || self.lock || self.power || self.elevated || self.adb }
    fn permits(&self, capability: &str) -> bool { match capability {
        "view"=>self.view, "input"=>self.input, "clipboard_text"=>self.clipboard_text,
        "clipboard_images"=>self.clipboard_images, "clipboard_files"=>self.clipboard_files,
        "file_transfer"=>self.file_transfer, "audio"=>self.audio, "lock"=>self.lock,
        "power"=>self.power, "elevated"=>self.elevated, "tv_keys"=>self.tv_keys,
        "tv_apps"=>self.tv_apps, "adb"=>self.adb, _=>false,
    }}
}
static CALL_LOCK: Mutex<()> = Mutex::new(());
static TRANSFERS: OnceLock<Mutex<HashMap<String, (String, FileReceiver)>>> = OnceLock::new();
fn transfers() -> &'static Mutex<HashMap<String, (String, FileReceiver)>> { TRANSFERS.get_or_init(|| Mutex::new(HashMap::new())) }
struct Session { permissions: Permissions, expires: std::time::Instant, held: HashMap<String, Value> }
static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
fn sessions() -> &'static Mutex<HashMap<String, Session>> { SESSIONS.get_or_init(|| Mutex::new(HashMap::new())) }
static EXPIRY_WORKER: OnceLock<Result<(),String>> = OnceLock::new();
fn start_expiry_worker()->Result<(),String> {
    EXPIRY_WORKER.get_or_init(|| std::thread::Builder::new().name("remote-session-expiry".into()).spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(_guard)=CALL_LOCK.lock() { expire_sessions(); }
    }).map(|_|()).map_err(|e|e.to_string())).clone()
}
fn release_session(session:Session)->usize {
    session.held.into_values().filter(|event|inject_input(event).is_err()).count()
}
fn expire_sessions() {
    let expired=if let Ok(mut map)=sessions().lock() {
        let ids:Vec<String>=map.iter().filter(|(_,s)|s.expires<=std::time::Instant::now()).map(|(id,_)|id.clone()).collect();
        ids.into_iter().filter_map(|id|map.remove(&id).map(|s|(id,s))).collect::<Vec<_>>()
    } else {return};
    for (id,session) in expired {release_session(session); if let Ok(mut map)=transfers().lock(){map.retain(|_,(owner,_)|owner!=&id);}}
}
static TRUST: std::sync::LazyLock<Mutex<auth::TrustedPolicies>> = std::sync::LazyLock::new(|| Mutex::new(auth::TrustedPolicies::default()));
/// Public key accepted as base64 or base64url (padded or not) and compared by decoded bytes; must be exactly 32 bytes.
fn key_bytes(v:&Value,key:&str)->Result<Vec<u8>,String> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let raw=required(v,key)?.trim_end_matches('='); if raw.len()!=43 {return Err(format!("invalid {key}"));}
    STANDARD_NO_PAD.decode(raw).or_else(|_|URL_SAFE_NO_PAD.decode(raw)).map_err(|_|format!("invalid {key}"))
}
/// Builds the v3 proof message from request fields (shared by sign/verify/password ops).
fn proof_msg(v:&Value)->Result<Vec<u8>,String> { auth::unattended_message(required(v,"purpose")?,required(v,"session_id")?,required(v,"target_id")?,required(v,"controller_id")?,&bytes(v,"nonce")?,required(v,"controller_dtls_fp")?,required(v,"target_dtls_fp")?) }
/// Verify ops accept only their own purpose, so an enroll proof never authenticates and vice versa.
fn purpose_msg(v:&Value,purpose:&str)->Result<Vec<u8>,String> { if required(v,"purpose")?!=purpose {return Err(format!("purpose must be {purpose}"));} proof_msg(v) }
fn record(v:&Value)->Result<auth::PasswordRecord,String> { serde_json::from_str(required(v,"record")?).map_err(|_|"invalid password record".into()) }
/// Preset or custom permissions; full/sensitive grants need explicit elevated confirmation.
fn confirmed_permissions(v:&Value)->Result<Permissions,String> {
    let name=required(v,"preset")?;
    let p=if name=="custom" {serde_json::from_value::<Permissions>(v.get("permissions").cloned().ok_or("permissions required")?).map_err(|e|e.to_string())?} else {Permissions::preset(name)?};
    if (name=="full" || p.sensitive()) && v.get("elevated_confirmed").and_then(Value::as_bool)!=Some(true) {return Err("explicit elevated confirmation required".into());}
    Ok(p)
}
/// Secure attention (Ctrl+Alt+Del) is a sensitive grant, so it needs "elevated" rather than plain "input".
fn input_capability(event:&Value)->&'static str { if event["t"]=="secure_attention" {"elevated"} else {"input"} }
fn input_identity(event:&Value)->Option<String> {
    match event["t"].as_str() {Some("key")=>event["code"].as_str().map(|v|format!("key:{v}")),Some("mouse_btn")=>event["b"].as_str().map(|v|format!("mouse:{v}")),_=>None}
}
fn required<'a>(v: &'a Value, key: &str) -> Result<&'a str,String> { v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| format!("missing {key}")) }
fn bytes(v: &Value, key: &str) -> Result<Vec<u8>,String> { let value=required(v,key)?; if value.len()>4 * ((MAX_CHUNK + 2) / 3) { return Err(format!("{key} too large")); } STANDARD.decode(value).map_err(|_| format!("invalid base64 {key}")) }
fn authorized(v: &Value, cap: &str) -> Result<(), String> {
    let id=required(v,"session_id")?;
    let map=sessions().lock().map_err(|_| "session state unavailable")?;
    if map.get(id).is_some_and(|s| s.expires > std::time::Instant::now() && s.permissions.permits(cap)) { Ok(()) } else { Err("session not authorized for capability".into()) }
}

/// A receiver is explicitly created by the target in an owner-selected directory.
/// It never overwrites files, enforces sequential bounded chunks, and removes incomplete output.
pub struct FileReceiver { file: Option<File>, path: std::path::PathBuf, expected: u64, written: u64, digest: Sha256, completed: bool }
impl FileReceiver {
    pub fn create(dir: &Path, name: &str, expected: u64) -> Result<Self,String> {
        if expected > MAX_FILE || name.is_empty() || name.len() > 255 || name.contains(['/', '\\', ':']) || name.ends_with(['.', ' ']) || name.chars().any(char::is_control) || !matches!(Path::new(name).components().collect::<Vec<_>>().as_slice(), [Component::Normal(_)]) { return Err("unsafe filename or file too large".into()); }
        // Windows device names are unsafe even when receiving on another OS.
        let stem=name.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(stem.as_str(), "CON"|"PRN"|"AUX"|"NUL"|"COM1"|"COM2"|"COM3"|"COM4"|"COM5"|"COM6"|"COM7"|"COM8"|"COM9"|"LPT1"|"LPT2"|"LPT3"|"LPT4"|"LPT5"|"LPT6"|"LPT7"|"LPT8"|"LPT9") { return Err("reserved filename".into()); }
        let path=dir.join(name);
        let file=OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| e.to_string())?;
        Ok(Self {file:Some(file),path,expected,written:0,digest:Sha256::new(),completed:false})
    }
    pub fn chunk(&mut self, offset:u64, data:&[u8], checksum:&[u8]) -> Result<(),String> {
        if offset != self.written || data.len()>MAX_CHUNK || data.is_empty() || self.written.saturating_add(data.len() as u64)>self.expected {return Err("invalid chunk bounds or offset".into());}
        if Sha256::digest(data).as_slice()!=checksum { return Err("chunk checksum mismatch".into()); }
        self.file.as_mut().ok_or("transfer closed")?.write_all(data).map_err(|e|e.to_string())?;
        self.digest.update(data); self.written+=data.len() as u64; Ok(())
    }
    pub fn finish(mut self, checksum:&[u8]) -> Result<(),String> {
        if self.written != self.expected || self.digest.clone().finalize().as_slice()!=checksum { return Err("file length or checksum mismatch".into()); }
        self.file.take().ok_or("transfer closed")?.sync_all().map_err(|e|e.to_string())?; self.completed=true; Ok(())
    }
}
impl Drop for FileReceiver { fn drop(&mut self) { if !self.completed { self.file.take(); let _=std::fs::remove_file(&self.path); } } }

fn handle(v: Value) -> Result<Value,String> {
    match required(&v,"op")? {
        "preset" => Ok(serde_json::to_value(Permissions::preset(required(&v,"name")?)?).unwrap()),
        "session_accept" => {
            let id=required(&v,"session_id")?;
            if id.len()>128 { return Err("session id too long".into()); }
            if v.get("accepted").and_then(Value::as_bool)!=Some(true) { return Err("target acceptance required".into()); }
            let p=confirmed_permissions(&v)?;
            start_expiry_worker()?;
            let old=sessions().lock().map_err(|_|"session state unavailable")?.insert(id.into(),Session {permissions:p.clone(),expires:std::time::Instant::now()+std::time::Duration::from_secs(3600),held:HashMap::new()});
            if let Some(old)=old {release_session(old);}
            transfers().lock().map_err(|_|"transfer state unavailable")?.retain(|_, (session, _)| session != id);
            Ok(json!(p))
        },
        "session_check" => { authorized(&v,required(&v,"capability")?)?; Ok(json!({"authorized":true})) },
        "session_revoke" => { let id=required(&v,"session_id")?; let old=sessions().lock().map_err(|_|"session state unavailable")?.remove(id); let failed=old.map(release_session).unwrap_or(0); transfers().lock().map_err(|_|"transfer state unavailable")?.retain(|_, (session, _)| session != id); Ok(json!({"revoked":true,"release_failures":failed})) },
        "file_begin" => {
            authorized(&v,"file_transfer")?;
            let session=required(&v,"session_id")?; let id=required(&v,"transfer_id")?;
            if id.len()>128 {return Err("transfer id too long".into());}
            let dir=required(&v,"directory")?; let name=required(&v,"filename")?;
            let size=v.get("size").and_then(Value::as_u64).ok_or("size required")?;
            let mut map=transfers().lock().map_err(|_|"transfer state unavailable")?;
            if map.contains_key(id) {return Err("duplicate transfer id".into());} if map.len()>=16 {return Err("too many active transfers".into());}
            let receiver=FileReceiver::create(Path::new(dir),name,size)?;
            map.insert(id.into(),(session.into(),receiver)); Ok(json!({"started":true}))
        },
        "file_chunk" => {
            authorized(&v,"file_transfer")?; let session=required(&v,"session_id")?;
            let id=required(&v,"transfer_id")?; let data=bytes(&v,"data")?; let hash=bytes(&v,"sha256")?;
            let offset=v.get("offset").and_then(Value::as_u64).ok_or("offset required")?;
            let mut map=transfers().lock().map_err(|_|"transfer state unavailable")?;
            let (owner,receiver)=map.get_mut(id).ok_or("unknown transfer")?;
            if owner!=session {return Err("transfer belongs to another session".into());}
            receiver.chunk(offset,&data,&hash)?; Ok(json!({"written":data.len()}))
        },
        "file_finish" => {
            authorized(&v,"file_transfer")?; let session=required(&v,"session_id")?;
            let id=required(&v,"transfer_id")?; let hash=bytes(&v,"sha256")?;
            let mut map=transfers().lock().map_err(|_|"transfer state unavailable")?;
            if map.get(id).ok_or("unknown transfer")?.0!=session {return Err("transfer belongs to another session".into());}
            let (_,receiver)=map.remove(id).ok_or("unknown transfer")?; receiver.finish(&hash)?;
            Ok(json!({"completed":true}))
        },
        // unattended_password_set {password} -> {record: "<json string to persist>"}; OPAQUE registration, client and server in-process
        "unattended_password_set" => Ok(json!({"record":serde_json::to_string(&auth::PasswordRecord::create(required(&v,"password")?)?).unwrap()})),
        // unattended_login_start {password} -> {ke1, state}; controller, state stays local until KE2
        "unattended_login_start" => { let (ke1,state)=auth::login_start(required(&v,"password")?)?; Ok(json!({"ke1":STANDARD.encode(ke1),"state":STANDARD.encode(state)})) },
        // unattended_login_respond {record, ke1, purpose:"auth", ...MSG} -> {ke2, state}; target, state stays local until KE3
        "unattended_login_respond" => { let (ke2,state)=record(&v)?.respond(&bytes(&v,"ke1")?,&purpose_msg(&v,"auth")?)?; Ok(json!({"ke2":STANDARD.encode(ke2),"state":STANDARD.encode(state)})) },
        // unattended_login_finish {password, state, ke2, purpose:"auth", ...MSG} -> {ke3}; controller, errors on wrong password or fake target
        "unattended_login_finish" => Ok(json!({"ke3":STANDARD.encode(auth::login_finish(required(&v,"password")?,&bytes(&v,"state")?,&bytes(&v,"ke2")?,&purpose_msg(&v,"auth")?)?)})),
        // unattended_login_verify {state, ke3, purpose:"auth", ...MSG} -> {valid}; target
        "unattended_login_verify" => Ok(json!({"valid":auth::login_verify(&bytes(&v,"state")?,&bytes(&v,"ke3")?,&purpose_msg(&v,"auth")?)?})),
        // unattended_proof_sign {private_key_pkcs8, purpose:"auth"|"enroll", session_id, target_id, controller_id, nonce, controller_dtls_fp, target_dtls_fp} -> {signature}
        "unattended_proof_sign" => { let pair=Ed25519KeyPair::from_pkcs8(&bytes(&v,"private_key_pkcs8")?).map_err(|_|"invalid private key")?; Ok(json!({"signature":STANDARD.encode(pair.sign(&proof_msg(&v)?).as_ref())})) },
        // trust_set {public_key, controller_id, preset|permissions, owner_confirmed:true, [elevated_confirmed]} -> {device_id}
        "trust_set" => { let key=key_bytes(&v,"public_key")?; TRUST.lock().map_err(|_|"native state unavailable")?.set(&key,required(&v,"controller_id")?,confirmed_permissions(&v)?,v.get("owner_confirmed").and_then(Value::as_bool)==Some(true))?; Ok(json!({"device_id":auth::fingerprint(&key)?})) },
        // trust_revoke {device_id} -> {revoked}
        "trust_revoke" => Ok(json!({"revoked":TRUST.lock().map_err(|_|"native state unavailable")?.revoke_device(required(&v,"device_id")?)})),
        // trust_list {} -> {devices:[{device_id, controller_id, permissions}]}
        "trust_list" => Ok(json!({"devices":TRUST.lock().map_err(|_|"native state unavailable")?.list().into_iter().map(|(id,c,p)|json!({"device_id":id,"controller_id":c,"permissions":p})).collect::<Vec<_>>()})),
        // trust_export {} -> {json}; trust_import {json} replaces the store (data is untrusted, strictly validated)
        "trust_export" => Ok(json!({"json":TRUST.lock().map_err(|_|"native state unavailable")?.to_json()})),
        "trust_import" => { let store=auth::TrustedPolicies::from_json(required(&v,"json")?)?; *TRUST.lock().map_err(|_|"native state unavailable")?=store; Ok(json!({"imported":true})) },
        // trust_verify {public_key, expected_public_key, controller_id, purpose:"auth", session_id, target_id, nonce, controller_dtls_fp, target_dtls_fp, signature} -> {device_id, permissions}
        "trust_verify" => { let key=key_bytes(&v,"public_key")?; let expected=key_bytes(&v,"expected_public_key")?; let msg=purpose_msg(&v,"auth")?; let store=TRUST.lock().map_err(|_|"native state unavailable")?; let p=store.verify(&key,&expected,required(&v,"controller_id")?,&msg,&bytes(&v,"signature")?)?; Ok(json!({"device_id":auth::fingerprint(&key)?,"permissions":p})) },
        // proof_verify {public_key, expected_public_key, purpose:"enroll", ...MSG, signature} -> {device_id}; like trust_verify but needs no trust entry
        "proof_verify" => { let key=key_bytes(&v,"public_key")?; auth::verify_signature(&key,&key_bytes(&v,"expected_public_key")?,&purpose_msg(&v,"enroll")?,&bytes(&v,"signature")?)?; Ok(json!({"device_id":auth::fingerprint(&key)?})) },
        // auth_signature_verify {public_key, expected_public_key, purpose:"auth", ...MSG, signature} -> {valid:true}; key must be the registered one, no trust entry needed
        "auth_signature_verify" => { let key=key_bytes(&v,"public_key")?; auth::verify_signature(&key,&key_bytes(&v,"expected_public_key")?,&purpose_msg(&v,"auth")?,&bytes(&v,"signature")?)?; Ok(json!({"valid":true})) },
        // monitors {} -> {monitors:[{id,x,y,w,h,primary}]}; id is the enumeration index, pass it as event "display"
        "monitors" => Ok(json!({"monitors":monitors().iter().map(|m|json!({"id":m.id,"x":m.x,"y":m.y,"w":m.w,"h":m.h,"primary":m.primary})).collect::<Vec<_>>()})),
        "hash_begin" => Ok(json!({"handle":stream_hash::begin()?})),
        "hash_update" => { stream_hash::update(required(&v,"handle")?, &bytes(&v,"data")?)?; Ok(json!({"updated":true})) },
        "hash_finish" => Ok(json!({"sha256":stream_hash::finish(required(&v,"handle")?)?})),
        "hash_cancel" => { stream_hash::cancel(required(&v,"handle")?)?; Ok(json!({"cancelled":true})) },
        "input_display" => Ok(input_display()),
        "sha256" => { let encoded=v.get("data").and_then(Value::as_str).ok_or("data required")?; if encoded.len()>4 * ((MAX_CHUNK + 2) / 3) {return Err("data too large".into());} let data=STANDARD.decode(encoded).map_err(|_|"invalid base64 data")?; Ok(json!({"sha256":STANDARD.encode(Sha256::digest(data))})) },
        "key_fingerprint" => Ok(json!({"sha256":auth::fingerprint(&bytes(&v,"public_key")?)?})),
        "check_pin" => { let presented=bytes(&v,"public_key")?; let pinned=if v.get("pinned_key").is_some() {Some(bytes(&v,"pinned_key")?)} else {None}; let fingerprint=auth::check_pin(pinned.as_deref(),&presented,v.get("confirmed").and_then(Value::as_bool)==Some(true))?; Ok(json!({"sha256":fingerprint})) },
        "identity_generate" => { let pkcs8=Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_|"random generation failed")?; let pair=Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_|"key generation failed")?; Ok(json!({"private_key_pkcs8":STANDARD.encode(pkcs8.as_ref()),"public_key":STANDARD.encode(pair.public_key().as_ref())})) },
        "identity_sign" => { let key=bytes(&v,"private_key_pkcs8")?; let data=bytes(&v,"message")?; let pair=Ed25519KeyPair::from_pkcs8(&key).map_err(|_|"invalid private key")?; Ok(json!({"signature":STANDARD.encode(pair.sign(&data).as_ref())})) },
        "identity_verify" => { let key=bytes(&v,"public_key")?; let msg=bytes(&v,"message")?; let sig=bytes(&v,"signature")?; Ok(json!({"valid":UnparsedPublicKey::new(&ED25519,key).verify(&msg,&sig).is_ok()})) },
        "validate_input" => { let event=v.get("event").ok_or("event required")?; authorized(&v,input_capability(event))?; validate_input(event)?; Ok(json!({"valid":true})) },
        "inject_input" => {
            let event=v.get("event").ok_or("event required")?; authorized(&v,input_capability(event))?; let id=required(&v,"session_id")?; validate_input(event)?;
            // Ctrl+Alt+Del cannot be injected from a user session; the Windows service (SendSAS) must do it.
            if event["t"]=="secure_attention" {return Ok(json!({"injected":false,"requires_service":true,"reason":"Secure attention sequence requires the Windows service (SendSAS)"}));}
            let identity=input_identity(event);
            if let Some(ref key)=identity {
                let map=sessions().lock().map_err(|_|"session state unavailable")?;
                if map.iter().any(|(other,s)|other!=id && s.held.contains_key(key)) {return Err("input already held by another session".into());}
                if event["down"]==false && !map.get(id).is_some_and(|s|s.held.contains_key(key)) {return Err("input was not pressed by this session".into());}
            }
            inject_input(event)?;
            if let Some(key)=identity {let mut map=sessions().lock().map_err(|_|"session state unavailable")?; let s=map.get_mut(id).ok_or("session revoked")?;
                if event["down"]==true {let mut release=event.clone(); release["down"]=json!(false); s.held.insert(key,release);} else {s.held.remove(&key);}}
            Ok(json!({"injected":true}))
        },
        "samsung_key_payload" => { authorized(&v,"tv_keys")?; Ok(json!({"payload":tv::samsung_key_payload(required(&v,"key")?)?,"sent":false})) },
        "lg_request_payload" => { let action=required(&v,"action")?; let capability=if matches!(action,"launch"|"text") {"tv_apps"} else {"tv_keys"}; authorized(&v,capability)?; Ok(json!({"payload":tv::lg_request_payload(action,v.get("value").and_then(Value::as_str))?,"sent":false})) },
        "roku_key" => { authorized(&v,"tv_keys")?; let tv=tv::Roku::new(required(&v,"address")?)?; tv.send_key(required(&v,"key")?)?; Ok(json!({"accepted_by_device":true})) },
        "roku_launch" => { authorized(&v,"tv_apps")?; let tv=tv::Roku::new(required(&v,"address")?)?; tv.launch_app(required(&v,"app_id")?)?; Ok(json!({"accepted_by_device":true})) },
        "discover_roku" => { Ok(json!(tv::discover_roku()?)) },
        "service_send_sas" => service_send_sas(),
        "capabilities" => Ok(json!({"direct_ip":false,"linux_input":false,"roku_control":true,"roku_ssdp":true,"other_tv_control":false,"mdns":false,"screen_capture":false,"unattended_access":false,"multi_monitor":cfg!(windows),"unicode_text":cfg!(any(windows,target_os="linux")),"secure_attention":false,"persistent_trust":true})),
        _ => Err("unsupported operation".into()),
    }
}
pub fn validate_input(v:&Value) -> Result<(),String> {
    match required(v,"t")? {
        "mouse_move" | "touch" => { for k in ["x","y"] { let n=v.get(k).and_then(Value::as_f64).ok_or("missing coordinate")?; if !(0.0..=1.0).contains(&n) {return Err("coordinate out of range".into());} } if v.get("display").is_some_and(|d|!d.as_u64().is_some_and(|d|d<64)) {return Err("invalid display".into());} if v["t"]=="touch" && (!v.get("id").is_some_and(Value::is_u64) || !matches!(v.get("phase").and_then(Value::as_str),Some("start"|"move"|"end"|"cancel"))) {return Err("invalid touch".into());} },
        "mouse_btn" => { if !matches!(v.get("b").and_then(Value::as_str),Some("left"|"right"|"middle")) || !v.get("down").is_some_and(Value::is_boolean) {return Err("invalid mouse button".into());} },
        "wheel" => { let delta=v.get("dy").and_then(Value::as_i64).ok_or("wheel dy required")?; if delta == 0 || !(-1200..=1200).contains(&delta) {return Err("invalid wheel delta".into());} },
        "text" => { let text=v.get("text").and_then(Value::as_str).ok_or("text required")?; if text.is_empty() || text.len()>16 * 1024 || text.chars().any(char::is_control) {return Err("invalid text".into());} },
        "secure_attention" => { if v.as_object().is_some_and(|o|o.len()!=1) {return Err("invalid secure attention".into());} },
        "key" => { let code=required(v,"code")?; if code.len()>32 || !code.bytes().all(|b|b.is_ascii_alphanumeric()) || !v.get("down").is_some_and(Value::is_boolean) {return Err("invalid key".into());} },
        _ => return Err("unsupported input event".into()),
    } Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Monitor { id: u32, x: i32, y: i32, w: i32, h: i32, primary: bool }
#[cfg(windows)]
fn monitors() -> Vec<Monitor> {
    use windows_sys::Win32::{Foundation::{LPARAM, RECT}, Graphics::Gdi::*};
    unsafe extern "system" fn each(h: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> i32 {
        let out = unsafe { &mut *(data as *mut Vec<Monitor>) };
        let mut info: MONITORINFO = unsafe { std::mem::zeroed() }; info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if unsafe { GetMonitorInfoW(h, &mut info) } != 0 { let r = info.rcMonitor; out.push(Monitor { id: out.len() as u32, x: r.left, y: r.top, w: r.right - r.left, h: r.bottom - r.top, primary: info.dwFlags & 1 != 0 /* MONITORINFOF_PRIMARY */ }); }
        1
    }
    let mut out = Vec::new();
    unsafe { EnumDisplayMonitors(std::ptr::null_mut(), std::ptr::null(), Some(each), &mut out as *mut Vec<Monitor> as LPARAM); }
    out
}
// shortcut: X11 monitor listing is not implemented (empty list, display 0 only); add XRandR/Xinerama via dlopen when needed.
#[cfg(not(windows))]
fn monitors() -> Vec<Monitor> { Vec::new() }
/// Normalized position within a monitor -> 0..65535 absolute coordinate over the virtual desktop (MOUSEEVENTF_VIRTUALDESK).
#[cfg_attr(not(windows), allow(dead_code))]
fn virtual_coord(frac: f64, origin: i32, size: i32, v_origin: i32, v_size: i32) -> i32 {
    ((origin as f64 + frac * (size - 1).max(0) as f64 - v_origin as f64) * 65535.0 / (v_size - 1).max(1) as f64).round() as i32
}
/// Windows virtual-key code and extended-key flag for a DOM `code`.
#[cfg_attr(not(windows), allow(dead_code))]
fn win_vk(code: &str) -> Option<(u16, bool)> {
    Some(match code {
        "Enter" => (0x0D,false), "Escape" => (0x1B,false), "Tab" => (0x09,false), "Backspace" => (0x08,false), "Space" => (0x20,false),
        "ArrowLeft" => (0x25,true), "ArrowUp" => (0x26,true), "ArrowRight" => (0x27,true), "ArrowDown" => (0x28,true),
        "ShiftLeft" => (0xA0,false), "ShiftRight" => (0xA1,false), "ControlLeft" => (0xA2,false), "ControlRight" => (0xA3,true),
        "AltLeft" => (0xA4,false), "AltRight" => (0xA5,true), "MetaLeft" => (0x5B,true), "MetaRight" => (0x5C,true),
        "PageUp" => (0x21,true), "PageDown" => (0x22,true), "End" => (0x23,true), "Home" => (0x24,true), "Insert" => (0x2D,true), "Delete" => (0x2E,true),
        _ if code.len()==4 && code.starts_with("Key") && code.as_bytes()[3].is_ascii_uppercase() => (code.as_bytes()[3] as u16,false),
        _ if code.len()==6 && code.starts_with("Digit") && code.as_bytes()[5].is_ascii_digit() => (code.as_bytes()[5] as u16,false),
        _ if code.starts_with('F') => { let n = code[1..].parse::<u16>().ok().filter(|n| (1..=12).contains(n) && n.to_string()==code[1..])?; (0x6F+n,false) }
        _ => return None,
    })
}

fn input_display() -> Value {
    #[cfg(windows)] {
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CMONITORS};
        let count = unsafe { GetSystemMetrics(SM_CMONITORS) };
        // Safe once monitors enumerate: moves are mapped per monitor via the event "display" id (unmapped moves still need a single display).
        let listed = monitors();
        return json!({"desktop_input_safe":!listed.is_empty(),"monitor_count":count,
            "reason":"Input mapping covers full-display capture of an enumerated monitor (pass its id as display), never a window."});
    }
    #[cfg(not(windows))] {
        json!({"desktop_input_safe":false,"reason":"Capture-to-input display mapping has not been verified for this platform."})
    }
}

#[cfg(windows)]
fn inject_input(event: &Value) -> Result<(), String> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
    // The captured surface is selected by trusted local UI. Recheck monitor
    // topology at the OS boundary; releases remain allowed after a hot-plug.
    // Keys, buttons and text act on the cursor/focus, so only unmapped absolute moves need the single-display guarantee.
    if event["t"] == "mouse_move" && event.get("display").is_none() && event.get("down").and_then(Value::as_bool) != Some(false) &&
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics(windows_sys::Win32::UI::WindowsAndMessaging::SM_CMONITORS) } != 1 {
        return Err("input requires a verified single-display topology".into());
    }
    if event["t"] == "text" {
        // Unicode scan codes, one down+up per UTF-16 unit; independent of the keyboard layout.
        let kb = |unit: u16, flags: u32| INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk:0, wScan:unit, dwFlags:KEYEVENTF_UNICODE | flags, time:0, dwExtraInfo:0 } } };
        let inputs: Vec<INPUT> = event["text"].as_str().ok_or("text required")?.encode_utf16().flat_map(|u| [kb(u,0), kb(u,KEYEVENTF_KEYUP)]).collect();
        if unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) } != inputs.len() as u32 {return Err("SendInput failed or was blocked".into());}
        return Ok(());
    }
    if event["t"] == "key" {
        let code = event["code"].as_str().ok_or("key required")?;
        let (key, extended) = win_vk(code).ok_or("unsupported key code")?;
        if event.get("mods").is_some_and(|m| m.as_array().is_none_or(|a| !a.is_empty())) { return Err("send modifier key events separately".into()); }
        let flags = (if event["down"].as_bool()==Some(false) { KEYEVENTF_KEYUP } else { 0 }) | (if extended { KEYEVENTF_EXTENDEDKEY } else { 0 });
        let input = INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk:key, wScan:0, dwFlags:flags, time:0, dwExtraInfo:0 } } };
        if unsafe { SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) } != 1 {return Err("SendInput failed or was blocked".into());}
        return Ok(());
    }
    let mut mouse = MOUSEINPUT::default();
    match event["t"].as_str() {
        Some("mouse_move") => {
            let (x, y) = (event["x"].as_f64().ok_or("missing x")?, event["y"].as_f64().ok_or("missing y")?);
            mouse.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
            if let Some(id) = event.get("display").and_then(Value::as_u64) {
                use windows_sys::Win32::UI::WindowsAndMessaging::*;
                let m = *monitors().get(id as usize).ok_or("unknown display")?;
                let v = |i| unsafe { GetSystemMetrics(i) };
                mouse.dx = virtual_coord(x, m.x, m.w, v(SM_XVIRTUALSCREEN), v(SM_CXVIRTUALSCREEN));
                mouse.dy = virtual_coord(y, m.y, m.h, v(SM_YVIRTUALSCREEN), v(SM_CYVIRTUALSCREEN));
                mouse.dwFlags |= MOUSEEVENTF_VIRTUALDESK;
            } else { mouse.dx = (x * 65535.0).round() as i32; mouse.dy = (y * 65535.0).round() as i32; }
        }
        Some("wheel") => { mouse.dwFlags = MOUSEEVENTF_WHEEL; mouse.mouseData = event["dy"].as_i64().ok_or("wheel dy required")? as i32 as u32; }
        Some("mouse_btn") => {
            mouse.dwFlags = match (event["b"].as_str(), event["down"].as_bool()) {
                (Some("left"), Some(true)) => MOUSEEVENTF_LEFTDOWN,
                (Some("left"), Some(false)) => MOUSEEVENTF_LEFTUP,
                (Some("right"), Some(true)) => MOUSEEVENTF_RIGHTDOWN,
                (Some("right"), Some(false)) => MOUSEEVENTF_RIGHTUP,
                (Some("middle"), Some(true)) => MOUSEEVENTF_MIDDLEDOWN,
                (Some("middle"), Some(false)) => MOUSEEVENTF_MIDDLEUP,
                _ => return Err("invalid mouse button".into()),
            };
        }
        _ => return Err("input type not supported by Windows injector".into()),
    }
    let input = INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: mouse } };
    let count = unsafe { SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) };
    if count != 1 { return Err("SendInput failed or was blocked".into()); }
    Ok(())
}
#[cfg(target_os="linux")]
fn inject_input(event: &Value) -> Result<(), String> { x11::inject(event) }
#[cfg(not(any(windows, target_os="linux")))]
fn inject_input(_: &Value) -> Result<(), String> { Err("input injection unavailable on this platform".into()) }
/// Asks remote_link-service to send Ctrl+Alt+Del. The service accepts only the app process it launched.
#[cfg(windows)]
fn service_send_sas() -> Result<Value, String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::{Pipes::*, Services::*}};
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let pipe = w(r"\.\pipe\remote_link-service");
    unsafe {
        // The pipe server must be the running RemoteLinkService process, so a squatter cannot pose as it.
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0;
        let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        let svc = if scm.is_null() { null_mut() } else { OpenServiceW(scm, w("RemoteLinkService").as_ptr(), SERVICE_QUERY_STATUS) };
        let queried = !svc.is_null() && QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut needed) != 0;
        if !svc.is_null() { CloseServiceHandle(svc); }
        if !scm.is_null() { CloseServiceHandle(scm); }
        if !queried || status.dwCurrentState != SERVICE_RUNNING { return Err("service not running".into()); }
        // SECURITY_IDENTIFICATION: the server may identify but not impersonate this process.
        let open = || CreateFileW(pipe.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, null_mut());
        let mut h = open();
        if h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(pipe.as_ptr(), 2000) != 0 { h = open(); }
        if h == INVALID_HANDLE_VALUE { return Err("service not running".into()); }
        let result = (|| {
            let mut server = 0;
            if GetNamedPipeServerProcessId(h, &mut server) == 0 || server != status.dwProcessId { return Err("pipe not owned by service".to_string()); }
            let msg = br#"{"op":"send_sas"}"#;
            let mut n = 0;
            if WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut n, null_mut()) == 0 { return Err("service write failed".into()); }
            let mut buf = [0u8; 512];
            // The service drops clients it did not launch before reading, so this read fails for them.
            if ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, null_mut()) == 0 { return Err("service refused this process".into()); }
            let reply: Value = serde_json::from_slice(&buf[..n as usize]).map_err(|_| "invalid service reply")?;
            if reply["ok"] == true { Ok(json!({"sent":true})) } else { Err(reply["error"].as_str().unwrap_or("service error").to_string()) }
        })();
        CloseHandle(h);
        result
    }
}
#[cfg(not(windows))]
fn service_send_sas() -> Result<Value, String> { Err("service unavailable on this platform".into()) }
/// Caller must pass a valid NUL-terminated UTF-8 string and free the result with `remote_core_free`.
#[no_mangle]
pub unsafe extern "C" fn remote_core_call(request:*const c_char) -> *mut c_char {
    let response=std::panic::catch_unwind(|| {
        if request.is_null() {return json!({"ok":false,"error":"null request"});}
        let _guard=match CALL_LOCK.lock() { Ok(guard)=>guard, Err(_)=>return json!({"ok":false,"error":"native state unavailable"}) };
        let req=unsafe {CStr::from_ptr(request)};
        if req.to_bytes().len() > 400_000 {return json!({"ok":false,"error":"request too large"});}
        match serde_json::from_slice::<Value>(req.to_bytes()).map_err(|e|e.to_string()).and_then(handle) {Ok(result)=>json!({"ok":true,"result":result}),Err(error)=>json!({"ok":false,"error":error})}
    }).unwrap_or_else(|_|json!({"ok":false,"error":"native panic"}));
    CString::new(response.to_string()).unwrap().into_raw()
}
/// Frees a pointer returned by `remote_core_call` exactly once.
#[no_mangle]
pub unsafe extern "C" fn remote_core_free(ptr:*mut c_char) { if !ptr.is_null() {drop(unsafe {CString::from_raw(ptr)});} }

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn service_send_sas_without_service() { assert!(handle(json!({"op":"service_send_sas"})).is_err()); }
    #[test] fn presets_and_confirmation() { assert!(!Permissions::preset("basic").unwrap().input); assert!(Permissions::preset("normal").unwrap().input); assert!(handle(json!({"op":"session_accept","session_id":"s","accepted":true,"preset":"full"})).is_err()); assert!(handle(json!({"op":"session_accept","session_id":"s","accepted":true,"preset":"full","elevated_confirmed":true})).is_ok()); assert!(handle(json!({"op":"session_check","session_id":"s","capability":"file_transfer"})).is_ok()); handle(json!({"op":"session_revoke","session_id":"s"})).unwrap(); assert!(handle(json!({"op":"session_check","session_id":"s","capability":"view"})).is_err()); }
    #[test] fn identity_roundtrip() { let id=handle(json!({"op":"identity_generate"})).unwrap(); let sig=handle(json!({"op":"identity_sign","private_key_pkcs8":id["private_key_pkcs8"],"message":"aGk="})).unwrap(); assert_eq!(handle(json!({"op":"identity_verify","public_key":id["public_key"],"signature":sig["signature"],"message":"aGk="})).unwrap()["valid"],true); }
    #[test] fn bridge_authorization_and_transfer() {
        let dir=std::env::temp_dir().join(format!("remote-bridge-{}",std::process::id())); std::fs::create_dir_all(&dir).unwrap();
        let dir=dir.to_str().unwrap(); let session="bridge-test";
        let begin=json!({"op":"file_begin","session_id":session,"transfer_id":"tx","directory":dir,"filename":"file","size":5});
        assert!(handle(begin.clone()).is_err());
        assert!(handle(json!({"op":"session_accept","session_id":session,"accepted":true,"preset":"full","elevated_confirmed":true})).is_ok());
        assert!(handle(begin.clone()).is_ok()); assert!(handle(begin).is_err());
        let hash=STANDARD.encode(Sha256::digest(b"hello"));
        assert!(handle(json!({"op":"file_chunk","session_id":session,"transfer_id":"tx","offset":0,"data":"aGVsbG8=","sha256":hash})).is_ok());
        assert!(handle(json!({"op":"session_revoke","session_id":session})).is_ok());
        assert!(handle(json!({"op":"file_finish","session_id":session,"transfer_id":"tx","sha256":hash})).is_err());
        assert!(!Path::new(dir).join("file").exists()); std::fs::remove_dir(dir).unwrap();
        assert!(handle(json!({"op":"inject_input","session_id":session,"event":{"t":"mouse_move","x":0,"y":0}})).is_err());
    }
    #[test] fn transfer_checksums_and_cleanup() {
        let dir=std::env::temp_dir().join(format!("remote-core-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data=b"hello"; let hash=Sha256::digest(data);
        let mut receiver=FileReceiver::create(&dir,"ok.bin",data.len() as u64).unwrap();
        assert!(receiver.chunk(1,data,&hash).is_err());
        assert!(receiver.chunk(0,data,&[0;32]).is_err());
        receiver.chunk(0,data,&hash).unwrap(); receiver.finish(&hash).unwrap();
        assert_eq!(std::fs::read(dir.join("ok.bin")).unwrap(),data);
        assert!(FileReceiver::create(&dir,"ok.bin",5).is_err());
        let mut incomplete=FileReceiver::create(&dir,"partial.bin",5).unwrap();
        incomplete.chunk(0,data,&hash).unwrap(); assert!(incomplete.finish(&[0;32]).is_err());
        assert!(!dir.join("partial.bin").exists());
        std::fs::remove_file(dir.join("ok.bin")).unwrap(); std::fs::remove_dir(dir).unwrap();
    }
    #[test] fn expired_session_is_denied_and_removed() {
        let id="expiry-test";
        sessions().lock().unwrap().insert(id.into(),Session {permissions:Permissions::preset("normal").unwrap(),expires:std::time::Instant::now()-std::time::Duration::from_secs(1),held:HashMap::new()});
        assert!(authorized(&json!({"session_id":id}),"input").is_err()); expire_sessions();
        assert!(!sessions().lock().unwrap().contains_key(id));
        assert_eq!(input_identity(&json!({"t":"key","code":"KeyA","down":true})).as_deref(),Some("key:KeyA"));
        assert_eq!(input_identity(&json!({"t":"mouse_btn","b":"left","down":true})).as_deref(),Some("mouse:left"));
        assert_eq!(input_identity(&json!({"t":"wheel","dy":120})),None);
    }
    #[test] fn shared_input_schema() {
        assert!(validate_input(&json!({"t":"wheel","dy":120})).is_ok());
        for event in [json!({"t":"wheel","dy":0}),json!({"t":"wheel","dy":1201}),json!({"t":"wheel","dy":-1201}),json!({"t":"wheel","delta":120}),json!({"t":"wheel","dy":1.5})] {assert!(validate_input(&event).is_err(),"{event}");}
        assert!(validate_input(&json!({"t":"text","text":"hello"})).is_ok());
        assert!(validate_input(&json!({"t":"text","text":""})).is_err());
        assert!(validate_input(&json!({"t":"text","text":"a".repeat(16385)})).is_err());
        assert!(validate_input(&json!({"t":"text","text":"a".repeat(16384)})).is_ok());
    }
    #[test] fn extended_input_schema() {
        assert!(validate_input(&json!({"t":"text","text":"héllo 😀"})).is_ok());
        assert!(validate_input(&json!({"t":"text","text":"a\nb"})).is_err());
        assert!(validate_input(&json!({"t":"secure_attention"})).is_ok());
        assert!(validate_input(&json!({"t":"secure_attention","x":1})).is_err());
        assert!(validate_input(&json!({"t":"mouse_move","x":0.5,"y":0.5,"display":1})).is_ok());
        for d in [json!(-1),json!(64),json!("1"),json!(1.5)] {assert!(validate_input(&json!({"t":"mouse_move","x":0,"y":0,"display":d})).is_err());}
        assert_eq!(input_capability(&json!({"t":"secure_attention"})),"elevated"); assert_eq!(input_capability(&json!({"t":"key"})),"input");
    }
    #[test] fn secure_attention_needs_elevated_and_service() {
        let s="sas-test"; let ev=json!({"t":"secure_attention"});
        handle(json!({"op":"session_accept","session_id":s,"accepted":true,"preset":"normal"})).unwrap();
        assert!(handle(json!({"op":"inject_input","session_id":s,"event":ev})).is_err());
        handle(json!({"op":"session_accept","session_id":s,"accepted":true,"preset":"full","elevated_confirmed":true})).unwrap();
        let r=handle(json!({"op":"inject_input","session_id":s,"event":ev})).unwrap(); assert_eq!(r["injected"],false); assert_eq!(r["requires_service"],true);
        handle(json!({"op":"session_revoke","session_id":s})).unwrap();
    }
    #[test] fn key_and_monitor_mapping() {
        assert_eq!(win_vk("F1"),Some((0x70,false))); assert_eq!(win_vk("F12"),Some((0x7B,false))); assert_eq!(win_vk("F13"),None); assert_eq!(win_vk("F01"),None); assert_eq!(win_vk("F+1"),None);
        assert_eq!(win_vk("MetaLeft"),Some((0x5B,true))); assert_eq!(win_vk("Delete"),Some((0x2E,true))); assert_eq!(win_vk("KeyA"),Some((65,false))); assert_eq!(win_vk("Bogus"),None);
        // two 1920-wide monitors, the left one at negative x: virtual desktop spans -1920..1920
        assert_eq!(virtual_coord(0.0,-1920,1920,-1920,3840),0); assert_eq!(virtual_coord(1.0,0,1920,-1920,3840),65535); assert_eq!(virtual_coord(0.0,0,1920,-1920,3840),32776);
        assert_eq!(virtual_coord(0.5,0,1,0,1),0);
        #[cfg(windows)] { assert_eq!(input_display()["desktop_input_safe"],!monitors().is_empty()); }
        #[cfg(windows)] { let m=monitors(); assert!(m.iter().any(|m|m.primary)); assert!(m.iter().enumerate().all(|(i,m)|m.id==i as u32 && m.w>0 && m.h>0)); }
    }
    #[test] fn unattended_and_trust_ops() {
        let record=handle(json!({"op":"unattended_password_set","password":"a strong password here"})).unwrap()["record"].as_str().unwrap().to_string();
        assert!(handle(json!({"op":"unattended_password_set","password":"short"})).is_err());
        let fields=json!({"purpose":"auth","session_id":"s1","target_id":"t1","controller_id":"c1","nonce":STANDARD.encode([5u8;32]),"controller_dtls_fp":"sha-256 AA:BB","target_dtls_fp":"sha-256 CC:DD"});
        let with=|op:&str,extra:Value|{let mut o=fields.clone(); o["op"]=json!(op); for (k,x) in extra.as_object().unwrap() {o[k]=x.clone();} o};
        // OPAQUE over the ops: controller start -> target respond -> controller finish -> target verify; `server` overrides target-side MSG fields
        let login=|pw:&str,server:Value|->Result<bool,String> {
            let start=handle(json!({"op":"unattended_login_start","password":pw}))?;
            let mut respond=with("unattended_login_respond",json!({"record":record,"ke1":start["ke1"]})); for (k,x) in server.as_object().unwrap() {respond[k]=x.clone();}
            let r=handle(respond.clone())?;
            let ke3=handle(with("unattended_login_finish",json!({"password":pw,"state":start["state"],"ke2":r["ke2"]})))?["ke3"].clone();
            respond["op"]=json!("unattended_login_verify"); respond["state"]=r["state"].clone(); respond["ke3"]=ke3;
            Ok(handle(respond)?["valid"]==true)
        };
        assert_eq!(login("a strong password here",json!({})),Ok(true));
        assert!(login("wrong password here",json!({})).is_err());
        // no process-wide lockout: many failures never block a correct password
        for _ in 0..6 {assert!(login("wrong password here",json!({})).is_err());}
        assert_eq!(login("a strong password here",json!({})),Ok(true));
        for (k,x) in [("session_id","s2"),("target_id","t2"),("controller_id","c2"),("nonce",&STANDARD.encode([6u8;32])),("controller_dtls_fp","sha-256 AA:BC"),("target_dtls_fp","sha-256 CC:DE"),("purpose","enroll"),("record","{}")] {assert!(login("a strong password here",json!({k:x})).is_err(),"{k}");}
        assert!(handle(with("unattended_login_respond",json!({"record":record,"ke1":STANDARD.encode([1u8;96]),"nonce":STANDARD.encode([6u8;31])}))).is_err());
        // a stored v2 PBKDF2 hash is not a valid record (no fallback)
        assert!(handle(with("unattended_login_respond",json!({"record":r#"{"version":1,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","verifier":"AAAA","iterations":600000}"#,"ke1":STANDARD.encode([1u8;96])}))).is_err());
        for op in ["unattended_password_params","unattended_password_proof","unattended_password_check","unattended_password_verify","password_create","password_verify"] {assert!(handle(json!({"op":op})).is_err(),"{op}");}
        let pkcs8=Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap(); let pair=Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(); let public=STANDARD.encode(pair.public_key().as_ref());
        let set=json!({"op":"trust_set","public_key":public,"controller_id":"c1","preset":"normal"});
        assert!(handle(set.clone()).is_err());
        let mut full=set.clone(); full["owner_confirmed"]=json!(true); full["preset"]=json!("full"); assert!(handle(full).is_err());
        let mut noid=set.clone(); noid["owner_confirmed"]=json!(true); noid.as_object_mut().unwrap().remove("controller_id"); assert!(handle(noid).is_err());
        let mut ok=set; ok["owner_confirmed"]=json!(true); let id=handle(ok).unwrap()["device_id"].as_str().unwrap().to_string();
        let sig=handle(with("unattended_proof_sign",json!({"private_key_pkcs8":STANDARD.encode(pkcs8.as_ref())}))).unwrap()["signature"].clone();
        let verify=with("trust_verify",json!({"public_key":public,"expected_public_key":public,"signature":sig}));
        assert_eq!(handle(verify.clone()).unwrap()["permissions"]["input"],true);
        { // same key in base64url must verify (compared as decoded bytes)
            use base64::engine::general_purpose::URL_SAFE_NO_PAD; let mut url=verify.clone(); url["expected_public_key"]=json!(URL_SAFE_NO_PAD.encode(pair.public_key().as_ref())); assert!(handle(url).is_ok());
            let mut short=verify.clone(); short["expected_public_key"]=json!("AAAA"); assert!(handle(short).is_err()); }
        for (k,x) in [("session_id","s2"),("target_id","t2"),("nonce",&STANDARD.encode([6u8;32])),("controller_dtls_fp","sha-256 AA:BC"),("target_dtls_fp","sha-256 CC:DE"),("controller_id","c2"),("expected_public_key",&STANDARD.encode([1u8;32])),("purpose","enroll")] {let mut bad=verify.clone(); bad[k]=json!(x); assert!(handle(bad).is_err(),"{k}");}
        // proof_verify: same checks, no trust entry needed (use a fresh untrusted key)
        let other=Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap(); let other_pub=STANDARD.encode(Ed25519KeyPair::from_pkcs8(other.as_ref()).unwrap().public_key().as_ref());
        let osig=handle(with("unattended_proof_sign",json!({"private_key_pkcs8":STANDARD.encode(other.as_ref()),"purpose":"enroll"}))).unwrap()["signature"].clone();
        let pv=with("proof_verify",json!({"public_key":other_pub,"expected_public_key":other_pub,"signature":osig,"purpose":"enroll"}));
        assert!(handle(with("trust_verify",json!({"public_key":other_pub,"expected_public_key":other_pub,"signature":osig}))).is_err());
        // purpose swap: an enroll signature never passes trust_verify, an auth signature never passes proof_verify
        let mut swapped=verify.clone(); swapped["signature"]=handle(with("unattended_proof_sign",json!({"private_key_pkcs8":STANDARD.encode(pkcs8.as_ref()),"purpose":"enroll"}))).unwrap()["signature"].clone(); assert!(handle(swapped.clone()).is_err());
        swapped["purpose"]=json!("enroll"); assert!(handle(swapped).is_err());
        let mut as_enroll=verify.clone(); as_enroll["op"]=json!("proof_verify"); as_enroll["purpose"]=json!("enroll"); assert!(handle(as_enroll.clone()).is_err());
        as_enroll["purpose"]=json!("auth"); assert!(handle(as_enroll).is_err());
        // auth_signature_verify: signature + registered key only, purpose auth only, no trust entry needed
        let mut asv=verify.clone(); asv["op"]=json!("auth_signature_verify"); assert!(handle(asv.clone()).is_ok());
        let mut bad=asv.clone(); bad["expected_public_key"]=json!(STANDARD.encode([1u8;32])); assert!(handle(bad).is_err());
        let mut bad=asv.clone(); bad["purpose"]=json!("enroll"); assert!(handle(bad).is_err());
        let mut bad=asv.clone(); bad["nonce"]=json!(STANDARD.encode([6u8;32])); assert!(handle(bad).is_err());
        let mut nopurpose=pv.clone(); nopurpose.as_object_mut().unwrap().remove("purpose"); assert!(handle(nopurpose).is_err());
        assert_eq!(handle(pv.clone()).unwrap()["device_id"],auth::fingerprint(&STANDARD.decode(&other_pub).unwrap()).unwrap());
        for (k,x) in [("session_id","s2"),("target_id","t2"),("controller_id","c2"),("nonce",&STANDARD.encode([6u8;32])),("controller_dtls_fp","sha-256 AA:BC"),("target_dtls_fp","sha-256 CC:DE"),("expected_public_key",&public),("purpose","auth")] {let mut bad=pv.clone(); bad[k]=json!(x); assert!(handle(bad).is_err(),"proof_verify {k}");}
        let exported=handle(json!({"op":"trust_export"})).unwrap()["json"].as_str().unwrap().to_string();
        assert!(handle(json!({"op":"trust_import","json":exported.replace("\"version\":2","\"version\":1")})).is_err());
        assert_eq!(handle(json!({"op":"trust_revoke","device_id":id})).unwrap()["revoked"],true); assert!(handle(verify.clone()).is_err());
        handle(json!({"op":"trust_import","json":exported})).unwrap(); assert!(handle(verify).is_ok());
        assert!(handle(json!({"op":"trust_list"})).unwrap()["devices"].as_array().unwrap().iter().any(|d|d["device_id"]==id && d["controller_id"]=="c1"));
        handle(json!({"op":"trust_revoke","device_id":id})).unwrap();
    }
    #[test] fn ffi_session_revocation() {
        fn call(v:Value)->Value {let request=CString::new(v.to_string()).unwrap(); unsafe {let p=remote_core_call(request.as_ptr()); let value=serde_json::from_slice(CStr::from_ptr(p).to_bytes()).unwrap(); remote_core_free(p); value}}
        assert_eq!(call(json!({"op":"session_accept","session_id":"ffi-test","preset":"normal","accepted":true}))["ok"],true);
        assert_eq!(call(json!({"op":"session_check","session_id":"ffi-test","capability":"input"}))["ok"],true);
        assert_eq!(call(json!({"op":"session_revoke","session_id":"ffi-test"}))["ok"],true);
        assert_eq!(call(json!({"op":"session_check","session_id":"ffi-test","capability":"input"}))["ok"],false);
        assert_eq!(call(json!({"op":"inject_input","session_id":"ffi-test","event":{"t":"wheel","dy":120}}))["ok"],false);
    }
    #[test] fn sha256_bridge() {
        let v=handle(json!({"op":"sha256","data":"YWJj"})).unwrap();
        assert_eq!(v["sha256"],"ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
        assert_eq!(handle(json!({"op":"sha256","data":""})).unwrap()["sha256"],"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
        assert!(handle(json!({"op":"sha256","data":"!"})).is_err());
        assert!(handle(json!({"op":"sha256","data":"A".repeat(400000)})).is_err());
    }
    #[test] fn filename_and_input() { assert!(FileReceiver::create(&std::env::temp_dir(),"../bad",0).is_err()); assert!(FileReceiver::create(&std::env::temp_dir(),"CON.txt",0).is_err()); assert!(validate_input(&json!({"t":"mouse_move","x":1.1,"y":0})).is_err()); }
}















