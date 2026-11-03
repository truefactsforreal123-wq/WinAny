//! Authentication building blocks; none creates an unattended session.
use base64::{engine::general_purpose::STANDARD, Engine};
use opaque_ke::{ciphersuite::CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest, CredentialResponse, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup};
use rand_core::OsRng;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use crate::Permissions;

const DOMAIN: &[u8] = b"remote-link-auth-v3\0";
/// OPAQUE (RFC 9807): ristretto255 OPRF, 3DH with SHA-512, Argon2id KSF (argon2 crate defaults: m=19 MiB, t=2, p=1).
pub struct Suite;
impl CipherSuite for Suite { type OprfCs=opaque_ke::Ristretto255; type KeyExchange=opaque_ke::TripleDh<opaque_ke::Ristretto255,sha2::Sha512>; type Ksf=opaque_ke::argon2::Argon2<'static>; }
/// One unattended password per target, so the credential identifier is fixed.
const CRED_ID: &[u8] = b"remote-link-unattended";
/// Exact wire sizes of the OPAQUE messages for this suite (ristretto255, 3DH, SHA-512).
const KE1_LEN: usize = 96;
const KE2_LEN: usize = 320;
const KE3_LEN: usize = 64;
fn bad<E>(_:E) -> String { "invalid password record or message".into() }
fn ctx(msg:&[u8]) -> ServerLoginParameters<'_,'static> { ServerLoginParameters {context:Some(msg),..Default::default()} }
/// Target-side unattended password record: OPAQUE server setup + registration record.
/// Not password-equivalent: logging in still needs the password, and testing a guess needs the Argon2 KSF.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordRecord { version: u8, setup: String, record: String }
impl PasswordRecord {
    /// Runs OPAQUE registration client and server in-process on the target.
    pub fn create(password: &str) -> Result<Self,String> {
        if password.chars().count()<12 || password.len()>1024 {return Err("password must be 12 characters or longer and at most 1024 bytes".into());}
        let setup=ServerSetup::<Suite>::new(&mut OsRng);
        let start=ClientRegistration::<Suite>::start(&mut OsRng,password.as_bytes()).map_err(bad)?;
        let response=ServerRegistration::<Suite>::start(&setup,start.message,CRED_ID).map_err(bad)?;
        let upload=start.state.finish(&mut OsRng,password.as_bytes(),response.message,ClientRegistrationFinishParameters::default()).map_err(bad)?;
        Ok(Self {version:3,setup:STANDARD.encode(setup.serialize()),record:STANDARD.encode(ServerRegistration::finish(upload.message).serialize())})
    }
    /// Target: answers the controller's KE1 with KE2, bound to `msg` (the v3 auth message). Returns (KE2, server state).
    pub fn respond(&self,ke1:&[u8],msg:&[u8]) -> Result<(Vec<u8>,Vec<u8>),String> {
        if self.version!=3 || ke1.len()!=KE1_LEN {return Err(bad(()));}
        let setup=ServerSetup::<Suite>::deserialize(&STANDARD.decode(&self.setup).map_err(bad)?).map_err(bad)?;
        let record=ServerRegistration::<Suite>::deserialize(&STANDARD.decode(&self.record).map_err(bad)?).map_err(bad)?;
        let r=ServerLogin::start(&mut OsRng,&setup,Some(record),CredentialRequest::deserialize(ke1).map_err(bad)?,CRED_ID,ctx(msg)).map_err(bad)?;
        Ok((r.message.serialize().to_vec(),r.state.serialize().to_vec()))
    }
}
/// Controller: KE1 to send plus client state to keep until KE2 arrives.
pub fn login_start(password:&str) -> Result<(Vec<u8>,Vec<u8>),String> {
    if password.is_empty() || password.len()>1024 {return Err("invalid password".into());}
    let r=ClientLogin::<Suite>::start(&mut OsRng,password.as_bytes()).map_err(bad)?;
    Ok((r.message.serialize().to_vec(),r.state.serialize().to_vec()))
}
/// Controller: KE3. Fails on a wrong password, a fake target or a different `msg`.
pub fn login_finish(password:&str,state:&[u8],ke2:&[u8],msg:&[u8]) -> Result<Vec<u8>,String> {
    if ke2.len()!=KE2_LEN {return Err(bad(()));}
    let state=ClientLogin::<Suite>::deserialize(state).map_err(bad)?;
    let r=state.finish(&mut OsRng,password.as_bytes(),CredentialResponse::deserialize(ke2).map_err(bad)?,ClientLoginFinishParameters::new(Some(msg),Default::default(),None)).map_err(|_|"password not accepted".to_string())?;
    Ok(r.message.serialize().to_vec())
}
/// Target: true only if KE3 proves the password over the same `msg`.
pub fn login_verify(state:&[u8],ke3:&[u8],msg:&[u8]) -> Result<bool,String> {
    if ke3.len()!=KE3_LEN {return Err(bad(()));}
    // Note: opaque-ke 4.0.1 ServerLogin::finish ignores the context; the binding to `msg` happens in respond() (KE2 MACs).
    let state=ServerLogin::<Suite>::deserialize(state).map_err(bad)?;
    Ok(state.finish(CredentialFinalization::deserialize(ke3).map_err(bad)?,ctx(msg)).is_ok())
}
/// In-memory policy map. The owner is responsible for integrity-protected storage.
#[derive(Default)]
pub struct TrustedPolicies { entries: HashMap<[u8;32], TrustEntry> }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustEntry { controller_id: String, permissions: Permissions }
fn valid_id(id:&str) -> bool { !id.is_empty() && id.len()<=128 }
impl TrustedPolicies {
    pub fn set(&mut self, key:&[u8], controller_id:&str, permissions:Permissions, owner_confirmed:bool) -> Result<(),String> {
        if !owner_confirmed {return Err("owner confirmation required".into());}
        if !valid_id(controller_id) {return Err("invalid controller id".into());}
        let key: [u8;32]=key.try_into().map_err(|_|"invalid Ed25519 public key")?;
        self.entries.insert(key,TrustEntry {controller_id:controller_id.into(),permissions}); Ok(())
    }
    pub fn revoke(&mut self,key:&[u8]) {if let Ok(key)=<&[u8;32]>::try_from(key) {self.entries.remove(key);}}
    /// Device id is the key fingerprint (lowercase hex SHA-256); returns whether an entry was removed.
    pub fn revoke_device(&mut self,id:&str) -> bool { let n=self.entries.len(); self.entries.retain(|k,_|fingerprint(k).map_or(true,|f|!f.eq_ignore_ascii_case(id))); self.entries.len()!=n }
    pub fn list(&self) -> Vec<(String,&str,&Permissions)> { let mut v:Vec<_>=self.entries.iter().filter_map(|(k,e)|fingerprint(k).ok().map(|f|(f,e.controller_id.as_str(),&e.permissions))).collect(); v.sort_by(|a,b|a.0.cmp(&b.0)); v }
    /// Persistence format: {"version":2,"entries":{"<base64 public key>":{"controller_id":..,"permissions":{..}}}}.
    pub fn to_json(&self) -> String { serde_json::to_string(&Stored {version:2,entries:self.entries.iter().map(|(k,e)|(STANDARD.encode(k),e.clone())).collect()}).unwrap() }
    /// Loaded data is untrusted: bounded, strictly parsed. Integrity of the stored file is the owner's job.
    pub fn from_json(json:&str) -> Result<Self,String> {
        if json.len()>1_000_000 {return Err("trust store too large".into());}
        let stored:Stored=serde_json::from_str(json).map_err(|_|"invalid trust store")?;
        if stored.version!=2 || stored.entries.len()>1024 || stored.entries.values().any(|e|!valid_id(&e.controller_id)) {return Err("invalid trust store".into());}
        let mut store=Self::default();
        for (k,e) in stored.entries { let key:[u8;32]=STANDARD.decode(k).ok().and_then(|b|b.try_into().ok()).ok_or("invalid trust store key")?; store.entries.insert(key,e); }
        Ok(store)
    }
    /// Verifies a v2 proof: signing key must equal the signaling-registered key, be trusted for this controller id, and sign `msg`.
    pub fn verify(&self,key:&[u8],expected_key:&[u8],controller_id:&str,msg:&[u8],signature:&[u8]) -> Result<&Permissions,String> {
        let array: &[u8;32]=key.try_into().map_err(|_|"invalid Ed25519 public key")?;
        verify_signature(key,expected_key,msg,signature)?;
        let entry=self.entries.get(array).filter(|e|e.controller_id==controller_id).ok_or("controller not trusted")?;
        Ok(&entry.permissions)
    }
}
/// Key must equal the registered key and the Ed25519 signature must verify over `msg`; no trust lookup.
pub fn verify_signature(key:&[u8],expected_key:&[u8],msg:&[u8],signature:&[u8]) -> Result<(),String> {
    #[allow(deprecated)] // public keys are not secret; ring keeps this helper for exactly this use
    let same=ring::constant_time::verify_slices_are_equal(key,expected_key);
    same.map_err(|_|"proof key does not match registered key")?;
    UnparsedPublicKey::new(&ED25519,key).verify(msg,signature).map_err(|_|"invalid proof".to_string())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored { version: u8, entries: BTreeMap<String,TrustEntry> }
/// Single source of truth for the v3 proof message (docs/AUTH_V2.md section 7). All inputs are bounded.
pub fn unattended_message(purpose:&str,session_id:&str,target_id:&str,controller_id:&str,nonce:&[u8],controller_dtls_fp:&str,target_dtls_fp:&str) -> Result<Vec<u8>,String> {
    let purpose=match purpose {"auth"=>1u8,"enroll"=>2,_=>return Err("invalid purpose".into())};
    if nonce.len()!=32 {return Err("nonce must be 32 bytes".into());}
    let mut m=DOMAIN.to_vec(); m.push(purpose);
    for (x,max) in [(session_id,128),(target_id,128),(controller_id,128)] { if x.is_empty() || x.len()>max {return Err("invalid id".into());} m.extend_from_slice(&(x.len() as u16).to_be_bytes()); m.extend_from_slice(x.as_bytes()); }
    m.extend_from_slice(nonce);
    for x in [controller_dtls_fp,target_dtls_fp] { if x.is_empty() || x.len()>200 {return Err("invalid fingerprint".into());} m.extend_from_slice(&(x.len() as u16).to_be_bytes()); m.extend_from_slice(x.as_bytes()); }
    Ok(m)
}
pub fn fingerprint(key:&[u8]) -> Result<String,String> {
    if key.len()!=32 {return Err("invalid Ed25519 public key")?;}
    Ok(Sha256::digest(key).iter().map(|b|format!("{b:02x}")).collect())
}
/// A first-use pin is not accepted without explicit local confirmation.
pub fn check_pin(pinned:Option<&[u8]>, presented:&[u8], confirmed:bool) -> Result<String,String> {
    let fingerprint=fingerprint(presented)?;
    match pinned {Some(key) if key==presented=>Ok(fingerprint),Some(_)=>Err("public key pin mismatch".into()),None if confirmed=>Ok(fingerprint),None=>Err("first-use key confirmation required".into())}
}
#[cfg(test)] mod tests {
    use super::*; use ring::{rand::SystemRandom, signature::{Ed25519KeyPair,KeyPair}};
    fn msg_for(purpose:&str,nonce:u8) -> Vec<u8> { unattended_message(purpose,"s","t","c",&[nonce;32],"sha-256 AA:BB","sha-256 CC:DD").unwrap() }
    fn msg() -> Vec<u8> { msg_for("auth",9) }
    #[test] fn message_layout_and_bounds() {
        let m=msg(); assert!(m.starts_with(b"remote-link-auth-v3\0\x01\0\x01s\0\x01t\0\x01c")); assert!(m.ends_with(b"\0\x0dsha-256 CC:DD"));
        assert!(msg_for("enroll",9).starts_with(b"remote-link-auth-v3\0\x02"));
        for p in ["","AUTH","other"] {assert!(unattended_message(p,"s","t","c",&[9;32],"a","b").is_err());}
        assert!(unattended_message("auth","s","t","c",&[9;31],"a","b").is_err()); assert!(unattended_message("auth","","t","c",&[9;32],"a","b").is_err());
        assert!(unattended_message("auth",&"x".repeat(129),"t","c",&[9;32],"a","b").is_err()); assert!(unattended_message("auth","s","t","c",&[9;32],&"x".repeat(201),"b").is_err());
        assert!(unattended_message("auth","s","t","c",&[9;32],"a","").is_err());
        let m2=|s,t,c,n:u8,cf,tf|unattended_message("auth",s,t,c,&[n;32],cf,tf).unwrap();
        for other in [m2("S","t","c",9,"sha-256 AA:BB","sha-256 CC:DD"),m2("s","T","c",9,"sha-256 AA:BB","sha-256 CC:DD"),m2("s","t","C",9,"sha-256 AA:BB","sha-256 CC:DD"),m2("s","t","c",8,"sha-256 AA:BB","sha-256 CC:DD"),m2("s","t","c",9,"sha-256 AA:BC","sha-256 CC:DD"),m2("s","t","c",9,"sha-256 AA:BB","sha-256 CC:DE"),msg_for("enroll",9)] {assert_ne!(other,m);}
    }
    #[test] fn proof_pin_and_revocation() {
        let key=Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap(); let key=Ed25519KeyPair::from_pkcs8(key.as_ref()).unwrap(); let public=key.public_key().as_ref();
        let mut store=TrustedPolicies::default(); assert!(store.set(public,"c",Permissions::default(),false).is_err()); assert!(store.set(public,"",Permissions::default(),true).is_err()); store.set(public,"c",Permissions::default(),true).unwrap();
        let m=msg(); let sig=key.sign(&m);
        assert!(store.verify(public,public,"c",&m,sig.as_ref()).is_ok());
        assert!(store.verify(public,public,"other",&m,sig.as_ref()).is_err());
        assert!(store.verify(public,&[1;32],"c",&m,sig.as_ref()).is_err());
        assert!(store.verify(public,public,"c",&msg_for("auth",8),sig.as_ref()).is_err());
        // purpose swap: an enroll signature is not an auth proof
        assert!(store.verify(public,public,"c",&m,key.sign(&msg_for("enroll",9)).as_ref()).is_err());
        assert!(check_pin(None,public,false).is_err()); assert!(check_pin(None,public,true).is_ok()); assert!(check_pin(Some(&[3;32]),public,true).is_err());
        store.revoke(public); assert!(store.verify(public,public,"c",&m,sig.as_ref()).is_err());
    }
    /// Full OPAQUE login; Err if the controller rejects KE2, Ok(target verdict) otherwise.
    fn login(record:&PasswordRecord,password:&str,client_msg:&[u8],server_msg:&[u8]) -> Result<bool,String> {
        let (ke1,client)=login_start(password)?; let (ke2,server)=record.respond(&ke1,server_msg)?;
        assert_eq!((ke1.len(),ke2.len()),(96,320)); // the app validates these lengths
        let ke3=login_finish(password,&client,&ke2,client_msg)?; assert_eq!(ke3.len(),64);
        login_verify(&server,&ke3,server_msg)
    }
    #[test] fn opaque_roundtrip_and_failures() {
        assert!(PasswordRecord::create("short").is_err());
        let record=PasswordRecord::create("a strong password here").unwrap(); let m=msg();
        assert_eq!(login(&record,"a strong password here",&m,&m),Ok(true));
        assert!(login(&record,"wrong password here",&m,&m).is_err()); // wrong password: controller cannot even build KE3
        assert!(login(&record,"a strong password here",&m,&msg_for("auth",8)).is_err()); // MSG field mismatch
        assert!(login(&record,"a strong password here",&m,&msg_for("enroll",9)).is_err()); // purpose swap
        // a KE3 replayed against another session's state is rejected by the target
        let (ke1,client)=login_start("a strong password here").unwrap(); let (ke2,_)=record.respond(&ke1,&m).unwrap();
        let ke3=login_finish("a strong password here",&client,&ke2,&m).unwrap();
        let (_,other)=record.respond(&login_start("a strong password here").unwrap().0,&m).unwrap();
        assert_eq!(login_verify(&other,&ke3,&m),Ok(false));
        let mut v2=serde_json::to_value(&record).unwrap(); v2["version"]=serde_json::json!(1);
        assert!(serde_json::from_value::<PasswordRecord>(v2).unwrap().respond(&ke1,&m).is_err());
    }
    #[test] fn opaque_messages_have_exact_sizes() {
        let record=PasswordRecord::create("a strong password here").unwrap(); let m=msg();
        let (ke1,client)=login_start("a strong password here").unwrap(); let (ke2,server)=record.respond(&ke1,&m).unwrap();
        let ke3=login_finish("a strong password here",&client,&ke2,&m).unwrap();
        for n in [0,95,97,320] {assert!(record.respond(&vec![1u8;n],&m).is_err());}
        for n in [0,319,321,96] {assert!(login_finish("a strong password here",&client,&vec![1u8;n],&m).is_err());}
        for n in [0,63,65,96] {assert!(login_verify(&server,&vec![1u8;n],&m).is_err());}
        assert_eq!(login_verify(&server,&ke3,&m),Ok(true));
    }
    #[test] fn stored_record_is_not_a_login_credential() {
        let record=PasswordRecord::create("a strong password here").unwrap(); let m=msg();
        let json=serde_json::to_string(&record).unwrap(); assert!(!json.contains("a strong password"));
        for stolen in [json.as_str(),&record.record,&record.setup] {assert!(login(&record,stolen,&m,&m).is_err());}
    }
    #[test] fn trust_store_roundtrip_and_device_revoke() {
        let mut store=TrustedPolicies::default(); store.set(&[1;32],"c1",Permissions::preset("normal").unwrap(),true).unwrap(); store.set(&[2;32],"c2",Permissions::default(),true).unwrap();
        let loaded=TrustedPolicies::from_json(&store.to_json()).unwrap();
        assert_eq!(loaded.list().len(),2); assert!(loaded.list().iter().any(|(_,c,p)|*c=="c1" && p.input));
        let mut loaded=loaded; let id=fingerprint(&[1;32]).unwrap();
        assert!(!loaded.revoke_device("nope")); assert!(loaded.revoke_device(&id.to_uppercase())); assert_eq!(loaded.list().len(),1);
        let k=STANDARD.encode([1u8;32]);
        for bad in ["","{}",r#"{"version":1,"entries":{}}"#,r#"{"version":3,"entries":{}}"#,r#"{"version":2,"entries":{"AAAA":{"controller_id":"c","permissions":{}}}}"#,r#"{"version":2,"entries":{},"x":1}"#,&format!(r#"{{"version":2,"entries":{{"{k}":{{"controller_id":"","permissions":{{}}}}}}}}"#),&format!(r#"{{"version":2,"entries":{{"{k}":{{"permissions":{{}}}}}}}}"#),&format!(r#"{{"version":1,"entries":{{"{k}":{{}}}}}}"#),&format!(r#"{{"version":2,"entries":{{"{k}":{{"controller_id":"c","permissions":{{"bogus":true}}}}}}}}"#)] {assert!(TrustedPolicies::from_json(bad).is_err(),"{bad}");}
    }
}
