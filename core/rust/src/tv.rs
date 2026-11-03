//! LAN TV adapters. Device addresses must be selected by the target owner.
use std::{io::{Read, Write}, net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket}, time::{Duration, Instant}};

#[derive(serde::Serialize)]
pub struct TvCapabilities {pub pair:bool,pub keys:bool,pub text:bool,pub apps:bool,pub state:bool,pub screen_view:bool}
pub trait TvAdapter {
    fn capabilities(&self) -> TvCapabilities;
    fn pair(&self) -> Result<(),String> {Err("pairing unavailable".into())}
    fn send_key(&self, key: &str) -> Result<(), String>;
    fn send_text(&self, _: &str) -> Result<(),String> {Err("text entry unavailable".into())}
    fn launch_app(&self, app: &str) -> Result<(), String>;
    fn get_state(&self) -> Result<serde_json::Value,String> {Err("state unavailable".into())}
}
pub struct Roku { address: Ipv4Addr }
impl Roku {
    pub fn new(address: &str) -> Result<Self, String> {
        let address: Ipv4Addr = address.parse().map_err(|_| "IPv4 address required")?;
        if !address.is_private() {return Err("only private IPv4 LAN addresses allowed".into());}
        Ok(Self {address})
    }
    fn post(&self, path: &str) -> Result<(), String> {
        let addr=SocketAddr::from((self.address,8060));
        let mut stream=TcpStream::connect_timeout(&addr,Duration::from_secs(3)).map_err(|e|e.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e|e.to_string())?;
        stream.set_write_timeout(Some(Duration::from_secs(3))).map_err(|e|e.to_string())?;
        write!(stream,"POST /{} HTTP/1.1\r\nHost: {}:8060\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",path,self.address).map_err(|e|e.to_string())?;
        let mut response=Vec::new(); stream.take(8192).read_to_end(&mut response).map_err(|e|e.to_string())?;
        let line=response.split(|b| *b==b'\n').next().ok_or("empty HTTP response")?;
        let line=std::str::from_utf8(line).map_err(|_|"invalid HTTP response")?;
        let mut parts=line.split_whitespace(); let version=parts.next().unwrap_or(""); let status=parts.next().unwrap_or("");
        if !matches!(version,"HTTP/1.0"|"HTTP/1.1") || status.len()!=3 || !status.starts_with('2') || !status.bytes().all(|b|b.is_ascii_digit()) {return Err(format!("Roku rejected request: {status}"));}
        Ok(())
    }
}
impl TvAdapter for Roku {
    fn capabilities(&self)->TvCapabilities {TvCapabilities{pair:false,keys:true,text:false,apps:true,state:false,screen_view:false}}
    fn send_key(&self, key:&str) -> Result<(),String> {
        if !matches!(key,"Home"|"Rev"|"Fwd"|"Play"|"Select"|"Left"|"Right"|"Down"|"Up"|"Back"|"InstantReplay"|"Info"|"Backspace"|"Search"|"Enter"|"VolumeDown"|"VolumeMute"|"VolumeUp"|"PowerOff"|"ChannelUp"|"ChannelDown") {return Err("unsupported Roku key".into());}
        self.post(&format!("keypress/{key}"))
    }
    fn launch_app(&self, app:&str) -> Result<(),String> {
        if app.is_empty() || app.len()>20 || !app.bytes().all(|b|b.is_ascii_digit()) {return Err("invalid Roku app id".into());}
        self.post(&format!("launch/{app}"))
    }
}
/// Protocol message builders only; a transport must perform authenticated pairing,
/// validate the TV certificate, handle responses and store credentials securely.
pub fn samsung_key_payload(key:&str) -> Result<serde_json::Value,String> {
    if !matches!(key,"KEY_HOME"|"KEY_RETURN"|"KEY_UP"|"KEY_DOWN"|"KEY_LEFT"|"KEY_RIGHT"|"KEY_ENTER"|"KEY_VOLUP"|"KEY_VOLDOWN"|"KEY_MUTE"|"KEY_POWEROFF"|"KEY_PLAY"|"KEY_PAUSE") {return Err("unsupported Samsung key".into());}
    Ok(serde_json::json!({"method":"ms.remote.control","params":{"Cmd":"Click","DataOfCmd":key,"Option":"false","TypeOfRemote":"SendRemoteKey"}}))
}
pub fn lg_register_payload(client_key:Option<&str>,manifest:serde_json::Value)->Result<serde_json::Value,String> {
    if !manifest.is_object() {return Err("LG pairing manifest required".into());}
    if client_key.is_some_and(|k|k.is_empty() || k.len()>1024) {return Err("invalid LG client key".into());}
    let mut payload=serde_json::json!({"pairingType":"PROMPT","manifest":manifest});
    if let Some(key)=client_key {payload["client-key"]=serde_json::json!(key);}
    Ok(serde_json::json!({"type":"register","id":"register-1","payload":payload}))
}
pub fn lg_request_payload(action:&str,value:Option<&str>)->Result<serde_json::Value,String> {
    let (uri,payload)=match action {
        "volume_up"=>("ssap://audio/volumeUp",serde_json::json!({})),
        "volume_down"=>("ssap://audio/volumeDown",serde_json::json!({})),
        "power_off"=>("ssap://system/turnOff",serde_json::json!({})),
        "get_state"=>("ssap://audio/getVolume",serde_json::json!({})),
        "launch"=> {let id=value.ok_or("app id required")?; if id.is_empty() || id.len()>128 || !id.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'.'|b'_'|b'-')) {return Err("invalid app id".into());} ("ssap://system.launcher/launch",serde_json::json!({"id":id}))},
        "text"=> {let text=value.ok_or("text required")?; if text.len()>4096 {return Err("text too long".into());} ("ssap://com.webos.service.ime/insertText",serde_json::json!({"text":text,"replace":0}))},
        _=>return Err("unsupported LG action".into()),
    };
    Ok(serde_json::json!({"id":"request-1","type":"request","uri":uri,"payload":payload}))
}
/// Discover Roku addresses only; never fetch or trust a URL from an SSDP response.
pub fn discover_roku() -> Result<Vec<String>,String> {
    let socket=UdpSocket::bind("0.0.0.0:0").map_err(|e|e.to_string())?;
    socket.set_read_timeout(Some(Duration::from_millis(250))).map_err(|e|e.to_string())?;
    socket.send_to(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: roku:ecp\r\n\r\n","239.255.255.250:1900").map_err(|e|e.to_string())?;
    let deadline=Instant::now()+Duration::from_secs(2); let mut result=Vec::new(); let mut buf=[0u8;4096];
    while Instant::now()<deadline && result.len()<64 {
        match socket.recv_from(&mut buf) {
            Ok((n,addr)) => {if let std::net::IpAddr::V4(ip)=addr.ip() {let text=String::from_utf8_lossy(&buf[..n]); if ip.is_private() && text.starts_with("HTTP/1.1 200") && text.to_ascii_lowercase().contains("roku:ecp") {let s=ip.to_string(); if !result.contains(&s) {result.push(s);}}}},
            Err(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut) => (),
            Err(e)=>return Err(e.to_string()),
        }
    } Ok(result)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn protocol_payload_validation() {
        assert_eq!(samsung_key_payload("KEY_UP").unwrap()["params"]["DataOfCmd"],"KEY_UP"); assert!(samsung_key_payload("KEY_BAD").is_err());
        assert_eq!(lg_request_payload("launch",Some("com.example.app")).unwrap()["payload"]["id"],"com.example.app");
        assert!(lg_request_payload("launch",Some("../bad")).is_err()); assert!(lg_register_payload(None,serde_json::Value::Null).is_err());
        assert_eq!(lg_register_payload(Some("token"),serde_json::json!({})).unwrap()["payload"]["client-key"],"token");
    }
    #[test] fn reject_network_and_path_injection() {
        assert!(Roku::new("127.0.0.1").is_err()); assert!(Roku::new("8.8.8.8").is_err());
        let r=Roku::new("192.168.1.1").unwrap(); assert!(r.send_key("../bad").is_err()); assert!(r.launch_app("123?x").is_err());
    }
}

