//! Pipe protocol. One pipe message = one UTF-8 JSON object of at most MAX_MESSAGE bytes.
//! Requests:  {"op":"send_sas"}
//!            {"op":"switch_desktop_input","event":{"t":"key","code":"KeyA","down":true}}
//! Event "t" is one of mouse_move{x,y in 0..=1}, mouse_btn{b:left|right|middle,down},
//! wheel{dy: non-zero, -1200..=1200}, key{code,down} (same schema as remote_core input).
//! Replies:   {"ok":true} | {"ok":false,"error":"..."}
use serde::{Deserialize, Serialize};

pub const MAX_MESSAGE: usize = 512;

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    SendSas {},
    SwitchDesktopInput { event: InputEvent },
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputEvent {
    MouseMove { x: f64, y: f64 },
    MouseBtn { b: Button, down: bool },
    Wheel { dy: i32 },
    Key { code: String, down: bool },
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Button { Left, Right, Middle }

impl InputEvent {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            InputEvent::MouseMove { x, y } if !(0.0..=1.0).contains(x) || !(0.0..=1.0).contains(y) => Err("coordinate out of range".into()),
            InputEvent::Wheel { dy } if *dy == 0 || !(-1200..=1200).contains(dy) => Err("invalid wheel delta".into()),
            InputEvent::Key { code, .. } if key_vk(code).is_none() => Err("unsupported key code".into()),
            _ => Ok(()),
        }
    }
}

/// Virtual-key code and "extended key" flag; same key set as remote_core's Windows injector.
pub fn key_vk(code: &str) -> Option<(u16, bool)> {
    let b = code.as_bytes();
    Some(match code {
        "Enter" => (0x0D, false), "Escape" => (0x1B, false), "Tab" => (0x09, false), "Backspace" => (0x08, false),
        "Space" => (0x20, false), "ArrowLeft" => (0x25, true), "ArrowUp" => (0x26, true), "ArrowRight" => (0x27, true), "ArrowDown" => (0x28, true),
        "ShiftLeft" => (0xA0, false), "ShiftRight" => (0xA1, false), "ControlLeft" => (0xA2, false), "ControlRight" => (0xA3, true),
        "AltLeft" => (0xA4, false), "AltRight" => (0xA5, true),
        _ if b.len() == 4 && code.starts_with("Key") && b[3].is_ascii_uppercase() => (b[3] as u16, false),
        _ if b.len() == 6 && code.starts_with("Digit") && b[5].is_ascii_digit() => (b[5] as u16, false),
        _ => return None,
    })
}

pub fn parse(msg: &[u8]) -> Result<Request, String> {
    if msg.len() > MAX_MESSAGE { return Err("message too large".into()); }
    let v: serde_json::Value = serde_json::from_slice(msg).map_err(|_| "invalid request".to_string())?;
    // serde's tagged enums also accept arrays; only the documented object form is allowed.
    if !v.is_object() || v.get("event").is_some_and(|e| !e.is_object()) { return Err("invalid request".into()); }
    let req: Request = serde_json::from_value(v).map_err(|_| "invalid request".to_string())?;
    if let Request::SwitchDesktopInput { event } = &req { event.validate()?; }
    Ok(req)
}

pub fn reply(result: &Result<(), String>) -> Vec<u8> {
    match result {
        Ok(()) => serde_json::json!({"ok": true}),
        Err(e) => serde_json::json!({"ok": false, "error": e}),
    }.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_requests() {
        assert_eq!(parse(br#"{"op":"send_sas"}"#), Ok(Request::SendSas {}));
        assert_eq!(parse(br#"{"op":"switch_desktop_input","event":{"t":"key","code":"KeyA","down":true}}"#),
            Ok(Request::SwitchDesktopInput { event: InputEvent::Key { code: "KeyA".into(), down: true } }));
        assert!(parse(br#"{"op":"switch_desktop_input","event":{"t":"mouse_move","x":0.5,"y":1}}"#).is_ok());
        assert!(parse(br#"{"op":"switch_desktop_input","event":{"t":"mouse_btn","b":"left","down":false}}"#).is_ok());
        assert!(parse(br#"{"op":"switch_desktop_input","event":{"t":"wheel","dy":-120}}"#).is_ok());
    }

    #[test]
    fn rejects_invalid_requests() {
        for bad in [
            &br#"{"op":"exec","cmd":"calc"}"#[..],
            br#"{"op":"send_sas","extra":1}"#,
            br#"{"op":"switch_desktop_input"}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"key","code":"KeyA","down":true,"x":1}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"key","code":"F13","down":true}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"key","code":"Keya","down":true}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"mouse_move","x":1.5,"y":0}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"mouse_move","x":-0.1,"y":0}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"mouse_btn","b":"x1","down":true}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"wheel","dy":0}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"wheel","dy":5000}}"#,
            br#"{"op":"switch_desktop_input","event":{"t":"text","text":"hi"}}"#,
            br#"["send_sas"]"#,
            br#"{"op":"switch_desktop_input","event":["key","KeyA",true]}"#,
            b"not json",
            b"\xff\xfe",
            b"",
        ] {
            assert!(parse(bad).is_err(), "accepted {:?}", String::from_utf8_lossy(bad));
        }
        let big = format!(r#"{{"op":"send_sas","pad":"{}"}}"#, "a".repeat(MAX_MESSAGE));
        assert_eq!(parse(big.as_bytes()), Err("message too large".into()));
    }

    #[test]
    fn helper_line_roundtrip_and_reply() {
        let ev = InputEvent::MouseBtn { b: Button::Right, down: true };
        let line = serde_json::to_string(&ev).unwrap();
        assert_eq!(serde_json::from_str::<InputEvent>(&line).unwrap(), ev);
        assert_eq!(reply(&Ok(())), br#"{"ok":true}"#);
        assert_eq!(reply(&Err("no".into())), br#"{"error":"no","ok":false}"#);
    }
}
