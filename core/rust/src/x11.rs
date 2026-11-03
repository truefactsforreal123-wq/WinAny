//! X11/XTest input is available only to an explicitly authorized X11 session.
use serde_json::Value;

pub fn keysym(code: &str) -> Option<u64> {
    Some(match code {
        "Enter"=>0xff0d, "Escape"=>0xff1b, "Tab"=>0xff09, "Backspace"=>0xff08,
        "Space"=>0x20, "ArrowLeft"=>0xff51, "ArrowUp"=>0xff52, "ArrowRight"=>0xff53, "ArrowDown"=>0xff54,
        "ShiftLeft"=>0xffe1, "ShiftRight"=>0xffe2, "ControlLeft"=>0xffe3, "ControlRight"=>0xffe4,
        "AltLeft"=>0xffe9, "AltRight"=>0xffea, "MetaLeft"=>0xffeb, "MetaRight"=>0xffec,
        "Home"=>0xff50, "PageUp"=>0xff55, "PageDown"=>0xff56, "End"=>0xff57, "Insert"=>0xff63, "Delete"=>0xffff,
        _ if code.len()>=2 && code.starts_with('F') && code[1..].parse::<u64>().is_ok_and(|n|(1..=12).contains(&n) && n.to_string()==code[1..]) => 0xffbd+code[1..].parse::<u64>().unwrap(),
        _ if code.len()==4 && code.starts_with("Key") && code.as_bytes()[3].is_ascii_uppercase() => code.as_bytes()[3].to_ascii_lowercase() as u64,
        _ if code.len()==6 && code.starts_with("Digit") && code.as_bytes()[5].is_ascii_digit() => code.as_bytes()[5] as u64,
        _=>return None,
    })
}
#[cfg(target_os="linux")]
pub fn inject(event:&Value) -> Result<(),String> {
    use std::{ffi::{c_char,c_int,c_uint,c_ulong,c_void,CString}, ptr};
    #[link(name="dl")] unsafe extern "C" { fn dlopen(name:*const c_char, flags:c_int)->*mut c_void; fn dlsym(handle:*mut c_void,name:*const c_char)->*mut c_void; fn dlclose(handle:*mut c_void)->c_int; }
    struct Library(*mut c_void);
    impl Drop for Library {fn drop(&mut self){unsafe {dlclose(self.0);}}}
    fn library(name:&str)->Result<Library,String> {let n=CString::new(name).unwrap(); let p=unsafe{dlopen(n.as_ptr(),2)}; if p.is_null(){Err(format!("{name} unavailable"))}else{Ok(Library(p))}}
    fn symbol(lib:&Library,name:&str)->Result<*mut c_void,String> {let n=CString::new(name).unwrap(); let p=unsafe{dlsym(lib.0,n.as_ptr())}; if p.is_null(){Err(format!("{name} unavailable"))}else{Ok(p)}}
    if std::env::var("XDG_SESSION_TYPE").is_ok_and(|s|s.eq_ignore_ascii_case("wayland")) {return Err("Wayland requires the RemoteDesktop consent portal; unsupported".into());}
    if std::env::var_os("DISPLAY").is_none() {return Err("X11 DISPLAY unavailable".into());}
    let x=library("libX11.so.6")?; let xt=library("libXtst.so.6")?;
    unsafe {
        let open: unsafe extern "C" fn(*const c_char)->*mut c_void=std::mem::transmute(symbol(&x,"XOpenDisplay")?);
        let close: unsafe extern "C" fn(*mut c_void)->c_int=std::mem::transmute(symbol(&x,"XCloseDisplay")?);
        let query: unsafe extern "C" fn(*mut c_void,*mut c_int,*mut c_int,*mut c_int,*mut c_int)->c_int=std::mem::transmute(symbol(&xt,"XTestQueryExtension")?);
        let fake_key: unsafe extern "C" fn(*mut c_void,c_uint,c_int,c_ulong)->c_int=std::mem::transmute(symbol(&xt,"XTestFakeKeyEvent")?);
        let fake_button: unsafe extern "C" fn(*mut c_void,c_uint,c_int,c_ulong)->c_int=std::mem::transmute(symbol(&xt,"XTestFakeButtonEvent")?);
        let fake_move: unsafe extern "C" fn(*mut c_void,c_int,c_int,c_int,c_ulong)->c_int=std::mem::transmute(symbol(&xt,"XTestFakeMotionEvent")?);
        let keycode: unsafe extern "C" fn(*mut c_void,c_ulong)->u8=std::mem::transmute(symbol(&x,"XKeysymToKeycode")?);
        let screen: unsafe extern "C" fn(*mut c_void)->c_int=std::mem::transmute(symbol(&x,"XDefaultScreen")?);
        let width: unsafe extern "C" fn(*mut c_void,c_int)->c_int=std::mem::transmute(symbol(&x,"XDisplayWidth")?);
        let height: unsafe extern "C" fn(*mut c_void,c_int)->c_int=std::mem::transmute(symbol(&x,"XDisplayHeight")?);
        let flush: unsafe extern "C" fn(*mut c_void)->c_int=std::mem::transmute(symbol(&x,"XFlush")?);
        let display=open(ptr::null()); if display.is_null(){return Err("cannot open X11 display".into());}
        struct Display(*mut c_void, unsafe extern "C" fn(*mut c_void)->c_int);
        impl Drop for Display {fn drop(&mut self){unsafe{(self.1)(self.0);}}}
        let d=Display(display,close); let mut a=0; let mut b=0; let mut c=0; let mut e=0;
        if query(d.0,&mut a,&mut b,&mut c,&mut e)==0 {return Err("XTest extension unavailable".into());}
        let result=match event["t"].as_str() {
            Some("mouse_move")=> {if event.get("display").is_some_and(|d|d.as_u64()!=Some(0)) {return Err("X11 supports display 0 only".into());} let s=screen(d.0); let w=width(d.0,s); let h=height(d.0,s); if w<=0 || h<=0 {return Err("invalid display size".into());} fake_move(d.0,s,(event["x"].as_f64().ok_or("invalid x")?*(w-1) as f64).round() as c_int,(event["y"].as_f64().ok_or("invalid y")?*(h-1) as f64).round() as c_int,0)},
            Some("mouse_btn")=> {let button=match event["b"].as_str(){Some("left")=>1,Some("middle")=>2,Some("right")=>3,_=>return Err("invalid button".into())}; fake_button(d.0,button,event["down"].as_bool().ok_or("invalid button state")? as c_int,0)},
            Some("wheel")=> {let delta=event["dy"].as_i64().ok_or("invalid wheel")?; if delta%120!=0 {return Err("X11 wheel delta must be a multiple of 120".into());} let button=if delta>0 {4}else{5}; for _ in 0..delta.unsigned_abs()/120 {if fake_button(d.0,button,1,0)==0 || fake_button(d.0,button,0,0)==0 {return Err("XTest wheel failed".into());}} 1},
            Some("key")=> {if event.get("mods").is_some_and(|m|m.as_array().is_none_or(|a|!a.is_empty())) {return Err("send modifier key events separately".into());} let sym=keysym(event["code"].as_str().ok_or("invalid key")?).ok_or("unsupported key")?; let key=keycode(d.0,sym as c_ulong); if key==0 {return Err("key unavailable in X11 keymap".into());} fake_key(d.0,key as c_uint,event["down"].as_bool().ok_or("invalid key state")? as c_int,0)},
            // shortcut: no Shift handling, so uppercase/shifted symbols type their base key; upgrade by remapping a spare keycode.
            Some("text")=> {for ch in event["text"].as_str().ok_or("invalid text")?.chars() {let cp=ch as u32; let sym=if cp<0x100 {cp as c_ulong} else {0x0100_0000+cp as c_ulong}; let key=keycode(d.0,sym); if key==0 {return Err(format!("U+{cp:04X} unavailable in X11 keymap"));} if fake_key(d.0,key as c_uint,1,0)==0 || fake_key(d.0,key as c_uint,0,0)==0 {return Err("XTest text failed".into());}} 1},
            _=>return Err("unsupported X11 input type".into()),
        };
        if result==0 {return Err("XTest input failed".into());} flush(d.0); Ok(())
    }
}
#[cfg(not(target_os="linux"))]
pub fn inject(_: &Value)->Result<(),String> {Err("X11 input unavailable on this platform".into())}
#[cfg(test)] mod tests {use super::*; #[test] fn mappings() {assert_eq!(keysym("KeyA"),Some(97)); assert_eq!(keysym("Digit0"),Some(48)); assert_eq!(keysym("ArrowLeft"),Some(0xff51)); assert_eq!(keysym("F1"),Some(0xffbe)); assert_eq!(keysym("F12"),Some(0xffc9)); assert_eq!(keysym("F13"),None); assert_eq!(keysym("F01"),None); assert_eq!(keysym("F+1"),None); assert_eq!(keysym("MetaLeft"),Some(0xffeb)); assert_eq!(keysym("Delete"),Some(0xffff)); assert_eq!(keysym("Keya"),None); assert_eq!(keysym("../bad"),None);}}



