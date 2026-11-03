//! Bounded process-local hashing handles for the local file sender.
//! These operations grant no access to a session, filesystem or network.
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::{Mutex, OnceLock}, time::{Duration, Instant}};

const MAX_HANDLES: usize = 8;
const MAX_BYTES: u64 = 1024 * 1024 * 1024;
struct Hasher { digest: Sha256, bytes: u64, touched: Instant }
static HASHES: OnceLock<Mutex<HashMap<String, Hasher>>> = OnceLock::new();
fn handles() -> &'static Mutex<HashMap<String, Hasher>> { HASHES.get_or_init(|| Mutex::new(HashMap::new())) }
pub fn begin() -> Result<String, String> {
    let mut map = handles().lock().map_err(|_| "hash state unavailable")?;
    map.retain(|_, h| h.touched.elapsed() < Duration::from_secs(120));
    if map.len() >= MAX_HANDLES { return Err("too many hashing handles".into()); }
    let mut random = [0u8; 24];
    SystemRandom::new().fill(&mut random).map_err(|_| "random generation failed")?;
    let id = STANDARD.encode(random);
    map.insert(id.clone(), Hasher { digest: Sha256::new(), bytes: 0, touched: Instant::now() });
    Ok(id)
}
pub fn update(id: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > 256 * 1024 { return Err("invalid hash chunk length".into()); }
    let mut map = handles().lock().map_err(|_| "hash state unavailable")?;
    let hash = map.get_mut(id).ok_or("unknown hash handle")?;
    if hash.touched.elapsed() >= Duration::from_secs(120) || hash.bytes.saturating_add(bytes.len() as u64) > MAX_BYTES {
        map.remove(id); return Err("hash expired or file too large".into());
    }
    hash.digest.update(bytes); hash.bytes += bytes.len() as u64; hash.touched = Instant::now();
    Ok(())
}
pub fn finish(id: &str) -> Result<String, String> {
    let hash = handles().lock().map_err(|_| "hash state unavailable")?.remove(id).ok_or("unknown hash handle")?;
    if hash.touched.elapsed() >= Duration::from_secs(120) { return Err("hash expired".into()); }
    Ok(STANDARD.encode(hash.digest.finalize()))
}
pub fn cancel(id: &str) -> Result<(), String> {
    handles().lock().map_err(|_| "hash state unavailable")?.remove(id); Ok(())
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn streaming_hash_is_one_shot_and_matches_digest() {
        let id = begin().unwrap();
        update(&id, b"ab").unwrap(); update(&id, b"c").unwrap();
        assert_eq!(finish(&id).unwrap(), STANDARD.encode(Sha256::digest(b"abc")));
        assert!(finish(&id).is_err()); assert!(update(&id, b"x").is_err());
        let id = begin().unwrap(); assert!(update(&id, &[]).is_err());
        assert!(update(&id, &vec![0; 256 * 1024 + 1]).is_err()); cancel(&id).unwrap();
        assert!(finish(&id).is_err());
    }
}
