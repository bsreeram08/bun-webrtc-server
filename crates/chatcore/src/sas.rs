//! Call verification code (port of verify.js): commit-then-reveal nonces over a dedicated data
//! channel, then a 6-digit code over both DTLS fingerprints and both nonces.
use sha2::{Digest, Sha256};

use crate::error::{ChatError, Result};
use crate::primitives::random_bytes;

const LABEL: &str = "webrtc-bun-sas-v1";

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn is_hex64(text: &str) -> bool { text.len() == 64 && text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) }

/// SHA-256 over the UTF-8 text, as verify.js hashes strings (not decoded bytes).
fn sha256_text(text: &str) -> [u8; 32] { Sha256::digest(text.as_bytes()).into() }

/// A fresh 32-byte nonce as lowercase hex.
pub fn new_nonce() -> String { hex(&random_bytes::<32>()) }

/// The commitment sent first: hex SHA-256 of the nonce's hex text.
pub fn commitment(nonce: &str) -> Result<String> {
    if !is_hex64(nonce) { return Err(ChatError::transient("Invalid verification packet")); }
    Ok(hex(&sha256_text(nonce)))
}

/// Checks a peer's reveal against the commitment it sent earlier.
pub fn check_reveal(peer_commitment: &str, peer_nonce: &str) -> bool {
    is_hex64(peer_commitment) && is_hex64(peer_nonce) && hex(&sha256_text(peer_nonce)) == peer_commitment
}

/// Exactly one `a=fingerprint:sha-256 XX:..` (32 bytes) per SDP; any other line mentioning
/// "fingerprint" fails closed so a decoy line can never be hashed in place of the real one.
pub fn fingerprints(sdp: &str) -> Result<String> {
    let mut values: Vec<String> = Vec::new();
    for raw in sdp.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if !line.to_ascii_lowercase().contains("fingerprint") { continue; }
        let value = line.strip_prefix("a=fingerprint:sha-256 ").filter(|value| {
            let parts: Vec<&str> = value.split(':').collect();
            parts.len() == 32 && parts.iter().all(|part| part.len() == 2 && part.bytes().all(|c| c.is_ascii_hexdigit()))
        });
        let Some(value) = value else { return Err(ChatError::transient("Unsupported DTLS fingerprint")) };
        let value = format!("sha-256 {}", value.to_ascii_uppercase());
        if !values.contains(&value) { values.push(value); }
    }
    if values.len() != 1 { return Err(ChatError::transient("Expected exactly one DTLS fingerprint")); }
    Ok(values.remove(0))
}

/// The code both people compare: "123 456".
pub fn sas_code(prints: [&str; 2], nonces: [&str; 2]) -> Result<String> {
    if prints.iter().any(|value| value.is_empty()) || !nonces.iter().all(|value| is_hex64(value)) {
        return Err(ChatError::transient("Invalid verification input"));
    }
    let mut prints = prints;
    prints.sort();
    let mut nonces = nonces;
    nonces.sort();
    let text = [LABEL, prints[0], prints[1], nonces[0], nonces[1]].join("\n");
    let digest = sha256_text(&text);
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    let code = format!("{value:06}");
    Ok(format!("{} {}", &code[..3], &code[3..]))
}

/// Convenience: fingerprints from both SDPs, then the code.
pub fn sas_from_sdp(local_sdp: &str, remote_sdp: &str, nonces: [&str; 2]) -> Result<String> {
    let local = fingerprints(local_sdp)?;
    let remote = fingerprints(remote_sdp)?;
    sas_code([&local, &remote], nonces)
}
