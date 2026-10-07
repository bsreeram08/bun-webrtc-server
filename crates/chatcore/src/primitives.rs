//! Byte-level primitives, each matching one helper in signal.js.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{ChatError, Result};

pub const ZERO_SALT: [u8; 32] = [0; 32];
pub const F: [u8; 32] = [0xff; 32];

// ---------- Encoding (b64 / unb64) ----------
pub fn b64(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }

fn b64_alphabet(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Strict base64url: alphabet only, canonical (re-encodes to the same text), optional exact length.
pub fn unb64(text: &str, length: Option<usize>) -> Result<Vec<u8>> {
    if !b64_alphabet(text) { return Err(ChatError::transient("Invalid encoding")); }
    // A strict decoder rejects non-zero trailing bits, which signal.js rejects via its canonical re-encode check.
    let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| ChatError::transient("Invalid encoding"))?;
    if let Some(expected) = length { if bytes.len() != expected { return Err(ChatError::transient("Invalid key length")); } }
    if b64(&bytes) != text { return Err(ChatError::transient("Invalid encoding")); }
    Ok(bytes)
}

pub fn unb64_32(text: &str) -> Result<[u8; 32]> {
    let bytes = unb64(text, Some(32))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn is_key_b64(text: &str) -> bool { text.len() == 43 && b64_alphabet(text) }
pub fn is_b64(text: &str) -> bool { b64_alphabet(text) }

pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts { out.extend_from_slice(part); }
    out
}

// ---------- Secrets ----------
/// 32 secret bytes, wiped on drop, serialized as base64url for storage.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Secret32(pub [u8; 32]);

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Secret32(..)") }
}
impl Serialize for Secret32 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> { s.serialize_str(&b64(&self.0)) }
}
impl<'de> Deserialize<'de> for Secret32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let mut text = String::deserialize(d)?;
        let bytes = unb64_32(&text).map_err(serde::de::Error::custom);
        text.zeroize();
        Ok(Secret32(bytes?))
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

// ---------- X25519 ----------
/// An X25519 key pair (signal.js `dhPair`): private scalar plus its public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhPair {
    pub secret: Secret32,
    #[serde(with = "b64_32")]
    pub public: [u8; 32],
}

impl DhPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        DhPair { secret: Secret32(secret.to_bytes()), public }
    }
}

/// X25519 shared secret. WebCrypto rejects an all-zero output (a low-order peer key); so do we,
/// uncoded like the browser's OperationError.
pub fn dh(pair: &DhPair, public: &[u8; 32]) -> Result<Secret32> {
    let secret = StaticSecret::from(pair.secret.0);
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() { return Err(ChatError::transient("Invalid public key")); }
    Ok(Secret32(shared.to_bytes()))
}

// ---------- KDFs ----------
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &str, length: usize) -> Vec<u8> {
    let mut out = vec![0u8; length];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info.as_bytes(), &mut out).expect("HKDF length within bounds");
    out
}

pub fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn split64(mut out: Vec<u8>) -> (Secret32, Secret32) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..64]);
    out.zeroize();
    (Secret32(a), Secret32(b))
}

/// KDF_RK: HKDF-SHA256 with the root key as salt → (root key, chain key).
pub fn kdf_rk(rk: &Secret32, dh_out: &Secret32) -> (Secret32, Secret32) {
    split64(hkdf(&dh_out.0, &rk.0, "webrtc-bun-ratchet-v1", 64))
}

/// KDF_CK: HMAC-SHA256 with constants 0x02 (next chain key) and 0x01 (message key).
pub fn kdf_ck(ck: &Secret32) -> (Secret32, Secret32) {
    (Secret32(hmac(&ck.0, &[0x02])), Secret32(hmac(&ck.0, &[0x01])))
}

/// Message cipher: 44 HKDF bytes over the message key → AES-256 key (32) and GCM nonce (12).
struct MessageCipher { key: [u8; 32], iv: [u8; 12] }
impl Drop for MessageCipher { fn drop(&mut self) { self.key.zeroize(); } }

fn message_cipher(mk: &Secret32) -> MessageCipher {
    let mut out = hkdf(&mk.0, &ZERO_SALT, "webrtc-bun-message-v1", 44);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&out[..32]);
    iv.copy_from_slice(&out[32..44]);
    out.zeroize();
    MessageCipher { key, iv }
}

pub fn seal(mk: &Secret32, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = message_cipher(mk);
    Aes256Gcm::new_from_slice(&cipher.key)
        .expect("32-byte key")
        .encrypt(Nonce::from_slice(&cipher.iv), Payload { msg: plaintext, aad })
        .expect("AES-GCM encryption cannot fail for bounded input")
}

pub fn open(mk: &Secret32, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = message_cipher(mk);
    Aes256Gcm::new_from_slice(&cipher.key)
        .expect("32-byte key")
        .decrypt(Nonce::from_slice(&cipher.iv), Payload { msg: ciphertext, aad })
        .map_err(|_| ChatError::coded("auth", "Message authentication failed"))
}

pub mod b64_32 {
    use super::{b64, unb64_32};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&b64(value)) }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        unb64_32(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

pub mod b64_vec {
    use super::{b64, unb64};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&b64(value)) }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        if text.is_empty() { return Ok(Vec::new()); }
        unb64(&text, None).map_err(serde::de::Error::custom)
    }
}
