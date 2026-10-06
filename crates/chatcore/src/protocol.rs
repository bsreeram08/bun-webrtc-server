//! X3DH, the Double Ratchet, the envelope format and safety numbers — a line-by-line port of
//! packages/signaling/public/signal.js. The wire format (header JSON key order, base64url, AD bytes)
//! must stay byte-identical; tests/interop/run.mjs checks it against the JavaScript implementation.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha512};

use crate::error::{ChatError, Result};
use crate::primitives::*;

pub const MAX_SKIP: u64 = 1000;
pub const MAX_STORED_SKIPPED: usize = 2000;
pub const MAX_SESSIONS: usize = 4;
pub const PREKEY_BATCH: u64 = 100;
pub const MAX_CLAIMS_PER_CONTACT: u64 = 20;
const MAX_OLD_CHAINS: usize = 16;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

// ---------- Keys ----------
/// Public identity: separate X25519 (dh) and Ed25519 (sign) keys. Field order is part of the wire format.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPub {
    pub dh: String,
    pub sign: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    /// Ed25519 seed.
    pub sign: Secret32,
    pub dh: DhPair,
    #[serde(rename = "pub")]
    pub public: IdentityPub,
}

pub fn generate_identity() -> Identity {
    let signing = SigningKey::generate(&mut OsRng);
    let dh = DhPair::generate();
    let public = IdentityPub { dh: b64(&dh.public), sign: b64(signing.verifying_key().as_bytes()) };
    Identity { sign: Secret32(signing.to_bytes()), dh, public }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub id: u64,
    pub pair: DhPair,
    #[serde(rename = "pub")]
    pub public: String,
    pub signature: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}

fn spk_message(public: &[u8]) -> Vec<u8> { concat(&[b"webrtc-bun-spk-v1", public]) }

pub fn generate_signed_prekey(identity: &Identity, id: u64, now: u64) -> SignedPreKey {
    let pair = DhPair::generate();
    let signing = SigningKey::from_bytes(&identity.sign.0);
    let signature = signing.sign(&spk_message(&pair.public));
    SignedPreKey { id, public: b64(&pair.public), signature: b64(&signature.to_bytes()), pair, created_at: now }
}

/// What a peer publishes: `{ identity, signedPreKey: { id, key, signature }, oneTimePreKey: { id, key } | null }`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedSignedPreKey {
    pub id: u64,
    pub key: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublishedOneTimePreKey {
    pub id: u64,
    pub key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    pub identity: IdentityPub,
    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: PublishedSignedPreKey,
    #[serde(rename = "oneTimePreKey", default)]
    pub one_time_pre_key: Option<PublishedOneTimePreKey>,
}

pub fn verify_signed_prekey(identity: &IdentityPub, spk: &PublishedSignedPreKey) -> Result<()> {
    let invalid = || ChatError::transient("Signed prekey signature is invalid");
    let key = VerifyingKey::from_bytes(&unb64_32(&identity.sign)?).map_err(|_| invalid())?;
    let signature = Signature::from_slice(&unb64(&spk.signature, Some(64))?).map_err(|_| invalid())?;
    // verify_strict: rejects small-order keys and non-canonical signatures (WebCrypto/OpenSSL do as well).
    key.verify_strict(&spk_message(&unb64(&spk.key, Some(32))?), &signature).map_err(|_| invalid())?;
    Ok(())
}

pub fn identity_bytes(public: &IdentityPub) -> Result<Vec<u8>> {
    Ok(concat(&[&unb64(&public.dh, Some(32))?, &unb64(&public.sign, Some(32))?]))
}

// ---------- Header and envelope ----------
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainHeader {
    pub dh: String,
    pub pn: u64,
    pub n: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handshake {
    pub ik: IdentityPub,
    pub ek: String,
    pub spk: u64,
    pub opk: Option<u64>,
}
/// The canonical header: `{ v: 1, sid, h: { dh, pn, n }, x?: { ik: { dh, sign }, ek, spk, opk } }`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub v: u8,
    pub sid: String,
    pub h: ChainHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<Handshake>,
}
#[derive(Serialize)]
struct EnvelopeOut<'a> {
    #[serde(flatten)]
    header: &'a Header,
    c: String,
}

impl Header {
    pub fn json(&self) -> String { serde_json::to_string(self).expect("header serializes") }
}

pub struct Parsed {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// `Number.isSafeInteger(value) && value >= 0` on a parsed JSON value.
fn safe_integer(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    if let Some(n) = value.as_u64() { return (n <= MAX_SAFE_INTEGER).then_some(n); }
    let f = value.as_f64()?;
    (f.fract() == 0.0 && f >= 0.0 && f <= MAX_SAFE_INTEGER as f64).then_some(f as u64)
}
fn key_field(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).filter(|text| is_key_b64(text)).map(str::to_string)
}

pub fn parse_envelope(envelope: &str) -> Result<Parsed> {
    if envelope.len() > 90000 { return Err(ChatError::malformed()); }
    let bytes = unb64(envelope, None).map_err(|_| ChatError::malformed())?;
    let text = String::from_utf8(bytes).map_err(|_| ChatError::malformed())?;
    let packet: Value = serde_json::from_str(&text).map_err(|_| ChatError::malformed())?;
    let object = packet.as_object().ok_or_else(ChatError::malformed)?;
    if object.get("v").and_then(Value::as_f64) != Some(1.0) { return Err(ChatError::malformed()); }
    let sid = key_field(object.get("sid")).ok_or_else(ChatError::malformed)?;
    let h = object.get("h").and_then(Value::as_object).ok_or_else(ChatError::malformed)?;
    let dh = key_field(h.get("dh")).ok_or_else(ChatError::malformed)?;
    let pn = safe_integer(h.get("pn")).ok_or_else(ChatError::malformed)?;
    let n = safe_integer(h.get("n")).ok_or_else(ChatError::malformed)?;
    let c = object.get("c").and_then(Value::as_str).filter(|text| is_b64(text)).ok_or_else(ChatError::malformed)?;
    let x = match object.get("x") {
        None => None,
        Some(value) => {
            let x = value.as_object().ok_or_else(ChatError::malformed)?;
            let ik = x.get("ik").and_then(Value::as_object);
            let ik_dh = key_field(ik.and_then(|ik| ik.get("dh"))).ok_or_else(ChatError::malformed)?;
            let ik_sign = key_field(ik.and_then(|ik| ik.get("sign"))).ok_or_else(ChatError::malformed)?;
            let ek = x.get("ek").and_then(Value::as_str).filter(|ek| *ek == sid).ok_or_else(ChatError::malformed)?;
            let spk = safe_integer(x.get("spk")).ok_or_else(ChatError::malformed)?;
            let opk = match x.get("opk") {
                Some(Value::Null) => None,
                other => Some(safe_integer(other).ok_or_else(ChatError::malformed)?),
            };
            Some(Handshake { ik: IdentityPub { dh: ik_dh, sign: ik_sign }, ek: ek.to_string(), spk, opk })
        }
    };
    let ciphertext = unb64(c, None).map_err(|_| ChatError::malformed())?;
    Ok(Parsed { header: Header { v: 1, sid, h: ChainHeader { dh, pn, n }, x }, ciphertext })
}

// ---------- Double Ratchet ----------
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub sid: String,
    #[serde(with = "b64_vec")]
    pub ad: Vec<u8>,
    pub peer: IdentityPub,
    pub dhs: DhPair,
    /// Remote ratchet key, base64url (canonical, so string equality is byte equality).
    pub dhr: Option<String>,
    pub rk: Secret32,
    pub cks: Option<Secret32>,
    pub ckr: Option<Secret32>,
    pub ns: u64,
    pub nr: u64,
    pub pn: u64,
    /// Skipped message keys in insertion order, keyed `${dhr}:${n}` like signal.js.
    pub skipped: Vec<(String, Secret32)>,
    #[serde(rename = "oldDhr")]
    pub old_dhr: Vec<String>,
    pub init: Option<Handshake>,
}

fn ratchet_step(state: &mut State, remote: &str) -> Result<()> {
    if let Some(previous) = state.dhr.take() {
        state.old_dhr.push(previous);
        let excess = state.old_dhr.len().saturating_sub(MAX_OLD_CHAINS);
        state.old_dhr.drain(..excess);
    }
    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.dhr = Some(remote.to_string());
    let remote_bytes = unb64_32(remote)?;
    let (rk, ckr) = kdf_rk(&state.rk, &dh(&state.dhs, &remote_bytes)?);
    state.rk = rk;
    state.ckr = Some(ckr);
    state.dhs = DhPair::generate();
    let (rk, cks) = kdf_rk(&state.rk, &dh(&state.dhs, &remote_bytes)?);
    state.rk = rk;
    state.cks = Some(cks);
    Ok(())
}

fn skip_until(state: &mut State, until: u64) -> Result<()> {
    let Some(mut ckr) = state.ckr.clone() else { return Ok(()) };
    if until as i128 - state.nr as i128 > MAX_SKIP as i128 { return Err(ChatError::coded("skip-limit", "Too many skipped messages")); }
    let dhr = state.dhr.clone().unwrap_or_default();
    while state.nr < until {
        let (next, mk) = kdf_ck(&ckr);
        ckr = next;
        let key = format!("{dhr}:{}", state.nr);
        // Like assigning an existing object property in JS: replace in place, keep insertion order.
        match state.skipped.iter_mut().find(|(existing, _)| existing == &key) {
            Some(slot) => slot.1 = mk,
            None => state.skipped.push((key, mk)),
        }
        state.nr += 1;
    }
    state.ckr = Some(ckr);
    let excess = state.skipped.len().saturating_sub(MAX_STORED_SKIPPED);
    state.skipped.drain(..excess);
    Ok(())
}

fn aad(state: &State, header: &Header) -> Vec<u8> { concat(&[&state.ad, header.json().as_bytes()]) }

/// Returns the advanced state and the envelope; the input state is untouched (signal.js `copy`).
pub fn encrypt(session: &State, plaintext: &[u8]) -> Result<(State, String)> {
    let mut state = session.clone();
    let cks = state.cks.clone().ok_or_else(|| ChatError::transient("Session cannot send yet"))?;
    let (next, mk) = kdf_ck(&cks);
    state.cks = Some(next);
    let header = Header { v: 1, sid: state.sid.clone(), h: ChainHeader { dh: b64(&state.dhs.public), pn: state.pn, n: state.ns }, x: state.init.clone() };
    state.ns += 1;
    let ciphertext = seal(&mk, &aad(&state, &header), plaintext);
    let json = serde_json::to_string(&EnvelopeOut { header: &header, c: b64(&ciphertext) }).expect("envelope serializes");
    Ok((state, b64(json.as_bytes())))
}

pub fn decrypt(session: &State, parsed: &Parsed) -> Result<(State, Vec<u8>)> {
    let mut state = session.clone();
    let header = &parsed.header;
    // signal.js decodes the remote key first; a non-canonical key is an uncoded (transient) error there too.
    unb64_32(&header.h.dh)?;
    let skipped_key = format!("{}:{}", header.h.dh, header.h.n);
    let mk = if let Some(index) = state.skipped.iter().position(|(key, _)| key == &skipped_key) {
        state.skipped.remove(index).1 // Each message key is usable once.
    } else {
        if state.dhr.as_deref() == Some(header.h.dh.as_str()) {
            if header.h.n < state.nr { return Err(ChatError::replay()); }
        } else if state.old_dhr.contains(&header.h.dh) {
            return Err(ChatError::replay()); // An old chain whose key was already used.
        } else {
            skip_until(&mut state, header.h.pn)?;
            ratchet_step(&mut state, &header.h.dh)?;
        }
        skip_until(&mut state, header.h.n)?;
        let ckr = state.ckr.clone().ok_or_else(|| ChatError::transient("No receiving chain"))?;
        let (next, mk) = kdf_ck(&ckr);
        state.ckr = Some(next);
        state.nr += 1;
        mk
    };
    let plaintext = open(&mk, &aad(&state, header), &parsed.ciphertext)?;
    state.init = None; // The peer has this session now; stop resending the X3DH header.
    Ok((state, plaintext))
}

// ---------- X3DH ----------
pub fn initiate(identity: &Identity, bundle: &Bundle) -> Result<State> {
    verify_signed_prekey(&bundle.identity, &bundle.signed_pre_key)?;
    let ek = DhPair::generate();
    let spk = unb64_32(&bundle.signed_pre_key.key)?;
    let mut parts = vec![Secret32(F), dh(&identity.dh, &spk)?, dh(&ek, &unb64_32(&bundle.identity.dh)?)?, dh(&ek, &spk)?];
    if let Some(opk) = &bundle.one_time_pre_key { parts.push(dh(&ek, &unb64_32(&opk.key)?)?); }
    let sk = x3dh_secret(&parts);
    let dhs = DhPair::generate();
    let (rk, cks) = kdf_rk(&sk, &dh(&dhs, &spk)?);
    Ok(State {
        sid: b64(&ek.public),
        ad: concat(&[&identity_bytes(&identity.public)?, &identity_bytes(&bundle.identity)?]),
        peer: bundle.identity.clone(),
        dhs,
        dhr: Some(b64(&spk)),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: Vec::new(),
        old_dhr: Vec::new(),
        init: Some(Handshake { ik: identity.public.clone(), ek: b64(&ek.public), spk: bundle.signed_pre_key.id, opk: bundle.one_time_pre_key.as_ref().map(|opk| opk.id) }),
    })
}

fn x3dh_secret(parts: &[Secret32]) -> Secret32 {
    let refs: Vec<&[u8]> = parts.iter().map(|part| part.0.as_slice()).collect();
    let mut ikm = concat(&refs);
    let out = hkdf(&ikm, &ZERO_SALT, "webrtc-bun-x3dh-v1", 32);
    zeroize::Zeroize::zeroize(&mut ikm);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&out);
    Secret32(sk)
}

pub fn respond(identity: &Identity, spk: &SignedPreKey, opk: Option<&DhPair>, header: &Header) -> Result<State> {
    let x = header.x.as_ref().ok_or_else(|| ChatError::coded("unknown-session", "Unknown session"))?;
    let ek = unb64_32(&x.ek)?;
    let mut parts = vec![Secret32(F), dh(&spk.pair, &unb64_32(&x.ik.dh)?)?, dh(&identity.dh, &ek)?, dh(&spk.pair, &ek)?];
    if let Some(opk) = opk { parts.push(dh(opk, &ek)?); }
    let sk = x3dh_secret(&parts);
    Ok(State {
        sid: x.ek.clone(),
        ad: concat(&[&identity_bytes(&x.ik)?, &identity_bytes(&identity.public)?]),
        peer: x.ik.clone(),
        dhs: spk.pair.clone(),
        dhr: None,
        rk: sk,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        skipped: Vec::new(),
        old_dhr: Vec::new(),
        init: None,
    })
}

// ---------- Safety numbers ----------
fn fingerprint(username: &str, identity: &IdentityPub) -> Result<String> {
    let id = identity_bytes(identity)?;
    let mut digest = concat(&[format!("webrtc-bun-safety-v1:{username}:").as_bytes(), &id]);
    for _ in 0..1024 {
        let mut hasher = Sha512::new();
        hasher.update(&digest);
        hasher.update(&id);
        digest = hasher.finalize().to_vec();
    }
    let mut digits = String::with_capacity(30);
    for chunk in 0..6 {
        let value = digest[chunk * 5..chunk * 5 + 5].iter().fold(0u64, |sum, byte| sum * 256 + *byte as u64);
        digits.push_str(&format!("{:05}", value % 100000));
    }
    Ok(digits)
}

/// 60 digits in groups of five, ordered by username so both sides display the same number.
pub fn safety_number(a: (&str, &IdentityPub), b: (&str, &IdentityPub)) -> Result<String> {
    let (first, second) = if a.0 < b.0 { (a, b) } else { (b, a) };
    let digits = fingerprint(first.0, first.1)? + &fingerprint(second.0, second.1)?;
    Ok(digits.as_bytes().chunks(5).map(|chunk| std::str::from_utf8(chunk).expect("ascii")).collect::<Vec<_>>().join(" "))
}
