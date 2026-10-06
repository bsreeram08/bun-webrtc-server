//! What Dart sees (see `lib/src/rust/api.dart`). Prekey payloads cross as JSON strings because the app
//! uploads them to the server as JSON unchanged; everything else is typed.
use chatcore::api as core;
use chatcore::protocol::IdentityPub;
use chatcore::{ChatError, EncryptOutcome};
use flutter_rust_bridge::frb;

/// A core failure. `code` is the web client's vocabulary (replay, malformed, auth, …); `None` is transient.
#[derive(Debug)]
pub struct CoreError {
    pub code: Option<String>,
    pub message: String,
}
impl From<ChatError> for CoreError {
    fn from(error: ChatError) -> Self { Self { code: error.code, message: error.message } }
}
type Result<T> = std::result::Result<T, CoreError>;

pub struct Identity {
    pub dh: String,
    pub sign: String,
}
impl From<IdentityPub> for Identity {
    fn from(value: IdentityPub) -> Self { Self { dh: value.dh, sign: value.sign } }
}
impl From<Identity> for IdentityPub {
    fn from(value: Identity) -> Self { Self { dh: value.dh, sign: value.sign } }
}

pub struct Decrypted {
    pub pending_id: String,
    pub plaintext_json: String,
    pub identity_changed: bool,
    pub first_contact: bool,
    pub identity: Option<Identity>,
}

pub struct Safety {
    pub number: String,
    pub verified: bool,
    pub changed: bool,
    pub blocked: bool,
}

pub struct SessionInfo {
    pub sid: String,
    pub started_at: u64,
}

/// Opens the account's key database, sealed with `store_key` (32 bytes from the platform keystore).
/// `expect_existing`: the keystore already held this key, so the database must exist (fails closed otherwise).
pub fn init(db_path: String, store_key: Vec<u8>, expect_existing: bool) -> Result<()> { Ok(core::init(db_path, store_key, expect_existing)?) }

pub fn identity() -> Result<Identity> { Ok(core::identity()?.into()) }

/// JSON of `{identity, rotated, signedPreKey}` (signal.js `prekeys()`).
pub fn prepare_prekeys(now_ms: u64) -> Result<String> {
    Ok(serde_json::to_string(&core::prepare_prekeys(now_ms)?).map_err(|error| CoreError { code: None, message: error.to_string() })?)
}

/// JSON array of `{id, key}` one-time prekeys to upload.
pub fn one_time_prekeys(count: u64) -> Result<String> {
    Ok(serde_json::to_string(&core::one_time_prekeys(count)?).map_err(|error| CoreError { code: None, message: error.to_string() })?)
}

/// `Some(envelope)`, or `None` when there is no sending session: fetch the bundle and call again with it.
pub fn encrypt_to(contact_id: String, plaintext_json: String, bundle_json: Option<String>) -> Result<Option<String>> {
    Ok(match core::encrypt_to(contact_id, plaintext_json, bundle_json)? {
        EncryptOutcome::Envelope(envelope) => Some(envelope),
        EncryptOutcome::NeedsBundle => None,
    })
}

pub fn decrypt_from(contact_id: String, envelope: String, published_identity: Option<Identity>) -> Result<Decrypted> {
    let decrypted = core::decrypt_from(contact_id, envelope, published_identity.map(Into::into))?;
    Ok(Decrypted {
        pending_id: decrypted.pending_id,
        plaintext_json: decrypted.plaintext_json,
        identity_changed: decrypted.identity_changed,
        first_contact: decrypted.first_contact,
        identity: decrypted.identity.map(Into::into),
    })
}

/// After the message is stored. `rotate` when the payload was the peer's `{type:'rotate'}` session reset.
pub fn commit(pending_id: String, rotate: bool) -> Result<bool> { Ok(core::commit(pending_id, rotate)?) }
pub fn abort(pending_id: String) -> Result<()> { Ok(core::abort(pending_id)?) }

pub fn note_peer(contact_id: String, identity: Identity) -> Result<()> { Ok(core::note_peer(contact_id, identity.into())?) }

pub fn safety(my_username: String, contact_id: String, their_username: String) -> Result<Option<Safety>> {
    Ok(core::safety(my_username, contact_id, their_username)?.map(|value| Safety { number: value.number, verified: value.verified, changed: value.changed, blocked: value.blocked }))
}
pub fn set_verified(contact_id: String, verified: bool) -> Result<()> { Ok(core::set_verified(contact_id, verified)?) }
pub fn accept_change(contact_id: String) -> Result<()> { Ok(core::accept_change(contact_id)?) }
pub fn forget(contact_id: String) -> Result<()> { Ok(core::forget(contact_id)?) }

// ---- Chat key rotation ----
pub fn rotate(contact_id: String) -> Result<()> { Ok(core::rotate(contact_id)?) }
pub fn session_info(contact_id: String) -> Result<Option<SessionInfo>> {
    Ok(core::session_info(contact_id)?.map(|value| SessionInfo { sid: value.sid, started_at: value.started_at }))
}
pub fn reset_identity() -> Result<()> { Ok(core::reset_identity()?) }
#[frb(sync)]
pub fn rotation_interval(mine: u64, theirs: u64) -> u64 { core::rotation_interval(mine, theirs) }

// ---- Call verification (verify.js) ----
#[frb(sync)]
pub fn sas_new_nonce() -> String { core::sas_new_nonce() }
#[frb(sync)]
pub fn sas_commitment(nonce: String) -> Result<String> { Ok(core::sas_commitment(nonce)?) }
#[frb(sync)]
pub fn sas_check_reveal(peer_commitment: String, peer_nonce: String) -> bool { core::sas_check_reveal(peer_commitment, peer_nonce) }
#[frb(sync)]
pub fn sas_code(local_sdp: String, remote_sdp: String, my_nonce: String, peer_nonce: String) -> Result<String> {
    Ok(core::sas_code(local_sdp, remote_sdp, my_nonce, peer_nonce)?)
}
