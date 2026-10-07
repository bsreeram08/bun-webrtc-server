//! The flat, flutter_rust_bridge-friendly API: owned types, no lifetimes, one process-wide core
//! behind a mutex (which also gives signal.js's per-contact and x3dh serialization). See API.md.
use std::sync::Mutex;

use crate::core::{Core, Decrypted, EncryptOutcome, PeerRecord, PrekeyUpload, Safety};
use crate::error::{ChatError, Result};
use crate::protocol::{Bundle, IdentityPub, PublishedOneTimePreKey};
use crate::sas;
use crate::store::{Open, SqliteStore};

static CORE: Mutex<Option<Core>> = Mutex::new(None);

fn with<T>(work: impl FnOnce(&mut Core) -> Result<T>) -> Result<T> {
    let mut guard = CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))?;
    // No open key database (never opened, or the last open failed): fail closed, never act on stale state.
    let core = guard.as_mut().ok_or_else(|| ChatError::storage("key database is not open"))?;
    work(core)
}

/// Opens the account's key database, sealed with `store_key` (32 bytes from the platform keystore).
/// `expect_existing`: the app created this database before (its keystore holds a key for it), so a missing
/// marker is a reset or replaced database and fails closed. Otherwise only an empty database is initialized.
/// No key, no implicit migration, no silent fresh start: every failure is a `storage` error.
pub fn init(db_path: String, store_key: Vec<u8>, expect_existing: bool) -> Result<()> {
    let key = <[u8; 32]>::try_from(store_key.as_slice()).map_err(|_| ChatError::storage("store key must be 32 bytes"))?;
    let mode = if expect_existing { Open::Existing } else { Open::Create };
    let mut guard = CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))?;
    // Close whatever was open first: a failed open must never leave a previous account's store in use.
    *guard = None;
    *guard = Some(Core::new(Box::new(SqliteStore::open_sealed(&db_path, key, mode)?)));
    Ok(())
}

pub fn identity() -> Result<IdentityPub> { with(|core| Ok(core.identity()?.public)) }

/// Signed prekey state to upload (rotates weekly). `now_ms` is Unix time in milliseconds.
pub fn prepare_prekeys(now_ms: u64) -> Result<PrekeyUpload> { with(|core| core.prekeys(now_ms, None)) }

pub fn one_time_prekeys(count: u64) -> Result<Vec<PublishedOneTimePreKey>> { with(|core| core.one_time_prekeys(count)) }

/// Encrypts a JSON payload for a contact. Without a sending session it returns `NeedsBundle`:
/// fetch `/api/keys/<username>` and call again with that JSON.
pub fn encrypt_to(contact_id: String, plaintext_json: String, bundle_json: Option<String>) -> Result<EncryptOutcome> {
    let bundle = bundle_json
        .map(|json| serde_json::from_str::<Bundle>(&json).map_err(|_| ChatError::transient("Invalid key bundle")))
        .transpose()?;
    with(|core| core.encrypt_to(&contact_id, &plaintext_json, bundle.as_ref()))
}

/// Phase one of receiving: decrypt and authenticate; store the message, then `commit(pending_id)`.
pub fn decrypt_from(contact_id: String, envelope: String, published_identity: Option<IdentityPub>) -> Result<Decrypted> {
    with(|core| core.decrypt_from(&contact_id, &envelope, published_identity.as_ref()))
}

/// Phase two: persist the ratchet advance. Returns true when a changed identity was recorded.
/// `rotate` is true when the stored payload was the peer's `{type:'rotate'}` session reset.
pub fn commit(pending_id: String, rotate: bool) -> Result<bool> { with(|core| core.commit(&pending_id, rotate)) }

pub fn abort(pending_id: String) -> Result<()> { with(|core| { core.abort(&pending_id); Ok(()) }) }

pub fn safety(my_username: String, contact_id: String, their_username: String) -> Result<Option<Safety>> {
    with(|core| core.safety(&my_username, &contact_id, &their_username))
}

pub fn peer(contact_id: String) -> Result<Option<PeerRecord>> { with(|core| core.peer(&contact_id)) }
pub fn set_verified(contact_id: String, verified: bool) -> Result<()> { with(|core| core.set_verified(&contact_id, verified)) }
pub fn accept_change(contact_id: String) -> Result<()> { with(|core| core.accept_change(&contact_id)) }
pub fn forget(contact_id: String) -> Result<()> { with(|core| core.forget(&contact_id)) }

/// Records an identity the server published for a contact (key-change events); a change is flagged and blocks sending.
pub fn note_peer(contact_id: String, identity: IdentityPub) -> Result<()> { with(|core| core.note_peer(&contact_id, &identity).map(|_| ())) }

/// Chat key rotation: the next message to this contact opens a fresh session.
pub fn rotate(contact_id: String) -> Result<()> { with(|core| core.rotate(&contact_id)) }

/// The active session with a contact: id and start time (Unix ms), for scheduled rotation.
pub fn session_info(contact_id: String) -> Result<Option<SessionInfo>> {
    with(|core| Ok(core.session_info(&contact_id)?.map(|(sid, started_at)| SessionInfo { sid, started_at })))
}

/// Replaces this device's identity (explicit user action only); contacts see a security-code change.
pub fn reset_identity() -> Result<()> { with(|core| core.reset_identity()) }

/// Chat key rotation schedule: the shorter non-off interval of the two sides wins (0 = off).
pub fn rotation_interval(mine: u64, theirs: u64) -> u64 { crate::core::rotation_interval(mine, theirs) }

pub struct SessionInfo {
    pub sid: String,
    pub started_at: u64,
}

// ---------- Call verification (verify.js) ----------
pub fn sas_new_nonce() -> String { sas::new_nonce() }
pub fn sas_commitment(nonce: String) -> Result<String> { sas::commitment(&nonce) }
pub fn sas_check_reveal(peer_commitment: String, peer_nonce: String) -> bool { sas::check_reveal(&peer_commitment, &peer_nonce) }
pub fn sas_code(local_sdp: String, remote_sdp: String, my_nonce: String, peer_nonce: String) -> Result<String> {
    sas::sas_from_sdp(&local_sdp, &remote_sdp, [&my_nonce, &peer_nonce])
}
