//! The flat, flutter_rust_bridge-friendly API: owned types, no lifetimes, one process-wide core
//! behind a mutex (which also gives signal.js's per-contact and x3dh serialization). See API.md.
use std::sync::Mutex;

use crate::core::{Core, Decrypted, EncryptOutcome, PeerRecord, PrekeyUpload, Safety};
use crate::error::{ChatError, Result};
use crate::protocol::{Bundle, IdentityPub, PublishedOneTimePreKey};
use crate::sas;
use crate::store::SqliteStore;

static CORE: Mutex<Option<Core>> = Mutex::new(None);

fn with<T>(work: impl FnOnce(&mut Core) -> Result<T>) -> Result<T> {
    let mut guard = CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))?;
    let core = guard.as_mut().ok_or_else(|| ChatError::transient("Call init(db_path) first"))?;
    work(core)
}

/// Opens (or creates) the account's key database. Call once per signed-in account.
pub fn init(db_path: String) -> Result<()> {
    let core = Core::new(Box::new(SqliteStore::open(&db_path)?));
    *CORE.lock().map_err(|_| ChatError::transient("Core lock poisoned"))? = Some(core);
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
pub fn commit(pending_id: String) -> Result<bool> { with(|core| core.commit(&pending_id)) }

pub fn abort(pending_id: String) -> Result<()> { with(|core| { core.abort(&pending_id); Ok(()) }) }

pub fn safety(my_username: String, contact_id: String, their_username: String) -> Result<Option<Safety>> {
    with(|core| core.safety(&my_username, &contact_id, &their_username))
}

pub fn peer(contact_id: String) -> Result<Option<PeerRecord>> { with(|core| core.peer(&contact_id)) }
pub fn set_verified(contact_id: String, verified: bool) -> Result<()> { with(|core| core.set_verified(&contact_id, verified)) }
pub fn accept_change(contact_id: String) -> Result<()> { with(|core| core.accept_change(&contact_id)) }
pub fn forget(contact_id: String) -> Result<()> { with(|core| core.forget(&contact_id)) }

// ---------- Call verification (verify.js) ----------
pub fn sas_new_nonce() -> String { sas::new_nonce() }
pub fn sas_commitment(nonce: String) -> Result<String> { sas::commitment(&nonce) }
pub fn sas_check_reveal(peer_commitment: String, peer_nonce: String) -> bool { sas::check_reveal(&peer_commitment, &peer_nonce) }
pub fn sas_code(local_sdp: String, remote_sdp: String, my_nonce: String, peer_nonce: String) -> Result<String> {
    sas::sas_from_sdp(&local_sdp, &remote_sdp, [&my_nonce, &peer_nonce])
}
