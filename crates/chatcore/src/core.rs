//! Account-level messaging on top of a `Store` — the Rust counterpart of signal.js `box()`.
//!
//! signal.js serializes work per contact (and claims under one global `x3dh` lock) and holds the
//! contact lock while the app stores a decrypted message. Here every call takes `&mut self` (the API
//! layer wraps the core in one mutex), and decryption is two-phase: `decrypt_from` authenticates,
//! claims and returns the plaintext without advancing the stored ratchet; the app stores the message,
//! then calls `commit`. A commit whose session record changed in between (a concurrent send or
//! receive for that contact) is refused as transient, and redelivery simply decrypts again.
use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ChatError, Result};
use crate::primitives::{b64, DhPair};
use crate::protocol::*;
use crate::store::{Store, Write};

const WEEK_MS: u64 = 7 * 86_400_000;
const DAY_MS: u64 = 86_400_000;
/// Rotation schedule choices (signal.js `ROTATION_CHOICES`); anything else is ignored, never trusted.
pub const ROTATION_CHOICES: [u64; 4] = [0, DAY_MS, 7 * DAY_MS, 30 * DAY_MS];

/// The shorter non-off interval wins; off on both sides (or unknown values) means no rotation.
pub fn rotation_interval(mine: u64, theirs: u64) -> u64 {
    [mine, theirs].into_iter().filter(|value| *value > 0 && ROTATION_CHOICES.contains(value)).min().unwrap_or(0)
}
const MAX_PENDING: usize = 256;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SessionRecord {
    pub active: Option<String>,
    pub list: BTreeMap<String, State>,
    pub order: Vec<String>,
    /// A manual or scheduled rotation is pending: the next send opens a new session (signal.js `rotating`).
    #[serde(default)]
    pub rotating: bool,
    /// The session our rotation opened; old chains go once the peer answers on it (signal.js `rotatedTo`).
    #[serde(default, rename = "rotatedTo")]
    pub rotated_to: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub identity: IdentityPub,
    pub verified: bool,
    pub changed: bool,
    #[serde(default)]
    pub blocked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SignedPreKeys {
    current: Option<SignedPreKey>,
    previous: Option<SignedPreKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OneTimePreKey {
    id: u64,
    pair: DhPair,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claim {
    contact: String,
    done: bool,
}

/// `prekeys()` result: what the app uploads (plus `oneTimePreKeys` when the server runs low).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrekeyUpload {
    pub identity: IdentityPub,
    pub rotated: bool,
    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: PublishedSignedPreKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptOutcome {
    Envelope(String),
    /// No sending session: fetch the contact's bundle from the server and call again with it.
    NeedsBundle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decrypted {
    /// Pass to `commit` once the message is stored (or `abort` to drop it).
    pub pending_id: String,
    pub plaintext_json: String,
    /// The message opened a session under a different identity than the one pinned for this contact.
    pub identity_changed: bool,
    pub first_contact: bool,
    /// The initiator identity of a new session (signal.js `info.identity`), else None.
    pub identity: Option<IdentityPub>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Safety {
    pub number: String,
    pub verified: bool,
    pub changed: bool,
    pub blocked: bool,
}

struct Pending {
    contact: String,
    snapshot: Option<Value>,
    state: State,
    fresh: Option<(u64, Handshake)>,
}

pub struct Core {
    store: Box<dyn Store>,
    pending: BTreeMap<String, Pending>,
    pending_order: VecDeque<String>,
    next_pending: u64,
}

fn same_identity(a: &IdentityPub, b: &IdentityPub) -> bool { a.dh == b.dh && a.sign == b.sign }
fn to_value<T: Serialize>(value: &T) -> Value { serde_json::to_value(value).expect("serializable") }
fn from_value<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T> { serde_json::from_value(value).map_err(ChatError::storage) }

fn remember(mut record: SessionRecord, state: State, make_active: bool) -> SessionRecord {
    let sid = state.sid.clone();
    record.list.insert(sid.clone(), state);
    record.order.retain(|value| value != &sid);
    record.order.push(sid.clone());
    while record.order.len() > MAX_SESSIONS {
        let oldest = record.order.remove(0);
        record.list.remove(&oldest);
    }
    let active_missing = record.active.as_ref().is_none_or(|active| !record.list.contains_key(active));
    // While a rotation is pending nothing old may become active again: the next send must open a new session.
    if make_active || (!record.rotating && active_missing) { record.active = Some(sid); }
    record
}

/// Keeps only one session (signal.js `only`), clearing any rotation state.
fn only(record: SessionRecord, sid: &str) -> SessionRecord {
    let mut list = BTreeMap::new();
    if let Some(state) = record.list.get(sid) { list.insert(sid.to_string(), state.clone()); }
    SessionRecord { active: Some(sid.to_string()), list, order: vec![sid.to_string()], rotating: false, rotated_to: None }
}

impl Core {
    pub fn new(store: Box<dyn Store>) -> Self {
        Self { store, pending: BTreeMap::new(), pending_order: VecDeque::new(), next_pending: 1 }
    }

    fn get<T: for<'de> Deserialize<'de>>(&mut self, key: &str) -> Result<Option<T>> {
        self.store.get(key)?.map(from_value).transpose()
    }

    pub fn identity(&mut self) -> Result<Identity> {
        if let Some(identity) = self.get::<Identity>("identity")? { return Ok(identity); }
        let identity = generate_identity();
        self.store.put("identity", to_value(&identity))?;
        Ok(identity)
    }

    /// Current signed prekey, rotated weekly (`max_age_ms`); replay records under a retired prekey go with it.
    pub fn prekeys(&mut self, now: u64, max_age_ms: Option<u64>) -> Result<PrekeyUpload> {
        let me = self.identity()?;
        let mut spks = self.get::<SignedPreKeys>("spk")?.unwrap_or_default();
        let mut rotated = false;
        let expired = spks.current.as_ref().is_none_or(|current| now.saturating_sub(current.created_at) > max_age_ms.unwrap_or(WEEK_MS));
        if expired {
            let retired = spks.previous.take();
            let next_id = spks.current.as_ref().map_or(0, |current| current.id) + 1;
            spks = SignedPreKeys { current: Some(generate_signed_prekey(&me, next_id, now)), previous: spks.current.take() };
            self.store.put("spk", to_value(&spks))?;
            rotated = true;
            if let Some(retired) = retired {
                self.store.delete_prefix(&format!("claim:{}:", retired.id))?;
                self.store.delete_prefix(&format!("claims:{}:", retired.id))?;
            }
        }
        let current = spks.current.expect("present after rotation check");
        Ok(PrekeyUpload { identity: me.public, rotated, signed_pre_key: PublishedSignedPreKey { id: current.id, key: current.public, signature: current.signature } })
    }

    pub fn one_time_prekeys(&mut self, count: u64) -> Result<Vec<PublishedOneTimePreKey>> {
        let mut next = self.get::<u64>("opk-next")?.unwrap_or(1);
        let mut writes = Vec::new();
        let mut out = Vec::new();
        for _ in 0..count {
            let pair = DhPair::generate();
            out.push(PublishedOneTimePreKey { id: next, key: b64(&pair.public) });
            writes.push(Write::Put(format!("opk:{next}"), to_value(&OneTimePreKey { id: next, pair })));
            next += 1;
        }
        writes.push(Write::Put("opk-next".into(), Value::from(next)));
        self.store.batch(writes)?;
        Ok(out)
    }

    pub fn peer(&mut self, contact: &str) -> Result<Option<PeerRecord>> { self.get(&format!("peer:{contact}")) }

    /// Trust on first use. A different identity (either half) clears verification, blocks sending until
    /// `accept_change`, and drops that contact's sessions. Returns the writes so callers can batch them.
    fn note_peer_writes(&mut self, contact: &str, public: &IdentityPub) -> Result<(PeerRecord, Vec<Write>, bool)> {
        let known = self.peer(contact)?;
        if let Some(known) = &known { if same_identity(&known.identity, public) { return Ok((known.clone(), Vec::new(), false)); } }
        let changed = known.is_some();
        let record = PeerRecord { identity: public.clone(), verified: false, changed, blocked: changed };
        let mut writes = vec![Write::Put(format!("peer:{contact}"), to_value(&record))];
        if changed { writes.push(Write::Delete(format!("sessions:{contact}"))); }
        Ok((record, writes, changed))
    }

    pub fn note_peer(&mut self, contact: &str, public: &IdentityPub) -> Result<PeerRecord> {
        let (record, writes, _) = self.note_peer_writes(contact, public)?;
        if !writes.is_empty() { self.store.batch(writes)?; }
        Ok(record)
    }

    fn assert_sendable(&mut self, contact: &str) -> Result<()> {
        if self.peer(contact)?.is_some_and(|peer| peer.blocked) {
            return Err(ChatError::coded("identity-blocked", "Security code changed. Review it before sending."));
        }
        Ok(())
    }

    fn sessions(&mut self, contact: &str) -> Result<SessionRecord> { Ok(self.get(&format!("sessions:{contact}"))?.unwrap_or_default()) }

    pub fn encrypt_to(&mut self, contact: &str, plaintext_json: &str, bundle: Option<&Bundle>) -> Result<EncryptOutcome> {
        serde_json::from_str::<Value>(plaintext_json).map_err(|_| ChatError::coded("invalid", "Plaintext must be JSON"))?;
        self.assert_sendable(contact)?;
        let mut record = self.sessions(contact)?;
        let active = record.active.as_ref().and_then(|sid| record.list.get(sid)).filter(|state| state.cks.is_some()).cloned();
        let state = match active.filter(|_| !record.rotating) {
            Some(state) => state,
            None => {
                let Some(bundle) = bundle else { return Ok(EncryptOutcome::NeedsBundle) };
                self.note_peer(contact, &bundle.identity)?;
                self.assert_sendable(contact)?;
                record = self.sessions(contact)?;
                let state = initiate(&self.identity()?, bundle)?;
                // A manual or scheduled rotation: older sessions stay (bounded) so messages already in flight
                // still decrypt, and are dropped once the peer answers on this new one.
                if record.rotating { record.rotating = false; record.rotated_to = Some(state.sid.clone()); }
                state
            }
        };
        let (next, envelope) = encrypt(&state, plaintext_json.as_bytes())?;
        self.store.put(&format!("sessions:{contact}"), to_value(&remember(record, next, true)))?;
        Ok(EncryptOutcome::Envelope(envelope))
    }

    fn claim(&mut self, spk_id: u64, ek: &str, contact: &str) -> Result<()> {
        let key = format!("claim:{spk_id}:{ek}");
        if let Some(existing) = self.get::<Claim>(&key)? {
            if existing.contact != contact || existing.done { return Err(ChatError::replay()); }
            return Ok(());
        }
        let counter = format!("claims:{spk_id}:{contact}");
        let count = self.get::<u64>(&counter)?.unwrap_or(0);
        if count >= MAX_CLAIMS_PER_CONTACT { return Err(ChatError::coded("claim-limit", "Too many new sessions from this contact")); }
        self.store.batch(vec![Write::Put(key, to_value(&Claim { contact: contact.into(), done: false })), Write::Put(counter, Value::from(count + 1))])
    }

    /// Authenticates and decrypts without advancing the stored ratchet. `published` is the identity the
    /// server publishes for this contact (defence in depth only — circular if the server is the attacker).
    pub fn decrypt_from(&mut self, contact: &str, envelope: &str, published: Option<&IdentityPub>) -> Result<Decrypted> {
        let parsed = parse_envelope(envelope)?;
        let record = self.sessions(contact)?;
        let snapshot = self.store.get(&format!("sessions:{contact}"))?;
        let mut fresh = None;
        let state = match record.list.get(&parsed.header.sid) {
            Some(state) => state.clone(),
            None => {
                let Some(x) = parsed.header.x.clone() else { return Err(ChatError::coded("unknown-session", "Unknown session")) };
                let me = self.identity()?;
                let spks = self.get::<SignedPreKeys>("spk")?.unwrap_or_default();
                let spk = [spks.current, spks.previous].into_iter().flatten().find(|value| value.id == x.spk)
                    .ok_or_else(|| ChatError::coded("unknown-spk", "Unknown signed prekey"))?;
                let opk = match x.opk {
                    // A consumed one-time prekey is gone only after a completed claim, so this is a replay.
                    Some(id) => Some(self.get::<OneTimePreKey>(&format!("opk:{id}"))?.ok_or_else(|| ChatError::coded("replay", "One-time prekey already used"))?.pair),
                    None => None,
                };
                let state = respond(&me, &spk, opk.as_ref(), &parsed.header)?;
                fresh = Some((spk.id, x));
                state
            }
        };
        let (next, plaintext) = decrypt(&state, &parsed)?; // Authenticate before claiming anything.
        if let Some((spk_id, x)) = &fresh { self.claim(*spk_id, &x.ek, contact)?; }
        let known = if fresh.is_some() { self.peer(contact)? } else { None };
        let identity_changed = match (&fresh, &known) { (Some((_, x)), Some(known)) => !same_identity(&known.identity, &x.ik), _ => false };
        let first_contact = fresh.is_some() && known.is_none();
        let plaintext_json = String::from_utf8(plaintext).map_err(|_| ChatError::coded("invalid", "Invalid message content"))?;
        serde_json::from_str::<Value>(&plaintext_json).map_err(|_| ChatError::coded("invalid", "Invalid message content"))?;
        let identity = fresh.as_ref().map(|(_, x)| x.ik.clone());
        if let (Some(identity), Some(published)) = (&identity, published) {
            if !same_identity(identity, published) { return Err(ChatError::coded("mismatch", "Identity mismatch")); }
        }
        let pending_id = self.next_pending.to_string();
        self.next_pending += 1;
        self.pending.insert(pending_id.clone(), Pending { contact: contact.into(), snapshot, state: next, fresh });
        self.pending_order.push_back(pending_id.clone());
        while self.pending_order.len() > MAX_PENDING {
            if let Some(oldest) = self.pending_order.pop_front() { self.pending.remove(&oldest); }
        }
        Ok(Decrypted { pending_id, plaintext_json, identity_changed, first_contact, identity })
    }

    /// Persists the ratchet advance (and, for a new session, the pinned identity, the completed claim and
    /// the one-time prekey deletion) in one atomic batch. Returns whether a changed identity was recorded.
    /// `rotate`: the stored message was the peer's session reset (signal.js handle() answering `{ rotate: true }`).
    pub fn commit(&mut self, pending_id: &str, rotate: bool) -> Result<bool> {
        let pending = self.pending.remove(pending_id).ok_or_else(|| ChatError::transient("Unknown or expired pending message; decrypt again"))?;
        self.pending_order.retain(|id| id != pending_id);
        let key = format!("sessions:{}", pending.contact);
        if self.store.get(&key)? != pending.snapshot { return Err(ChatError::transient("Session changed concurrently; decrypt again")); }
        let mut record: SessionRecord = pending.snapshot.map(from_value).transpose()?.unwrap_or_default();
        let mut writes = Vec::new();
        let mut changed = false;
        if let Some((_, x)) = &pending.fresh {
            let (_, peer_writes, was_changed) = self.note_peer_writes(&pending.contact, &x.ik)?;
            if was_changed { record = SessionRecord::default(); }
            changed = was_changed;
            writes.extend(peer_writes.into_iter().filter(|write| !matches!(write, Write::Delete(k) if k == &key)));
        }
        let fresh = pending.fresh.is_some();
        let sid = pending.state.sid.clone();
        // A late message on an old session must not undo a rotation in progress. A fresh session from the
        // peer is itself new keys, so it simply becomes the one in use.
        let keep_rotation = !fresh && (record.rotating || record.rotated_to.as_ref().is_some_and(|to| to != &sid));
        let answered_rotation = !fresh && record.rotated_to.as_deref() == Some(sid.as_str());
        if fresh { record.rotating = false; record.rotated_to = None; }
        let mut next = remember(record, pending.state, !keep_rotation);
        // The peer answered on the session we rotated to: the old chains are no longer needed.
        if answered_rotation { next = only(next, &sid); }
        // The peer reset the session: keep only the new one it opened; a reset on an older session is ignored.
        if rotate && (fresh || answered_rotation) { next = only(next, &sid); }
        writes.push(Write::Put(key, to_value(&next)));
        if let Some((spk_id, x)) = &pending.fresh {
            writes.push(Write::Put(format!("claim:{spk_id}:{}", x.ek), to_value(&Claim { contact: pending.contact.clone(), done: true })));
            if let Some(opk) = x.opk { writes.push(Write::Delete(format!("opk:{opk}"))); }
        }
        self.store.batch(writes)?;
        Ok(changed)
    }

    pub fn abort(&mut self, pending_id: &str) {
        self.pending.remove(pending_id);
        self.pending_order.retain(|id| id != pending_id);
    }

    pub fn safety(&mut self, my_username: &str, contact: &str, their_username: &str) -> Result<Option<Safety>> {
        let me = self.identity()?;
        let Some(peer) = self.peer(contact)? else { return Ok(None) };
        let number = safety_number((my_username, &me.public), (their_username, &peer.identity))?;
        Ok(Some(Safety { number, verified: peer.verified, changed: peer.changed, blocked: peer.blocked }))
    }

    pub fn set_verified(&mut self, contact: &str, verified: bool) -> Result<()> {
        if let Some(mut peer) = self.peer(contact)? {
            peer.verified = verified;
            if verified { peer.changed = false; }
            peer.blocked = false;
            self.store.put(&format!("peer:{contact}"), to_value(&peer))?;
        }
        Ok(())
    }

    /// The user reviewed a changed security code and keeps messaging (without marking it verified).
    pub fn accept_change(&mut self, contact: &str) -> Result<()> {
        if let Some(mut peer) = self.peer(contact)? {
            peer.changed = false;
            peer.blocked = false;
            self.store.put(&format!("peer:{contact}"), to_value(&peer))?;
        }
        Ok(())
    }

    pub fn forget(&mut self, contact: &str) -> Result<()> { self.store.delete(&format!("sessions:{contact}")) }

    /// Starts a fresh session (new X3DH) with the next message; older sessions stay until the peer answers.
    pub fn rotate(&mut self, contact: &str) -> Result<()> {
        let mut record = self.sessions(contact)?;
        record.active = None;
        record.rotating = true;
        record.rotated_to = None;
        self.store.put(&format!("sessions:{contact}"), to_value(&record))
    }

    /// The active session's id and start time; sessions from before start times were recorded count from now.
    pub fn session_info(&mut self, contact: &str) -> Result<Option<(String, u64)>> {
        let mut record = self.sessions(contact)?;
        let Some(sid) = record.active.clone() else { return Ok(None) };
        let Some(state) = record.list.get_mut(&sid) else { return Ok(None) };
        if let Some(started) = state.started_at { return Ok(Some((sid, started))); }
        let started = now_ms();
        state.started_at = Some(started);
        self.store.put(&format!("sessions:{contact}"), to_value(&record))?;
        Ok(Some((sid, started)))
    }

    /// A new identity for this device: every session, prekey and replay record goes with the old one; pinned
    /// contact identities stay. The API mutex serializes this against in-flight encrypt/decrypt, and pending
    /// decrypts of the old identity are dropped so they can never be committed afterwards.
    pub fn reset_identity(&mut self) -> Result<()> {
        self.pending.clear();
        self.pending_order.clear();
        for prefix in ["sessions:", "opk:", "claim:", "claims:"] { self.store.delete_prefix(prefix)?; }
        self.store.batch(vec![Write::Delete("identity".into()), Write::Delete("spk".into()), Write::Delete("opk-next".into())])
    }

    #[doc(hidden)]
    pub fn store_mut(&mut self) -> &mut dyn Store { self.store.as_mut() }
}
