//! Mirrors tests/unit/signal.test.ts (and the SAS cases of verify.js) against the Rust core.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chatcore::core::Core;
use chatcore::protocol::{self, Bundle, IdentityPub, PublishedOneTimePreKey};
use chatcore::sas;
use chatcore::store::{MemoryStore, Store, Write};
use chatcore::{ChatError, EncryptOutcome};
use serde_json::{json, Value};

const NOW: u64 = 1_800_000_000_000;
const WEEK: u64 = 7 * 86_400_000;

/// A store whose next N writes fail, shared with the test through an Arc.
struct Flaky { inner: MemoryStore, fail: Arc<AtomicUsize> }
impl Store for Flaky {
    fn get(&mut self, key: &str) -> chatcore::Result<Option<Value>> { self.inner.get(key) }
    fn delete_prefix(&mut self, prefix: &str) -> chatcore::Result<()> { self.inner.delete_prefix(prefix) }
    fn batch(&mut self, writes: Vec<Write>) -> chatcore::Result<()> {
        if self.fail.load(Ordering::SeqCst) > 0 { self.fail.fetch_sub(1, Ordering::SeqCst); return Err(ChatError::storage("injected")); }
        self.inner.batch(writes)
    }
}

struct Party { core: Core, fail: Arc<AtomicUsize> }
fn party() -> Party {
    let fail = Arc::new(AtomicUsize::new(0));
    Party { core: Core::new(Box::new(Flaky { inner: MemoryStore::default(), fail: fail.clone() })), fail }
}
impl Party {
    fn bundle(&mut self, with_opk: bool) -> Bundle {
        let keys = self.core.prekeys(NOW, None).unwrap();
        let opk: Option<PublishedOneTimePreKey> = with_opk.then(|| self.core.one_time_prekeys(1).unwrap().remove(0));
        Bundle { identity: keys.identity, signed_pre_key: keys.signed_pre_key, one_time_pre_key: opk }
    }
    fn send(&mut self, contact: &str, text: &str, peer: Option<&mut Party>) -> chatcore::Result<String> {
        let payload = json!({ "text": text }).to_string();
        match self.core.encrypt_to(contact, &payload, None)? {
            EncryptOutcome::Envelope(envelope) => Ok(envelope),
            EncryptOutcome::NeedsBundle => {
                let bundle = peer.expect("bundle needed").bundle(true);
                match self.core.encrypt_to(contact, &payload, Some(&bundle))? { EncryptOutcome::Envelope(envelope) => Ok(envelope), _ => unreachable!() }
            }
        }
    }
    fn receive(&mut self, contact: &str, envelope: &str) -> chatcore::Result<(String, bool)> {
        let decrypted = self.core.decrypt_from(contact, envelope, None)?;
        self.core.commit(&decrypted.pending_id, false)?;
        let text = serde_json::from_str::<Value>(&decrypted.plaintext_json).unwrap()["text"].as_str().unwrap().to_string();
        Ok((text, decrypted.identity_changed))
    }
}
fn code(result: chatcore::Result<impl std::fmt::Debug>) -> Option<String> { result.expect_err("expected an error").code }
fn packet(envelope: &str) -> Value { serde_json::from_slice(&URL_SAFE_NO_PAD.decode(envelope).unwrap()).unwrap() }
fn envelope(packet: &Value) -> String { URL_SAFE_NO_PAD.encode(packet.to_string()) }
fn flip(text: &str) -> String { let mut bytes = URL_SAFE_NO_PAD.decode(text).unwrap(); let last = bytes.len() - 1; bytes[last] ^= 1; URL_SAFE_NO_PAD.encode(bytes) }

/// alice initiates to bob (bob's bundle with or without a one-time prekey).
fn pair(with_opk: bool) -> (Party, Party, String) {
    let (mut alice, mut bob) = (party(), party());
    let bundle = bob.bundle(with_opk);
    let EncryptOutcome::Envelope(first) = alice.core.encrypt_to("bob", &json!({ "text": "hello bob" }).to_string(), Some(&bundle)).unwrap() else { unreachable!() };
    (alice, bob, first)
}

// ---------- X3DH and the Double Ratchet ----------
#[test]
fn both_sides_derive_the_same_secret_with_and_without_a_one_time_prekey() {
    for with_opk in [true, false] {
        let (mut alice, mut bob, first) = pair(with_opk);
        assert_eq!(bob.receive("alice", &first).unwrap().0, "hello bob");
        let reply = bob.send("alice", "hi alice", None).unwrap();
        assert_eq!(alice.receive("bob", &reply).unwrap().0, "hi alice");
    }
}

#[test]
fn a_wrong_identity_produces_no_shared_secret() {
    let (_alice, _bob, first) = pair(true);
    let mut other = party();
    other.bundle(true);
    // Unknown signed prekey id on the wrong device is rejected before any decryption.
    assert!(other.receive("alice", &first).is_err());
}

#[test]
fn in_order_out_of_order_and_multi_ratchet_delivery() {
    let (mut alice, mut bob, first) = pair(true);
    let mut sent = vec![first];
    for i in 1..5 { sent.push(alice.send("bob", &format!("a{i}"), None).unwrap()); }
    let mut seen = vec![bob.receive("alice", &sent[0]).unwrap().0];
    for i in [3, 1, 2, 4] { seen.push(bob.receive("alice", &sent[i]).unwrap().0); }
    assert_eq!(seen, ["hello bob", "a3", "a1", "a2", "a4"]);
    for round in 0..3 {
        let reply = bob.send("alice", &format!("b{round}"), None).unwrap();
        assert_eq!(alice.receive("bob", &reply).unwrap().0, format!("b{round}"));
        let next = alice.send("bob", &format!("c{round}"), None).unwrap();
        assert_eq!(bob.receive("alice", &next).unwrap().0, format!("c{round}"));
    }
}

#[test]
fn the_skipped_message_bound_is_enforced() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let mut p = packet(&alice.send("bob", "far", None).unwrap());
    p["h"]["n"] = json!(protocol::MAX_SKIP + 5);
    assert_eq!(code(bob.receive("alice", &envelope(&p))).as_deref(), Some("skip-limit"));
}

#[test]
fn tampered_ciphertext_header_or_handshake_fields_are_rejected() {
    let (_alice, mut bob, first) = pair(true);
    let p = packet(&first);
    let mut cases = vec![p.clone(), p.clone(), p.clone(), p.clone()];
    cases[0]["c"] = json!(flip(p["c"].as_str().unwrap()));
    cases[1]["h"]["n"] = json!(1);
    cases[2]["h"]["pn"] = json!(3);
    cases[3]["x"]["ik"]["sign"] = json!(flip(p["x"]["ik"]["sign"].as_str().unwrap()));
    for case in &cases { assert_eq!(code(bob.receive("alice", &envelope(case))).as_deref(), Some("auth")); }
    for bad in ["!!".to_string(), URL_SAFE_NO_PAD.encode("not json"), envelope(&json!({ "v": 2 }))] {
        assert_eq!(code(bob.receive("alice", &bad)).as_deref(), Some("malformed"));
    }
    let mut mismatch = p.clone();
    mismatch["x"]["ek"] = p["x"]["ik"]["dh"].clone();
    assert_eq!(code(bob.receive("alice", &envelope(&mismatch))).as_deref(), Some("malformed"));
    assert_eq!(bob.receive("alice", &first).unwrap().0, "hello bob");
}

#[test]
fn replays_are_rejected_and_used_message_keys_are_deleted() {
    let (mut alice, mut bob, first) = pair(true);
    let second = alice.send("bob", "two", None).unwrap();
    bob.receive("alice", &second).unwrap(); // out of order: first's key is skipped
    bob.receive("alice", &first).unwrap();
    assert_eq!(code(bob.receive("alice", &first)).as_deref(), Some("replay"));
    assert_eq!(code(bob.receive("alice", &second)).as_deref(), Some("replay"));
}

#[test]
fn a_late_duplicate_from_an_earlier_chain_is_a_replay() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let reply = bob.send("alice", "r", None).unwrap();
    alice.receive("bob", &reply).unwrap();
    let next = alice.send("bob", "n", None).unwrap();
    bob.receive("alice", &next).unwrap();
    assert_eq!(code(bob.receive("alice", &first)).as_deref(), Some("replay"));
}

#[test]
fn a_bad_signed_prekey_signature_is_rejected() {
    let mut bob = party();
    let mut bundle = bob.bundle(true);
    bundle.signed_pre_key.signature = flip(&bundle.signed_pre_key.signature);
    let mut alice = party();
    let error = alice.core.encrypt_to("bob", "{}", Some(&bundle)).unwrap_err();
    assert_eq!(error.message, "Signed prekey signature is invalid");
}

#[test]
fn safety_numbers_match_on_both_sides_and_change_with_an_identity() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let a = alice.core.safety("alice", "bob", "bob").unwrap().unwrap().number;
    let b = bob.core.safety("bob", "alice", "alice").unwrap().unwrap().number;
    assert_eq!(a, b);
    assert_eq!(a.split(' ').count(), 12);
    let other = protocol::generate_identity().public;
    let alice_pub = alice.core.identity().unwrap().public;
    assert_ne!(protocol::safety_number(("alice", &alice_pub), ("bob", &other)).unwrap(), a);
}

// ---------- Persistent box ----------
#[test]
fn first_contact_replies_and_one_time_prekey_consumption() {
    let (mut alice, mut bob, first) = pair(true);
    let decrypted = bob.core.decrypt_from("alice", &first, None).unwrap();
    assert!(decrypted.first_contact && !decrypted.identity_changed);
    let opk = packet(&first)["x"]["opk"].as_u64().unwrap();
    assert!(bob.core.store_mut().get(&format!("opk:{opk}")).unwrap().is_some(), "kept until commit");
    bob.core.commit(&decrypted.pending_id, false).unwrap();
    assert!(bob.core.store_mut().get(&format!("opk:{opk}")).unwrap().is_none());
    let reply = bob.send("alice", "back", None).unwrap();
    assert_eq!(alice.receive("bob", &reply).unwrap().0, "back");
}

#[test]
fn a_failing_store_leaves_the_ratchet_unchanged_so_the_message_can_be_processed_again() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let second = alice.send("bob", "two", None).unwrap();
    let decrypted = bob.core.decrypt_from("alice", &second, None).unwrap();
    bob.fail.store(1, Ordering::SeqCst);
    assert_eq!(bob.core.commit(&decrypted.pending_id, false).unwrap_err().code.as_deref(), Some("storage"));
    assert_eq!(bob.receive("alice", &second).unwrap().0, "two");
    assert_eq!(code(bob.receive("alice", &second)).as_deref(), Some("replay"));
}

#[test]
fn a_concurrent_update_between_decrypt_and_commit_is_refused_as_transient() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let second = alice.send("bob", "two", None).unwrap();
    let pending = bob.core.decrypt_from("alice", &second, None).unwrap();
    bob.send("alice", "meanwhile", None).unwrap(); // advances bob's stored session
    assert_eq!(bob.core.commit(&pending.pending_id, false).unwrap_err().code, None);
    assert_eq!(bob.receive("alice", &second).unwrap().0, "two");
}

#[test]
fn simultaneous_first_messages_from_both_sides_still_decrypt() {
    let (mut alice, mut bob) = (party(), party());
    let (alice_bundle, bob_bundle) = (alice.bundle(true), bob.bundle(true));
    let EncryptOutcome::Envelope(from_alice) = alice.core.encrypt_to("bob", r#"{"text":"a"}"#, Some(&bob_bundle)).unwrap() else { unreachable!() };
    let EncryptOutcome::Envelope(from_bob) = bob.core.encrypt_to("alice", r#"{"text":"b"}"#, Some(&alice_bundle)).unwrap() else { unreachable!() };
    assert_eq!(bob.receive("alice", &from_alice).unwrap().0, "a");
    assert_eq!(alice.receive("bob", &from_bob).unwrap().0, "b");
    let reply = bob.send("alice", "c", None).unwrap();
    assert_eq!(alice.receive("bob", &reply).unwrap().0, "c");
}

#[test]
fn an_identity_change_is_reported_clears_verification_and_blocks_sending_until_accepted() {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    bob.core.set_verified("alice", true).unwrap();
    let mut reborn = party();
    let bundle = bob.bundle(true);
    let EncryptOutcome::Envelope(new) = reborn.core.encrypt_to("bob", r#"{"text":"new phone"}"#, Some(&bundle)).unwrap() else { unreachable!() };
    let (text, changed) = bob.receive("alice", &new).unwrap();
    assert!(text == "new phone" && changed);
    let peer = bob.core.peer("alice").unwrap().unwrap();
    assert!(peer.changed && peer.blocked && !peer.verified);
    assert_eq!(code(bob.send("alice", "x", None)).as_deref(), Some("identity-blocked"));
    bob.core.accept_change("alice").unwrap();
    let back = bob.send("alice", "ok", None).unwrap();
    assert_eq!(reborn.receive("bob", &back).unwrap().0, "ok");
    let _ = &mut alice;
}

#[test]
fn a_change_to_either_identity_half_counts_as_a_new_identity() {
    let mut bob = party();
    let original = protocol::generate_identity().public;
    bob.core.note_peer("alice", &original).unwrap();
    let half = IdentityPub { dh: original.dh.clone(), sign: protocol::generate_identity().public.sign };
    let record = bob.core.note_peer("alice", &half).unwrap();
    assert!(record.changed && record.blocked);
}

#[test]
fn an_initial_message_without_a_one_time_prekey_cannot_be_replayed_after_its_session_is_gone() {
    let (_alice, mut bob, first) = pair(false);
    bob.receive("alice", &first).unwrap();
    bob.core.forget("alice").unwrap();
    assert_eq!(code(bob.receive("alice", &first)).as_deref(), Some("replay"));
}

#[test]
fn one_initial_envelope_as_if_from_two_contacts_opens_at_most_one_session() {
    let (_alice, mut bob, first) = pair(false);
    bob.receive("alice", &first).unwrap();
    assert_eq!(code(bob.receive("mallory", &first)).as_deref(), Some("replay"));
    // Pending (uncommitted) claims are bound to their contact too.
    let (_a2, mut bob2, first2) = pair(false);
    let pending = bob2.core.decrypt_from("alice", &first2, None).unwrap();
    assert_eq!(code(bob2.core.decrypt_from("mallory", &first2, None)).as_deref(), Some("replay"));
    bob2.core.commit(&pending.pending_id, false).unwrap();
}

#[test]
fn a_message_whose_storage_failed_after_its_claim_is_processed_once_on_redelivery() {
    let (_alice, mut bob, first) = pair(true);
    let pending = bob.core.decrypt_from("alice", &first, None).unwrap();
    bob.core.abort(&pending.pending_id); // the app failed to store it
    assert_eq!(bob.receive("alice", &first).unwrap().0, "hello bob");
    assert_eq!(code(bob.receive("alice", &first)).as_deref(), Some("replay"));
}

#[test]
fn replays_stay_rejected_after_the_signed_prekey_retires() {
    let (_alice, mut bob, first) = pair(false);
    bob.receive("alice", &first).unwrap();
    bob.core.forget("alice").unwrap();
    bob.core.prekeys(NOW + WEEK + 1, None).unwrap();
    bob.core.prekeys(NOW + 2 * WEEK + 2, None).unwrap();
    assert_eq!(code(bob.receive("alice", &first)).as_deref(), Some("unknown-spk"));
}

#[test]
fn one_contact_flooding_new_sessions_hits_its_own_cap_and_others_get_through() {
    let mut bob = party();
    let bundle = bob.bundle(false);
    for i in 0..protocol::MAX_CLAIMS_PER_CONTACT {
        let mut flood = party();
        let EncryptOutcome::Envelope(env) = flood.core.encrypt_to("bob", &format!(r#"{{"text":"{i}"}}"#), Some(&bundle)).unwrap() else { unreachable!() };
        bob.receive("mallory", &env).unwrap();
        bob.core.accept_change("mallory").unwrap();
    }
    let mut extra = party();
    let EncryptOutcome::Envelope(env) = extra.core.encrypt_to("bob", r#"{"text":"x"}"#, Some(&bundle)).unwrap() else { unreachable!() };
    assert_eq!(code(bob.receive("mallory", &env)).as_deref(), Some("claim-limit"));
    let mut carol = party();
    let EncryptOutcome::Envelope(env) = carol.core.encrypt_to("bob", r#"{"text":"carol"}"#, Some(&bundle)).unwrap() else { unreachable!() };
    assert_eq!(bob.receive("carol", &env).unwrap().0, "carol");
    assert!(!bob.core.prekeys(NOW, None).unwrap().rotated, "volume never rotates the signed prekey");
}

#[test]
fn claims_and_counters_are_pruned_on_normal_weekly_rotation() {
    let (_alice, mut bob, first) = pair(false);
    bob.receive("alice", &first).unwrap();
    let spk = packet(&first)["x"]["spk"].as_u64().unwrap();
    bob.core.prekeys(NOW + WEEK + 1, None).unwrap();
    assert!(bob.core.store_mut().get(&format!("claims:{spk}:alice")).unwrap().is_some(), "previous prekey still accepted");
    bob.core.prekeys(NOW + 2 * WEEK + 2, None).unwrap();
    assert!(bob.core.store_mut().get(&format!("claims:{spk}:alice")).unwrap().is_none());
}

#[test]
fn a_pinned_identity_survives_forgotten_sessions() {
    let (_alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    bob.core.forget("alice").unwrap();
    let mut impostor = party();
    let bundle = bob.bundle(true);
    let EncryptOutcome::Envelope(env) = impostor.core.encrypt_to("bob", r#"{"text":"trust me"}"#, Some(&bundle)).unwrap() else { unreachable!() };
    let decrypted = bob.core.decrypt_from("alice", &env, None).unwrap();
    assert!(decrypted.identity_changed);
}

#[test]
fn a_published_identity_mismatch_is_coded() {
    let (_alice, mut bob, first) = pair(true);
    let other = protocol::generate_identity().public;
    assert_eq!(code(bob.core.decrypt_from("alice", &first, Some(&other))).as_deref(), Some("mismatch"));
}

#[test]
fn sqlite_store_round_trips_and_batches_atomically() {
    let path = std::env::temp_dir().join(format!("chatcore-test-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let mut core = Core::new(Box::new(chatcore::store::SqliteStore::open(path.to_str().unwrap()).unwrap()));
        let id = core.identity().unwrap().public;
        drop(core);
        let mut again = Core::new(Box::new(chatcore::store::SqliteStore::open(path.to_str().unwrap()).unwrap()));
        assert_eq!(again.identity().unwrap().public, id);
        again.one_time_prekeys(3).unwrap();
        again.store_mut().delete_prefix("opk:").unwrap();
        assert!(again.store_mut().get("opk:1").unwrap().is_none());
    }
    let _ = std::fs::remove_file(&path);
}

// ---------- Call verification ----------
#[test]
fn sas_codes_are_order_independent_and_fail_closed_on_ambiguous_fingerprints() {
    let print = |byte: &str| format!("sha-256 {}", vec![byte; 32].join(":"));
    let sdp = |p: &str| format!("v=0\r\na=fingerprint:{p}\r\nm=application 9\r\na=fingerprint:{p}\r\n");
    let (n1, n2) = (sas::new_nonce(), sas::new_nonce());
    let a = sas::sas_from_sdp(&sdp(&print("AA")), &sdp(&print("bb")), [&n1, &n2]).unwrap();
    let b = sas::sas_from_sdp(&sdp(&print("BB")), &sdp(&print("aa")), [&n2, &n1]).unwrap();
    assert_eq!(a, b);
    assert!(a.len() == 7 && a.as_bytes()[3] == b' ');
    assert!(sas::fingerprints(&format!("{}a=fingerprint:{}\r\n", sdp(&print("AA")), print("BB"))).is_err());
    assert!(sas::fingerprints(&format!("a=FINGERPRINT:{}\r\n", print("AA"))).is_err());
    assert!(sas::fingerprints("v=0\r\n").is_err());
    let commitment = sas::commitment(&n1).unwrap();
    assert!(sas::check_reveal(&commitment, &n1) && !sas::check_reveal(&commitment, &n2));
}

// ---------- Key database sealed at rest ----------
#[test]
fn a_sealed_key_database_reveals_no_secrets_and_needs_its_key() {
    use chatcore::store::{Open, SqliteStore};
    let dir = std::env::temp_dir().join(format!("chatcore-sealed-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keys.sqlite").to_string_lossy().to_string();
    let key = [7u8; 32];
    let private;
    {
        let mut core = Core::new(Box::new(SqliteStore::open_sealed(&path, key, Open::Create).unwrap()));
        core.prekeys(NOW, None).unwrap();
        core.one_time_prekeys(3).unwrap();
        private = serde_json::to_string(&core.store_mut().get("identity").unwrap().unwrap()).unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    let wal = std::fs::read(format!("{path}-wal")).unwrap_or_default();
    let needle = &private[private.len() / 2..private.len() / 2 + 24];
    for bytes in [&raw, &wal] { assert!(!bytes.windows(needle.len()).any(|window| window == needle.as_bytes()), "identity found in plain text"); }
    // The right key reopens it; no key or another key is a storage error, never silently new keys.
    let mut again = Core::new(Box::new(SqliteStore::open_sealed(&path, key, Open::Existing).unwrap()));
    assert_eq!(serde_json::to_string(&again.store_mut().get("identity").unwrap().unwrap()).unwrap(), private);
    assert_eq!(SqliteStore::open(&path).err().and_then(|error| error.code).as_deref(), Some("storage"));
    assert_eq!(SqliteStore::open_sealed(&path, [8u8; 32], Open::Existing).err().and_then(|error| error.code).as_deref(), Some("storage"));
    std::fs::remove_dir_all(&dir).ok();
}

/// Someone who can write the file (but has no store key) must not be able to plant or move state.
#[test]
fn a_sealed_key_database_fails_closed_on_tampering() {
    use chatcore::store::{Open, SqliteStore};
    let dir = std::env::temp_dir().join(format!("chatcore-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = [9u8; 32];
    let fresh = |name: &str| {
        let path = dir.join(name).to_string_lossy().to_string();
        let mut store = SqliteStore::open_sealed(&path, key, Open::Create).unwrap();
        store.put("peer:alice", json!({ "identity": "alice-pin" })).unwrap();
        store.put("peer:bob", json!({ "identity": "bob-pin" })).unwrap();
        drop(store);
        (path.clone(), rusqlite::Connection::open(&path).unwrap())
    };
    let row = |db: &rusqlite::Connection, key: &str| -> String { db.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0)).unwrap() };
    // The whole database is refused at open: one bad row never yields a partially trusted store.
    let refused = |path: &str| SqliteStore::open_sealed(path, key, Open::Existing).err().and_then(|error| error.code);

    // 1. A tampered ciphertext.
    let (path, db) = fresh("tampered.sqlite");
    let value = row(&db, "peer:alice");
    let flipped = format!("{}{}", &value[..value.len() - 1], if value.ends_with('A') { 'B' } else { 'A' });
    db.execute("UPDATE kv SET value = ?1 WHERE key = 'peer:alice'", [flipped]).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));

    // 2. A valid ciphertext moved to another row (bob's pin planted onto alice).
    let (path, db) = fresh("swapped.sqlite");
    db.execute("UPDATE kv SET value = ?1 WHERE key = 'peer:alice'", [row(&db, "peer:bob")]).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));

    // 3. A ciphertext from another store sealed with the same key (different store id).
    let (path, db) = fresh("cross.sqlite");
    let (_, other) = fresh("cross-other.sqlite");
    db.execute("UPDATE kv SET value = ?1 WHERE key = 'peer:alice'", [row(&other, "peer:alice")]).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));

    // 4. A plaintext row injected after migration.
    let (path, db) = fresh("injected.sqlite");
    db.execute("UPDATE kv SET value = '{\"identity\":\"attacker\"}' WHERE key = 'peer:alice'", []).unwrap();
    db.execute("INSERT INTO kv (key, value) VALUES ('peer:mallory', '{\"identity\":\"attacker\"}')", []).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));

    // 4b. A single planted row the app would never read still refuses the whole database.
    let (path, db) = fresh("unread.sqlite");
    db.execute("INSERT INTO kv (key, value) VALUES ('zzz:never-read', '{\"x\":1}')", []).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));

    // 5. The marker deleted (to force a fresh "migration" of planted plaintext).
    let (path, db) = fresh("unmarked.sqlite");
    db.execute("DELETE FROM kv WHERE key = '__sealed'", []).unwrap();
    db.execute("INSERT INTO kv (key, value) VALUES ('peer:mallory', '{\"identity\":\"attacker\"}')", []).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));
    // ... and "create" never adopts it either: a database with any rows is not new.
    assert_eq!(SqliteStore::open_sealed(&path, key, Open::Create).err().and_then(|error| error.code).as_deref(), Some("storage"));

    // 6. The marker deleted and every row replaced with planted plaintext: never sealed as if it were ours.
    let (path, db) = fresh("replanted.sqlite");
    db.execute("DELETE FROM kv", []).unwrap();
    db.execute("INSERT INTO kv (key, value) VALUES ('peer:alice', '{\"identity\":\"attacker\"}')", []).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));
    assert_eq!(SqliteStore::open_sealed(&path, key, Open::Create).err().and_then(|error| error.code).as_deref(), Some("storage"));

    // 7. The whole database deleted or emptied: an existing store is "missing or reset", never a fresh start.
    let (path, db) = fresh("emptied.sqlite");
    db.execute("DELETE FROM kv", []).unwrap();
    assert_eq!(refused(&path).as_deref(), Some("storage"));
    let gone = dir.join("deleted.sqlite").to_string_lossy().to_string();
    assert_eq!(refused(&gone).as_deref(), Some("storage"));

    // A plaintext store migrates once (explicitly), then never accepts plaintext again.
    let path = dir.join("legacy.sqlite").to_string_lossy().to_string();
    { let mut plain = SqliteStore::open(&path).unwrap(); plain.put("identity", json!({ "secret": "legacy" })).unwrap(); }
    { let mut sealed = SqliteStore::migrate_plaintext(&path, key).unwrap(); assert_eq!(sealed.get("identity").unwrap().unwrap()["secret"], "legacy"); }
    assert!(SqliteStore::open_sealed(&path, key, Open::Existing).is_ok(), "the migrated store opens as existing");
    let raw: String = rusqlite::Connection::open(&path).unwrap().query_row("SELECT value FROM kv WHERE key = 'identity'", [], |r| r.get(0)).unwrap();
    assert!(raw.starts_with("enc1:") && !raw.contains("legacy"));
    // No pre-migration plaintext survives anywhere on disk: not in the file (freed pages), not in the WAL.
    for suffix in ["", "-wal", "-journal"] {
        let bytes = std::fs::read(format!("{path}{suffix}")).unwrap_or_default();
        assert!(!bytes.windows(6).any(|window| window == b"legacy"), "plaintext left in {path}{suffix}");
    }
    assert!(SqliteStore::open(&path).is_err(), "a migrated store never reopens in plaintext mode");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Chat key rotation (signal.js rotate / rotatedTo) ----------
fn sids(party: &mut Party, contact: &str) -> Vec<String> {
    party.core.store_mut().get(&format!("sessions:{contact}")).unwrap()
        .and_then(|value| value.get("order").cloned()).map(|order| serde_json::from_value(order).unwrap()).unwrap_or_default()
}
fn established() -> (Party, Party) {
    let (mut alice, mut bob, first) = pair(true);
    bob.receive("alice", &first).unwrap();
    let reply = bob.send("alice", "hi alice", None).unwrap();
    alice.receive("bob", &reply).unwrap();
    (alice, bob)
}

#[test]
fn rotation_opens_a_fresh_session_keeps_in_flight_messages_then_drops_old_chains() {
    let (mut alice, mut bob) = established();
    let old = alice.core.session_info("bob").unwrap().unwrap().0;
    let in_flight = bob.send("alice", "late", None).unwrap();
    alice.core.rotate("bob").unwrap();
    let rotation = alice.send("bob", "rotate", Some(&mut bob)).unwrap();
    assert!(packet(&rotation).get("x").is_some(), "a rotation must start a new X3DH handshake");
    let fresh = alice.core.session_info("bob").unwrap().unwrap().0;
    assert_ne!(fresh, old);
    assert_eq!(alice.receive("bob", &in_flight).unwrap().0, "late"); // In flight on the old session.
    assert_eq!(alice.core.session_info("bob").unwrap().unwrap().0, fresh, "a late message must not undo the rotation");
    let decrypted = bob.core.decrypt_from("alice", &rotation, None).unwrap();
    bob.core.commit(&decrypted.pending_id, true).unwrap();
    assert_eq!(sids(&mut bob, "alice"), vec![fresh.clone()]);
    let answer = bob.send("alice", "on the new one", None).unwrap();
    alice.receive("bob", &answer).unwrap();
    assert_eq!(sids(&mut alice, "bob"), vec![fresh]);
    assert_eq!(code(alice.receive("bob", &in_flight)).as_deref(), Some("unknown-session"));
}

#[test]
fn a_pending_rotation_is_not_revived_by_a_late_message() {
    let (mut alice, mut bob) = established();
    let old = alice.core.session_info("bob").unwrap().unwrap().0;
    let late = bob.send("alice", "late", None).unwrap();
    alice.core.rotate("bob").unwrap();
    alice.receive("bob", &late).unwrap(); // Arrives before alice sends again.
    assert_eq!(alice.core.encrypt_to("bob", &json!({ "text": "next" }).to_string(), None).unwrap(), EncryptOutcome::NeedsBundle);
    let next = alice.send("bob", "next", Some(&mut bob)).unwrap();
    assert!(packet(&next).get("x").is_some());
    assert_ne!(alice.core.session_info("bob").unwrap().unwrap().0, old);
}

#[test]
fn a_reset_arriving_on_an_old_session_is_ignored() {
    let (mut alice, mut bob) = established();
    let stale = alice.send("bob", "rotate", None).unwrap(); // On the old session.
    alice.core.rotate("bob").unwrap();
    let opening = alice.send("bob", "new", Some(&mut bob)).unwrap();
    bob.receive("alice", &opening).unwrap();
    let fresh = bob.core.session_info("alice").unwrap().unwrap().0;
    assert_eq!(sids(&mut bob, "alice").len(), 2);
    let decrypted = bob.core.decrypt_from("alice", &stale, None).unwrap();
    bob.core.commit(&decrypted.pending_id, true).unwrap();
    assert_eq!(sids(&mut bob, "alice").len(), 2, "nothing pruned");
    assert!(sids(&mut bob, "alice").contains(&fresh));
}

#[test]
fn session_start_times_are_recorded_and_rotation_keeps_the_pinned_identity() {
    let (mut alice, _bob) = established();
    let started = alice.core.session_info("bob").unwrap().unwrap().1;
    assert!(started >= protocol::now_ms() - 60_000);
    let pinned = alice.core.peer("bob").unwrap().unwrap().identity;
    alice.core.rotate("bob").unwrap();
    assert_eq!(alice.core.peer("bob").unwrap().unwrap().identity, pinned);
}

#[test]
fn the_shorter_non_off_rotation_interval_wins() {
    use chatcore::core::rotation_interval;
    let day = 86_400_000;
    assert_eq!(rotation_interval(day, 7 * day), day);
    assert_eq!(rotation_interval(0, 30 * day), 30 * day);
    assert_eq!(rotation_interval(0, 0), 0);
    assert_eq!(rotation_interval(12_345, 99), 0);
}

#[test]
fn resetting_the_identity_drops_sessions_prekeys_and_pending_decrypts_but_keeps_pins() {
    let (mut alice, mut bob) = established();
    let old = alice.core.identity().unwrap().public;
    let message = bob.send("alice", "pending", None).unwrap();
    let pending = alice.core.decrypt_from("bob", &message, None).unwrap();
    alice.core.reset_identity().unwrap();
    assert!(alice.core.commit(&pending.pending_id, false).is_err(), "a decrypt from before the reset cannot be committed");
    assert!(sids(&mut alice, "bob").is_empty());
    assert_ne!(alice.core.identity().unwrap().public, old);
    assert!(alice.core.peer("bob").unwrap().is_some());
}

/// A missing identity row in an existing key database is never replaced silently; only reset_identity may.
#[test]
fn an_existing_key_database_never_mints_a_new_identity_on_its_own() {
    use chatcore::store::{Open, SqliteStore};
    let dir = std::env::temp_dir().join(format!("chatcore-identity-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keys.sqlite").to_string_lossy().to_string();
    let key = [5u8; 32];
    let first = Core::new(Box::new(SqliteStore::open_sealed(&path, key, Open::Create).unwrap())).identity().unwrap().public;
    {
        // Someone deletes the identity row (the rest of the database still authenticates).
        let mut store = SqliteStore::open_sealed(&path, key, Open::Existing).unwrap();
        store.delete("identity").unwrap();
    }
    let mut core = Core::new(Box::new(SqliteStore::open_sealed(&path, key, Open::Existing).unwrap()));
    assert_eq!(core.identity().unwrap_err().code.as_deref(), Some("storage"));
    assert_eq!(core.prekeys(NOW, None).unwrap_err().code.as_deref(), Some("storage"));
    // The explicit user action is the way out.
    core.reset_identity().unwrap();
    assert_ne!(core.identity().unwrap().public, first);
    std::fs::remove_dir_all(&dir).ok();
}
