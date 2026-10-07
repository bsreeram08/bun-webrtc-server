//! The browser's journaled store: replaying the drained journal onto the persisted rows and reopening a core
//! from them must be indistinguishable from never having closed it (what the WASM worker does after a reload).
use std::collections::BTreeMap;

use chatcore::commands::respond;
use chatcore::core::Core;
use chatcore::store::{Journal, JournaledStore, Store, Write};
use serde_json::{json, Value};

const NOW: u64 = 1_800_000_000_000;

/// A party whose key database lives only in `disk` (what IndexedDB holds); the core is rebuilt from it at will.
struct Party { disk: BTreeMap<String, Value>, core: Core, journal: Journal, existed: bool }
impl Party {
    fn new() -> Self {
        let (store, journal) = JournaledStore::new(BTreeMap::new(), true);
        Party { disk: BTreeMap::new(), core: Core::new(Box::new(store)), journal, existed: false }
    }
    fn call(&mut self, command: Value) -> Value {
        let result = respond(&mut self.core, &command);
        for write in self.journal.drain() {
            match write {
                Write::Put(key, value) => { self.disk.insert(key, value); }
                Write::Delete(key) => { self.disk.remove(&key); }
            }
        }
        self.existed |= !self.disk.is_empty();
        result
    }
    fn ok(&mut self, command: Value) -> Value {
        let result = self.call(command.clone());
        result.get("ok").cloned().unwrap_or_else(|| panic!("{command} failed: {result}"))
    }
    /// A page reload: a new core over exactly what was persisted.
    fn reload(&mut self) {
        let (store, journal) = JournaledStore::new(self.disk.clone(), !self.existed);
        self.core = Core::new(Box::new(store));
        self.journal = journal;
    }
    fn bundle(&mut self) -> Value {
        let keys = self.ok(json!({ "cmd": "prekeys", "now": NOW }));
        let opk = self.ok(json!({ "cmd": "opks", "count": 1 }))[0].clone();
        json!({ "identity": keys["identity"], "signedPreKey": keys["signedPreKey"], "oneTimePreKey": opk })
    }
    fn send(&mut self, to: &str, text: &str, bundle: Option<Value>) -> String {
        let plaintext = json!({ "text": text }).to_string();
        let first = self.ok(json!({ "cmd": "encrypt", "contact": to, "plaintext": plaintext }));
        let out = if first.get("needsBundle").is_some() { self.ok(json!({ "cmd": "encrypt", "contact": to, "plaintext": plaintext, "bundle": bundle })) } else { first };
        out["envelope"].as_str().unwrap().to_string()
    }
    fn receive(&mut self, from: &str, envelope: &str) -> String {
        let decrypted = self.ok(json!({ "cmd": "decrypt", "contact": from, "envelope": envelope, "commit": false }));
        self.ok(json!({ "cmd": "commit", "pendingId": decrypted["pendingId"], "rotate": false }));
        serde_json::from_str::<Value>(decrypted["plaintext"].as_str().unwrap()).unwrap()["text"].as_str().unwrap().to_string()
    }
}

#[test]
fn a_conversation_survives_reloads_after_every_call() {
    let (mut alice, mut bob) = (Party::new(), Party::new());
    let identity = alice.ok(json!({ "cmd": "identity" }));
    let bob_bundle = bob.bundle();
    for round in 0..6 {
        let to_bob = alice.send("bob", &format!("a{round}"), Some(bob_bundle.clone()));
        alice.reload();
        bob.reload();
        assert_eq!(bob.receive("alice", &to_bob), format!("a{round}"));
        bob.reload();
        let to_alice = bob.send("alice", &format!("b{round}"), None);
        assert_eq!(alice.receive("bob", &to_alice), format!("b{round}"));
        alice.reload();
    }
    // The identity is the persisted one, not a fresh one minted after a reload.
    assert_eq!(alice.ok(json!({ "cmd": "identity" })), identity);
}

#[test]
fn a_replay_after_a_reload_is_still_a_replay() {
    let (mut alice, mut bob) = (Party::new(), Party::new());
    let bundle = bob.bundle();
    let envelope = alice.send("bob", "once", Some(bundle));
    assert_eq!(bob.receive("alice", &envelope), "once");
    bob.reload();
    let again = bob.call(json!({ "cmd": "decrypt", "contact": "alice", "envelope": envelope, "commit": true }));
    assert_eq!(again["code"], "replay");
}

#[test]
fn delete_prefix_is_journaled_as_concrete_deletes_and_a_lost_identity_is_not_reminted() {
    let mut alice = Party::new();
    alice.ok(json!({ "cmd": "identity" }));
    alice.ok(json!({ "cmd": "prekeys", "now": NOW }));
    alice.ok(json!({ "cmd": "opks", "count": 3 }));
    alice.ok(json!({ "cmd": "resetIdentity" }));
    assert!(!alice.disk.keys().any(|key| key.starts_with("opk:")), "reset must persist the removal of every one-time prekey");
    // A database that existed before but lost its identity row fails closed instead of minting a new identity.
    alice.ok(json!({ "cmd": "identity" }));
    alice.disk.remove("identity");
    alice.reload();
    assert_eq!(alice.call(json!({ "cmd": "identity" }))["code"], "storage");
}

#[test]
fn journal_store_reports_writes_in_order() {
    let (mut store, journal) = JournaledStore::new(BTreeMap::from([("a:1".into(), json!(1)), ("a:2".into(), json!(2)), ("b".into(), json!(3))]), true);
    store.put("c", json!(4)).unwrap();
    store.delete_prefix("a:").unwrap();
    let writes: Vec<String> = journal.drain().into_iter().map(|write| match write { Write::Put(key, _) => format!("put {key}"), Write::Delete(key) => format!("del {key}") }).collect();
    assert_eq!(writes, ["put c", "del a:1", "del a:2"]);
    assert!(journal.drain().is_empty());
    assert_eq!(store.get("b").unwrap(), Some(json!(3)));
}
