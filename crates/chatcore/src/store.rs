//! Key/value storage under the box, mirroring signal.js's backend contract (get, put, delete,
//! deletePrefix, atomic batch). Values are JSON. A WASM build can implement this trait over IndexedDB.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{ChatError, Result};

#[derive(Clone, Debug)]
pub enum Write {
    Put(String, Value),
    Delete(String),
}

pub trait Store: Send {
    fn get(&mut self, key: &str) -> Result<Option<Value>>;
    fn put(&mut self, key: &str, value: Value) -> Result<()> { self.batch(vec![Write::Put(key.to_string(), value)]) }
    fn delete(&mut self, key: &str) -> Result<()> { self.batch(vec![Write::Delete(key.to_string())]) }
    fn delete_prefix(&mut self, prefix: &str) -> Result<()>;
    /// All writes apply atomically or not at all.
    fn batch(&mut self, writes: Vec<Write>) -> Result<()>;
    /// Whether a missing identity may be created on first use. False for a key database that existed
    /// before: there, a missing identity means it was deleted, and only an explicit reset may replace it.
    fn allows_new_identity(&self) -> bool { true }
}

#[cfg(feature = "native")]
pub use crate::sqlite::{Open, SqliteStore};


/// In-memory store for tests, with optional injected failures.
#[derive(Default)]
pub struct MemoryStore {
    pub map: BTreeMap<String, Value>,
    /// When set, the next N mutating calls fail (to exercise transient storage errors).
    pub fail_writes: usize,
}

impl Store for MemoryStore {
    fn get(&mut self, key: &str) -> Result<Option<Value>> { Ok(self.map.get(key).cloned()) }
    fn delete_prefix(&mut self, prefix: &str) -> Result<()> {
        if self.fail_writes > 0 { self.fail_writes -= 1; return Err(ChatError::storage("injected failure")); }
        self.map.retain(|key, _| !key.starts_with(prefix));
        Ok(())
    }
    fn batch(&mut self, writes: Vec<Write>) -> Result<()> {
        if self.fail_writes > 0 { self.fail_writes -= 1; return Err(ChatError::storage("injected failure")); }
        for write in writes {
            match write {
                Write::Put(key, value) => { self.map.insert(key, value); }
                Write::Delete(key) => { self.map.remove(&key); }
            }
        }
        Ok(())
    }
}

/// The browser's store (crates/chatcore-wasm). The whole key database is loaded into memory when the
/// core opens; every mutation applies in memory and is appended to a journal. After each API call the JS
/// shim drains the journal ([`Journal::drain`]) and persists it in ONE IndexedDB transaction, which keeps
/// signal.js's "one call, one atomic write" contract over an async database the synchronous core can't
/// await. If that persist fails, the shim discards this core and reloads from IndexedDB, so memory never
/// runs ahead of disk across calls. `deletePrefix` is journaled as the concrete keys it removed.
pub struct JournaledStore {
    map: BTreeMap<String, Value>,
    journal: Journal,
    allows_new_identity: bool,
}

/// Shared handle to a [`JournaledStore`]'s pending writes (the core owns the store itself).
#[derive(Clone, Default)]
pub struct Journal(std::sync::Arc<std::sync::Mutex<Vec<Write>>>);

impl Journal {
    /// Takes every write recorded since the last drain, in order.
    pub fn drain(&self) -> Vec<Write> { self.0.lock().map(|mut writes| std::mem::take(&mut *writes)).unwrap_or_default() }
    fn record(&self, write: Write) -> Result<()> {
        self.0.lock().map(|mut writes| writes.push(write)).map_err(|_| ChatError::storage("journal lock poisoned"))
    }
}

impl JournaledStore {
    /// `rows`: the decrypted contents of the persisted key database. `allows_new_identity` is false when the
    /// database existed before (see [`Store::allows_new_identity`]).
    pub fn new(rows: BTreeMap<String, Value>, allows_new_identity: bool) -> (Self, Journal) {
        let journal = Journal::default();
        (Self { map: rows, journal: journal.clone(), allows_new_identity }, journal)
    }
}

impl Store for JournaledStore {
    fn get(&mut self, key: &str) -> Result<Option<Value>> { Ok(self.map.get(key).cloned()) }
    fn delete_prefix(&mut self, prefix: &str) -> Result<()> {
        let keys: Vec<String> = self.map.range(prefix.to_string()..).take_while(|(key, _)| key.starts_with(prefix)).map(|(key, _)| key.clone()).collect();
        for key in keys {
            self.map.remove(&key);
            self.journal.record(Write::Delete(key))?;
        }
        Ok(())
    }
    fn batch(&mut self, writes: Vec<Write>) -> Result<()> {
        for write in writes {
            match &write {
                Write::Put(key, value) => { self.map.insert(key.clone(), value.clone()); }
                Write::Delete(key) => { self.map.remove(key); }
            }
            self.journal.record(write)?;
        }
        Ok(())
    }
    fn allows_new_identity(&self) -> bool { self.allows_new_identity }
}
