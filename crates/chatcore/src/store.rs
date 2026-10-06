//! Key/value storage under the box, mirroring signal.js's backend contract (get, put, delete,
//! deletePrefix, atomic batch). Values are JSON. A WASM build can implement this trait over IndexedDB.
use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
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
}

/// SQLite store: one `kv` table, every batch in one transaction. Secrets are stored in this file;
/// protect it with the platform's app sandbox (and SQLCipher/OS keystore wrapping later).
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    pub fn open(path: &str) -> Result<Self> {
        let connection = Connection::open(path).map_err(ChatError::storage)?;
        connection
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
            .map_err(ChatError::storage)?;
        Ok(Self { connection })
    }
    pub fn memory() -> Result<Self> { Self::open(":memory:") }
}

impl Store for SqliteStore {
    fn get(&mut self, key: &str) -> Result<Option<Value>> {
        let text: Option<String> = self
            .connection
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |row| row.get(0))
            .optional()
            .map_err(ChatError::storage)?;
        text.map(|text| serde_json::from_str(&text).map_err(ChatError::storage)).transpose()
    }
    fn delete_prefix(&mut self, prefix: &str) -> Result<()> {
        // Same range as IDBKeyRange.bound(prefix, prefix + '￿').
        let upper = format!("{prefix}\u{ffff}");
        self.connection.execute("DELETE FROM kv WHERE key >= ?1 AND key <= ?2", params![prefix, upper]).map_err(ChatError::storage)?;
        Ok(())
    }
    fn batch(&mut self, writes: Vec<Write>) -> Result<()> {
        let tx = self.connection.transaction().map_err(ChatError::storage)?;
        for write in writes {
            match write {
                Write::Put(key, value) => tx.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)", params![key, value.to_string()]),
                Write::Delete(key) => tx.execute("DELETE FROM kv WHERE key = ?1", params![key]),
            }
            .map_err(ChatError::storage)?;
        }
        tx.commit().map_err(ChatError::storage)
    }
}

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
