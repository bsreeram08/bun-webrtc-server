//! Key/value storage under the box, mirroring signal.js's backend contract (get, put, delete,
//! deletePrefix, atomic batch). Values are JSON. A WASM build can implement this trait over IndexedDB.
use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use zeroize::Zeroizing;

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

/// SQLite store: one `kv` table, every batch in one transaction.
///
/// With a store key (32 random bytes the app keeps in the platform keystore — Keychain / Android Keystore via
/// flutter_secure_storage), the store is *sealed*: every value is AES-256-GCM encrypted with a fresh 96-bit
/// nonce and associated data `enc1|<store id>|<row key>`, so a value can't be read without the key, edited,
/// or moved to another row or another store. A sealed store fails closed: a plaintext row, a ciphertext from
/// another row, a missing or altered marker, or the wrong key is a `storage` error, never silently new keys.
///
/// Opening is explicit about what the caller expects ([`Open`]): an `Existing` database must carry an
/// authenticated marker (a missing, deleted or reset database is a `storage` error, never a fresh start);
/// `Create` only initializes a database with no rows at all. Nothing is ever migrated implicitly: an
/// attacker who deletes the marker and plants plaintext rows can't get them sealed as if they were ours.
/// [`SqliteStore::migrate_plaintext`] is the one explicit, one-time migration (rows sealed and the marker
/// written in one transaction, then plaintext purged).
/// The store key stays in memory (zeroized on drop) for the life of the store, because every write seals.
/// Not covered: rolling a row back to an older sealed value of the *same* row (anyone able to write the file
/// can also delete it); the app sandbox and the keystore are the boundary for that.
pub struct SqliteStore {
    connection: Connection,
    sealing: Option<Sealing>,
    fresh: bool,
}

struct Sealing {
    key: Zeroizing<[u8; 32]>,
    store_id: String,
}

const SEALED: &str = "enc1:";
const MARKER: &str = "__sealed";

fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm> { Aes256Gcm::new_from_slice(key).map_err(ChatError::storage) }
fn seal_with(key: &[u8; 32], aad: &str, text: &str) -> Result<String> {
    let nonce = crate::primitives::random_bytes::<12>();
    let sealed = cipher(key)?.encrypt(Nonce::from_slice(&nonce), Payload { msg: text.as_bytes(), aad: aad.as_bytes() }).map_err(|_| ChatError::storage("seal failed"))?;
    Ok(format!("{SEALED}{}", URL_SAFE_NO_PAD.encode([nonce.as_slice(), &sealed].concat())))
}
fn unseal_with(key: &[u8; 32], aad: &str, text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let body = text.strip_prefix(SEALED).ok_or_else(|| ChatError::storage("plaintext row in a sealed key database"))?;
    let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| ChatError::storage("corrupt sealed row"))?;
    if bytes.len() < 12 + 16 { return Err(ChatError::storage("corrupt sealed row")); }
    cipher(key)?.decrypt(Nonce::from_slice(&bytes[..12]), Payload { msg: &bytes[12..], aad: aad.as_bytes() })
        .map(Zeroizing::new).map_err(|_| ChatError::storage("key database could not be unlocked"))
}
const MARKER_AAD: &str = "enc1|marker|__sealed";

/// What the caller expects to find when opening a sealed key database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Open {
    /// A database created earlier with this key: its authenticated marker must be present.
    Existing,
    /// A brand-new database: it must contain no rows; the marker is written now.
    Create,
}

fn connect(path: &str) -> Result<Connection> {
    let connection = Connection::open(path).map_err(ChatError::storage)?;
    connection
        // secure_delete: freed pages are zeroed, so replaced or deleted secrets don't linger in the file.
        .execute_batch("PRAGMA secure_delete = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
        .map_err(ChatError::storage)?;
    Ok(connection)
}
fn marker_of(connection: &Connection) -> Result<Option<String>> {
    connection.query_row("SELECT value FROM kv WHERE key = ?1", params![MARKER], |row| row.get(0)).optional().map_err(ChatError::storage)
}
fn row_count(connection: &Connection) -> Result<i64> {
    connection.query_row("SELECT COUNT(*) FROM kv", [], |row| row.get(0)).map_err(ChatError::storage)
}
fn write_marker(connection: &mut Connection, key: &[u8; 32], plaintext_rows: Vec<(String, Zeroizing<String>)>) -> Result<String> {
    let store_id = URL_SAFE_NO_PAD.encode(crate::primitives::random_bytes::<16>());
    let tx = connection.transaction().map_err(ChatError::storage)?;
    for (row, text) in plaintext_rows {
        serde_json::from_str::<Value>(&text).map_err(ChatError::storage)?;
        tx.execute("UPDATE kv SET value = ?1 WHERE key = ?2", params![seal_with(key, &format!("enc1|{store_id}|{row}"), &text)?, row]).map_err(ChatError::storage)?;
    }
    let marker = serde_json::json!({ "v": 1, "store": store_id }).to_string();
    tx.execute("INSERT INTO kv (key, value) VALUES (?1, ?2)", params![MARKER, seal_with(key, MARKER_AAD, &marker)?]).map_err(ChatError::storage)?;
    tx.commit().map_err(ChatError::storage)?;
    Ok(store_id)
}

impl SqliteStore {
    /// An unsealed store (tests and tools only; the apps always open sealed). Refuses a sealed database.
    pub fn open(path: &str) -> Result<Self> {
        let connection = connect(path)?;
        let any_sealed: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE value LIKE 'enc1:%')", [], |row| row.get(0)).map_err(ChatError::storage)?;
        if marker_of(&connection)?.is_some() || any_sealed { return Err(ChatError::storage("key database is locked: store key missing")); }
        Ok(Self { connection, sealing: None, fresh: true })
    }

    /// Opens a sealed key database. All or nothing: the marker and every row must authenticate under this
    /// key before the store is used, so one planted, moved or corrupted row refuses the whole database.
    pub fn open_sealed(path: &str, key: [u8; 32], mode: Open) -> Result<Self> {
        let mut connection = connect(path)?;
        let key = Zeroizing::new(key);
        let fresh = mode == Open::Create && marker_of(&connection)?.is_none();
        let store_id = match (marker_of(&connection)?, mode) {
            (Some(text), _) => {
                let plain = unseal_with(&key, MARKER_AAD, &text)?;
                let value: Value = serde_json::from_slice(&plain).map_err(ChatError::storage)?;
                let store_id = match (value.get("v").and_then(Value::as_u64), value.get("store").and_then(Value::as_str)) {
                    (Some(1), Some(id)) if id.len() == 22 => id.to_string(),
                    _ => return Err(ChatError::storage("invalid key database marker")),
                };
                let rows: Vec<(String, String)> = {
                    let mut statement = connection.prepare("SELECT key, value FROM kv WHERE key <> ?1").map_err(ChatError::storage)?;
                    let rows = statement.query_map(params![MARKER], |row| Ok((row.get(0)?, row.get(1)?))).map_err(ChatError::storage)?;
                    rows.collect::<std::result::Result<_, _>>().map_err(ChatError::storage)?
                };
                for (row, text) in rows {
                    let plain = unseal_with(&key, &format!("enc1|{store_id}|{row}"), &text)?;
                    serde_json::from_slice::<serde::de::IgnoredAny>(&plain).map_err(|_| ChatError::storage("corrupt sealed row"))?;
                }
                store_id
            }
            // Expected an existing database: a missing marker means it was deleted, reset or replaced.
            (None, Open::Existing) => return Err(ChatError::storage("key database missing or reset")),
            (None, Open::Create) => {
                if row_count(&connection)? != 0 { return Err(ChatError::storage("unexpected data in a new key database")); }
                write_marker(&mut connection, &key, Vec::new())?
            }
        };
        Ok(Self { connection, sealing: Some(Sealing { key, store_id }), fresh })
    }

    /// The one explicit migration of an unsealed database (never reached by opening): seals every row and writes
    /// the marker in one transaction, then purges plaintext (WAL checkpoint, VACUUM under secure_delete).
    pub fn migrate_plaintext(path: &str, key: [u8; 32]) -> Result<Self> {
        let mut connection = connect(path)?;
        let any_sealed: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM kv WHERE value LIKE 'enc1:%')", [], |row| row.get(0)).map_err(ChatError::storage)?;
        if marker_of(&connection)?.is_some() || any_sealed { return Err(ChatError::storage("key database is already sealed")); }
        let rows: Vec<(String, Zeroizing<String>)> = {
            let mut statement = connection.prepare("SELECT key, value FROM kv").map_err(ChatError::storage)?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, Zeroizing::new(row.get::<_, String>(1)?)))).map_err(ChatError::storage)?;
            rows.collect::<std::result::Result<_, _>>().map_err(ChatError::storage)?
        };
        write_marker(&mut connection, &key, rows)?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);").map_err(ChatError::storage)?;
        drop(connection);
        Self::open_sealed(path, key, Open::Existing)
    }
    pub fn memory() -> Result<Self> { Self::open(":memory:") }

    fn seal(&self, key: &str, value: &Value) -> Result<String> {
        if key == MARKER { return Err(ChatError::storage("reserved key")); }
        let text = Zeroizing::new(value.to_string());
        match &self.sealing {
            None => Ok(text.to_string()),
            Some(sealing) => seal_with(&sealing.key, &format!("enc1|{}|{key}", sealing.store_id), &text),
        }
    }
    fn unseal(&self, key: &str, text: &str) -> Result<Value> {
        match &self.sealing {
            None => serde_json::from_str(text).map_err(ChatError::storage),
            Some(sealing) => serde_json::from_slice(&unseal_with(&sealing.key, &format!("enc1|{}|{key}", sealing.store_id), text)?).map_err(ChatError::storage),
        }
    }
}

impl Store for SqliteStore {
    fn allows_new_identity(&self) -> bool { self.fresh }
    fn get(&mut self, key: &str) -> Result<Option<Value>> {
        if key == MARKER { return Err(ChatError::storage("reserved key")); }
        let text: Option<String> = self
            .connection
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |row| row.get(0))
            .optional()
            .map_err(ChatError::storage)?;
        text.map(|text| self.unseal(key, &text)).transpose()
    }
    fn delete_prefix(&mut self, prefix: &str) -> Result<()> {
        // Same range as IDBKeyRange.bound(prefix, prefix + '￿').
        let upper = format!("{prefix}\u{ffff}");
        self.connection.execute("DELETE FROM kv WHERE key >= ?1 AND key <= ?2 AND key <> ?3", params![prefix, upper, MARKER]).map_err(ChatError::storage)?;
        Ok(())
    }
    fn batch(&mut self, writes: Vec<Write>) -> Result<()> {
        let sealed: Vec<(String, Option<String>)> = writes.into_iter().map(|write| match write {
            Write::Put(key, value) => self.seal(&key, &value).map(|text| (key, Some(text))),
            Write::Delete(key) => Ok((key, None)),
        }).collect::<Result<_>>()?;
        let tx = self.connection.transaction().map_err(ChatError::storage)?;
        for (key, value) in sealed {
            match value {
                Some(text) => tx.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)", params![key, text]),
                None => tx.execute("DELETE FROM kv WHERE key = ?1", params![key]),
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
