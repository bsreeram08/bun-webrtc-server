//! chatcore for the browser. One [`ChatCore`] per account runs inside the web app's worker
//! (packages/signaling/public/core-worker.js). It speaks the same JSON command protocol as the interop CLI
//! (`chatcore::commands`), so the browser, the node interop party and the native CLI exercise one dispatcher.
//!
//! Storage contract: the worker decrypts the account's IndexedDB rows and passes them in at construction;
//! every [`ChatCore::call`] returns the writes that call made, which the worker seals and persists in ONE
//! IndexedDB transaction before answering the page. Nothing here touches IndexedDB or CryptoKeys.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use chatcore::commands::respond;
use chatcore::core::Core;
use chatcore::store::{Journal, JournaledStore, Write};
use serde_json::{json, Map, Value};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ChatCore {
    core: Core,
    journal: Journal,
}

#[wasm_bindgen]
impl ChatCore {
    /// `rows_json`: `{ key: value }`, the decrypted persisted key database. `existed`: the database was
    /// created before (so a missing identity is a deletion and fails closed instead of minting a new one).
    #[wasm_bindgen(constructor)]
    pub fn new(rows_json: &str, existed: bool) -> Result<ChatCore, JsError> {
        let rows: BTreeMap<String, Value> = serde_json::from_str(rows_json).map_err(|_| JsError::new("Key storage failed: unreadable rows (storage)"))?;
        let (store, journal) = JournaledStore::new(rows, !existed);
        Ok(ChatCore { core: Core::new(Box::new(store)), journal })
    }

    /// Runs one command (see `chatcore::commands`). Returns JSON:
    /// `{"ok": value, "writes": [...]}` or `{"error": message, "code": code|null, "writes": [...]}`, where each
    /// write is `{"put": key, "value": json}` or `{"delete": key}`. Writes are returned on errors too: a
    /// native core would already have committed them, and the caller must persist them all the same.
    pub fn call(&mut self, command_json: &str) -> String {
        let mut outcome = match serde_json::from_str::<Value>(command_json) {
            Ok(command) => respond(&mut self.core, &command),
            Err(error) => json!({ "error": format!("bad command: {error}"), "code": null }),
        };
        let writes: Vec<Value> = self.journal.drain().into_iter().map(|write| match write {
            Write::Put(key, value) => json!({ "put": key, "value": value }),
            Write::Delete(key) => json!({ "delete": key }),
        }).collect();
        if let Value::Object(map) = &mut outcome { map.insert("writes".into(), Value::Array(writes)); }
        outcome.to_string()
    }
}

/// Build identity of this module, for the manifest and diagnostics.
#[wasm_bindgen]
pub fn version() -> String {
    let mut info = Map::new();
    info.insert("crate".into(), json!(env!("CARGO_PKG_VERSION")));
    info.insert("protocol".into(), json!("chatcore-commands-1"));
    Value::Object(info).to_string()
}
