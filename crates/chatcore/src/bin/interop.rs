//! Interop driver for tests/interop/run.mjs: one JSON command per stdin line, one JSON result per
//! stdout line (`{"ok": ...}` or `{"error": "...", "code": "..." | null}`). Usage: interop [db_path]
use std::io::{self, BufRead, Write as _};

use chatcore::core::Core;
use chatcore::protocol::{Bundle, IdentityPub};
use chatcore::sas;
use chatcore::store::{MemoryStore, SqliteStore};
use chatcore::{ChatError, EncryptOutcome};
use serde_json::{json, Value};

fn text(command: &Value, key: &str) -> Result<String, ChatError> {
    command.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| ChatError::transient(format!("missing {key}")))
}

fn run(core: &mut Core, command: &Value) -> Result<Value, ChatError> {
    let cmd = text(command, "cmd")?;
    match cmd.as_str() {
        "identity" => Ok(json!(core.identity()?.public)),
        "prekeys" => {
            let now = command.get("now").and_then(Value::as_u64).unwrap_or(0);
            let max_age = command.get("maxAge").and_then(Value::as_u64);
            Ok(json!(core.prekeys(now, max_age)?))
        }
        "opks" => Ok(json!(core.one_time_prekeys(command.get("count").and_then(Value::as_u64).unwrap_or(1))?)),
        "encrypt" => {
            let bundle: Option<Bundle> = match command.get("bundle") {
                Some(Value::Null) | None => None,
                Some(value) => Some(serde_json::from_value(value.clone()).map_err(|_| ChatError::transient("Invalid key bundle"))?),
            };
            match core.encrypt_to(&text(command, "contact")?, &text(command, "plaintext")?, bundle.as_ref())? {
                EncryptOutcome::Envelope(envelope) => Ok(json!({ "envelope": envelope })),
                EncryptOutcome::NeedsBundle => Ok(json!({ "needsBundle": true })),
            }
        }
        "decrypt" => {
            let published: Option<IdentityPub> = match command.get("published") {
                Some(Value::Null) | None => None,
                Some(value) => serde_json::from_value(value.clone()).ok(),
            };
            let decrypted = core.decrypt_from(&text(command, "contact")?, &text(command, "envelope")?, published.as_ref())?;
            let commit = command.get("commit").and_then(Value::as_bool).unwrap_or(true);
            let recorded = if commit { Some(core.commit(&decrypted.pending_id)?) } else { None };
            Ok(json!({
                "plaintext": decrypted.plaintext_json, "identityChanged": decrypted.identity_changed, "firstContact": decrypted.first_contact,
                "identity": decrypted.identity, "pendingId": decrypted.pending_id, "identityRecorded": recorded,
            }))
        }
        "commit" => Ok(json!(core.commit(&text(command, "pendingId")?)?)),
        "safety" => Ok(match core.safety(&text(command, "me")?, &text(command, "contact")?, &text(command, "them")?)? {
            Some(safety) => json!({ "number": safety.number, "verified": safety.verified, "changed": safety.changed, "blocked": safety.blocked }),
            None => Value::Null,
        }),
        "peer" => Ok(json!(core.peer(&text(command, "contact")?)?)),
        "setVerified" => { core.set_verified(&text(command, "contact")?, command.get("verified").and_then(Value::as_bool).unwrap_or(true))?; Ok(Value::Null) }
        "acceptChange" => { core.accept_change(&text(command, "contact")?)?; Ok(Value::Null) }
        "forget" => { core.forget(&text(command, "contact")?)?; Ok(Value::Null) }
        "sas" => {
            let nonces: Vec<String> = command.get("nonces").and_then(Value::as_array).map(|list| list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            if nonces.len() != 2 { return Err(ChatError::transient("nonces")); }
            Ok(json!(sas::sas_from_sdp(&text(command, "localSdp")?, &text(command, "remoteSdp")?, [&nonces[0], &nonces[1]])?))
        }
        "sasCommitment" => Ok(json!(sas::commitment(&text(command, "nonce")?)?)),
        "sasCheck" => Ok(json!(sas::check_reveal(&text(command, "commitment")?, &text(command, "nonce")?))),
        other => Err(ChatError::transient(format!("unknown command {other}"))),
    }
}

fn main() {
    let path = std::env::args().nth(1);
    let store: Box<dyn chatcore::store::Store> = match path.as_deref() {
        None | Some(":mem:") => Box::new(MemoryStore::default()),
        Some(path) => Box::new(SqliteStore::open(path).expect("open database")),
    };
    let mut core = Core::new(store);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() { continue; }
        let output = match serde_json::from_str::<Value>(&line) {
            Ok(command) => match run(&mut core, &command) {
                Ok(value) => json!({ "ok": value }),
                Err(error) => json!({ "error": error.message, "code": error.code }),
            },
            Err(error) => json!({ "error": format!("bad command: {error}"), "code": null }),
        };
        writeln!(stdout, "{output}").expect("stdout");
        stdout.flush().expect("stdout");
    }
}
