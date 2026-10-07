//! Interop driver for tests/interop/run.mjs: one JSON command per stdin line, one JSON result per
//! stdout line (the protocol in chatcore::commands). Usage: interop [db_path]
use std::io::{self, BufRead, Write as _};

use chatcore::commands;
use chatcore::core::Core;
use chatcore::store::{MemoryStore, SqliteStore};
use serde_json::{json, Value};

fn main() {
    let path = std::env::args().nth(1);
    let store: Box<dyn chatcore::store::Store> = match path.as_deref() {
        None | Some(":mem:") => Box::new(MemoryStore::default()),
        // Sealed at rest, as the apps run it (a fresh store key per party).
        Some(path) => Box::new(SqliteStore::open_sealed(path, chatcore::primitives::random_bytes::<32>(), chatcore::store::Open::Create).expect("open database")),
    };
    let mut core = Core::new(store);
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() { continue; }
        let output = match serde_json::from_str::<Value>(&line) {
            Ok(command) => commands::respond(&mut core, &command),
            Err(error) => json!({ "error": format!("bad command: {error}"), "code": null }),
        };
        writeln!(stdout, "{output}").expect("stdout");
        stdout.flush().expect("stdout");
    }
}
