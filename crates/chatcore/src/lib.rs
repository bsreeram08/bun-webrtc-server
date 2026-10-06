//! chatcore: the end-to-end messaging core shared by the native apps (via flutter_rust_bridge) and,
//! later, the web app (via WASM). Wire-compatible with packages/signaling/public/signal.js and verify.js.
#![forbid(unsafe_code)]

pub mod api;
pub mod core;
pub mod error;
pub mod primitives;
pub mod protocol;
pub mod sas;
pub mod store;

pub use crate::core::{Core, Decrypted, EncryptOutcome, PeerRecord, PrekeyUpload, Safety};
pub use crate::error::{ChatError, Result};
pub use crate::protocol::{Bundle, IdentityPub};
