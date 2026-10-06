//! Bridge crate: the flutter_rust_bridge surface the Flutter app calls. All protocol logic lives in
//! `crates/chatcore`; this crate only adapts its flat API (`chatcore::api`) to FRB-friendly types.
pub mod api;
mod frb_generated;
