# OpenMLS spike — findings (2026-10-07)

**Verdict: go for M2/M3**, with the plan changes below. Tests: `cargo test` (16/16). Benchmarks: `cargo run --release --bin bench`; tamper probe: `examples/tamper_probe.rs`.

## Plan changes (docs/workspace-architecture.md)
1. **§1.5 point 4, §2.4 — the delivery service runs the same validator as clients.** The plan called the server check "UX only". A commit the DS accepts but clients reject forks the group, so the DS and every client must share one validator (`validate_staged`), evaluated against the pre-commit roles with the same decoder.
2. **§2.5 — poison-commit recovery protocol.** A byte-flip probe over a 1,003-byte commit: the DS rejected 939 flips but accepted every flip in the last 64 bytes (confirmation and membership tags), which need epoch secrets the DS doesn't have; every member rejected them. Any member can therefore wedge a group. Protocol: a client that rejects a sequenced commit reports it → the DS freezes the group → an admin device re-checks and signs a rollback → the DS truncates the log, restores its stored pre-commit public state, and removes the committer.
3. **§1.5 — no standalone proposals.** Only inline proposals; nothing is committed by reference. Drop `pending_proposals`.
4. **§2.8, §4.4 — custom `StorageProvider` before >1,000 leaves.** OpenMLS's memory storage keys are `label ‖ json(key) ‖ version` (not grouped by group id, so prefix preload doesn't work); the whole ratchet tree is one value rewritten every commit (6.5 MB at 2,500 leaves); each received message rewrites a `MessageSecrets` row that grows with the group (85 KB/message at 2,500). CPU is not the limit. Replacement: key by group id first, store tree nodes per row, write to the journal directly.
5. **§2.1 — pin OpenMLS 0.9.0**, not 0.7.x: `openmls =0.9.0`, `openmls_rust_crypto/traits/basic_credential =0.6.0`, `StorageProvider<1>`. wasm32 needs the `openmls/js` feature and `getrandom 0.4` with `wasm_js`.

## What worked (all as tests)
- 3 users × 2 devices: KeyPackages, Welcome with the tree sent separately, messaging.
- A removed device cannot decrypt the next epoch; self-update rotates leaf key and epoch.
- Concurrent commits: the DS returns `Conflict{epoch,seq}`; the loser clears, catches up, rebuilds, is accepted.
- External join for a public channel and for the user's own new device in an invite-only group; a stranger is refused by the joiner, the DS and members.
- Resync with the same leaf key (OpenMLS removes the old leaf).
- `roles` extension (0xF0A1) enforced as a required capability.
- Last-resort KeyPackage reusable; normal ones consumed.
- DS `PublicGroup` holds no secrets, rejects tampered signatures and stale replays, tree matches clients'.
- Journaled store survives a restart (KV → bytes → `Device::load` → messaging continues).

## Numbers
Native: release, Apple Silicon. wasm: `wasm32-wasip1` in node V8. Safari not measured.

| Leaves | Build group (128-add batches) native / wasm | Tree | Join (Welcome + certs) | Member processes commit | DS validates commit | Msg encrypt / decrypt | Written per commit | Written per message |
|---|---|---|---|---|---|---|---|---|
| 10 | 1.7 ms / 11 ms | 6.5 KB | 0.7 / 5.4 ms | 0.5 / 1.1 ms | 0.4 / 1.3 ms | 26–32 / 59–70 µs | 32 KB | 2.6 KB |
| 100 | 8.7 ms / 19 ms | 70 KB | 5.5 / 12 ms | 2.9 / 6.9 ms | 3.0 / 6.4 ms | 27–33 / 53–69 µs | 265 KB | 5.3 KB |
| 1,000 | 234 ms / 0.72 s | 707 KB | 57 / 115 ms | 29 / 65 ms | 29 / 65 ms | 39–45 / 60–75 µs | 2.6 MB | 24 KB |
| 2,500 | 1.2 s / 4.5 s | 1.76 MB | 161 / 312 ms | 73 / 159 ms | 71 / 156 ms | 79–86 / 88–103 µs | 6.5 MB | 85 KB |

Welcome for one joiner: 421 B. Add-one commit: 2.5 KB at 10 leaves, 207 KB at 2,500.
**wasm size:** 2.06 MB built, 1.63 MB after `wasm-opt -Oz`, 598 KB gzip, 452 KB brotli — within §4.3's budget but excluding the 1:1 crypto, JS glue and store (~250 KB brotli headroom left).

## What OpenMLS does NOT enforce (our layer must)
| Gap | Our rule |
|---|---|
| Credentials are opaque bytes | DeviceCert bound to the account key, checked on every Add, Update, UpdatePath, external join, Welcome member, DS bootstrap and reload |
| Update/UpdatePath can change the credential | same user and device required |
| No admin model | roles policy against the pre-commit group state |
| Any group extension; roles can be dropped | only required-capabilities + roles; roles must stay required |
| Welcome/GroupInfo can describe any group | validate the whole group before adopting it |
| Proposal store allows commit-by-reference | standalone proposals refused |
| No size limits beyond TLS prefixes | byte limits before parsing, proposal count, group size |
| Nothing canonical | ids lowercase `[a-z0-9_]`, bytes must re-encode exactly, unknown JSON fields rejected |
| DS can't check confirmation/membership tags | poison-commit protocol (not fixable inside MLS) |
| Committer merges its own commit unchecked | `merge_own` validates first |

OpenMLS does enforce: signatures, epochs, tree and parent hashes, KeyPackage validity and lifetimes, capability support, duplicate keys, duplicate extension types.

## Entry points and gates (`MlsGroup`/`PublicGroup` are private)
| Entry point | Gate |
|---|---|
| `create_group` | `validate_context` |
| `join` (Welcome) | byte limits → `validate_group_state` |
| `join_external` | byte limits → `validate_group_state`, plus `validate_staged` on its own commit |
| `merge_own` | `validate_staged` on the pending commit |
| `receive` (commit) | byte limits → `validate_staged` |
| `receive` (proposal) | refused |
| `load` | `validate_group_state` + own-leaf check |
| `Ds::new` | `validate_group_state` |
| `Ds::submit` (commit) | byte limits → epoch → `validate_staged` |
| `Ds::submit` (proposal) | refused |
| `Ds::submit` (application) | byte limit + epoch only |

Commit builders only produce bytes; no state changes until `merge_own` validates them.

## API gotchas
- `add_members` / `remove_members` / `self_update` are compiled out under `virtual-clients-draft`; use `commit_builder()` (also lets a roles change be bundled with Adds).
- `credentials_to_verify()` doesn't return leaf signature keys; iterate `queued_proposals()` and `update_path_leaf_node()`.
- External commits are always plaintext → groups need the `MIXED_PLAINTEXT` wire-format policy.
- `SignatureKeyPair::private()` is test-only; the type is serde, so store it serialized.

## Recommended v1 limits
Leaves ≤1,000 (2,500 after the custom StorageProvider) · proposals per commit ≤128 · commit 1 MiB · application message 64 KiB · Welcome 4 MiB · ratchet tree 4 MiB · GroupInfo 64 KiB · certificate identity 1 KiB · roles extension 4 KiB, 1–64 admins · KeyPackages per device 100 one-time + 1 last-resort.

## Not covered
Safari/JavaScriptCore timings, wasm-bindgen glue size, a real IndexedDB store, concurrent writers (tab vs service worker, app vs iOS notification extension), post-quantum suites, the DS running under Bun. `cargo clippy`: 6 style warnings, none functional.
