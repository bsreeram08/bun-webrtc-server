# chatcore API

`chatcore` is the end-to-end messaging core for the native apps (Flutter, through
flutter_rust_bridge) and, later, the web app (through WASM). It is a port of
`packages/signaling/public/signal.js` (X3DH + Double Ratchet, safety numbers) and `verify.js`
(call verification code). It's wire-compatible with them; `bun run test:interop` checks that both ways.

The functions below live in `src/api.rs`. They take and return owned values (no lifetimes), and
every error is a `ChatError { code, message }`:

- **`code` is set** for a permanent outcome. The app may acknowledge or discard the envelope:
  - `malformed`, `auth`, `replay`, `skip-limit`, `unknown-session`, `unknown-spk`, `claim-limit`;
  - `invalid` (the plaintext isn't JSON), `mismatch` (the published identity differs), `identity-blocked`;
  - `storage`. This one is transient: retry.
- **`code` is `None`** for a transient failure. Retry, up to the app's attempt cap, exactly as
  `ChatStore.inboundDisposition` does on the web.

## Setup

| Function | Returns | Notes |
|---|---|---|
| `init(db_path, store_key, expect_existing)` | `()` | Opens the account's sealed SQLite key database (AES-256-GCM, each value bound to its row and store; all-or-nothing open). `expect_existing` = the keystore already held this key: a missing marker means the database was deleted or reset, and fails with `storage`. Otherwise only an empty database is initialized. No implicit migration, no fresh start; a failed open closes any previously open store. In an existing database a missing identity is a `storage` error; only `reset_identity` replaces it. |
| `identity()` | `IdentityPub { dh, sign }` | Created on first call: separate X25519 and Ed25519 keys. |
| `prepare_prekeys(now_ms)` | `PrekeyUpload { identity, rotated, signedPreKey }` | The signed prekey rotates weekly. When it rotates, claims under the retired one are pruned. |
| `one_time_prekeys(count)` | `Vec<{ id, key }>` | Upload them when the server reports fewer than 20, as `account.js` `publishKeys` does. |

## Messaging

| Function | Returns | Notes |
|---|---|---|
| `encrypt_to(contact_id, plaintext_json, bundle_json?)` | `Envelope(String)` or `NeedsBundle` | `NeedsBundle` means there's no sending session: fetch `/api/keys/<username>` and call again with that JSON. Fails with `identity-blocked` while the contact's security code change hasn't been accepted. |
| `decrypt_from(contact_id, envelope, published_identity?)` | `Decrypted { pending_id, plaintext_json, identity_changed, first_contact, identity }` | Phase 1: authenticates, claims a new session once (global lock, at most 20 per contact per signed prekey) and returns the plaintext. The stored ratchet doesn't advance yet. |
| `commit(pending_id, rotate)` | `bool` (a changed identity was recorded) | Phase 2, called after the app stored the message (signal.js runs `handle()` first, then persists). One atomic batch writes the session, the pinned identity, the completed claim and the one-time prekey deletion. If the contact's sessions changed in between, it returns a transient error; decrypt the envelope again. |
| `abort(pending_id)` | `()` | Drops a pending decrypt, e.g. when storing the message failed. Redelivering the envelope processes it again. |

Use `identity_changed` to show the message with the security-code warning. Using
`published_identity` gives defence in depth only: it's circular when the server is the attacker.

Each app session should handle incoming envelopes in order: decrypt → store → commit → acknowledge.

`rotate` is true when the stored payload was the peer's `{type:'rotate'}` session reset (signal.js `handle()`
answering `{ rotate: true }`): the core keeps only the session it arrived on, and only if that session is new
(the peer's fresh handshake) or the one our own rotation opened. A reset arriving on an older session is ignored.

## Chat key rotation

| Function | Returns |
|---|---|
| `rotate(contact_id)` | `()`. The next `encrypt_to` opens a fresh session (returns `NeedsBundle`). Older sessions stay (bounded) so in-flight messages decrypt; a late message never revives them; they are dropped once the peer answers on the new one. The pinned identity is untouched. |
| `session_info(contact_id)` | `Option<SessionInfo { sid, started_at }>` for scheduled rotation. |
| `rotation_interval(mine, theirs)` | The shorter non-off interval (ms) of the two; unknown values are ignored. |
| `reset_identity()` | `()`. A new identity for this device (explicit user action only): sessions, prekeys and claims go, pinned contacts stay, pending decrypts are dropped. Upload with takeover semantics afterwards. |

## Trust

| Function | Returns |
|---|---|
| `safety(my_username, contact_id, their_username)` | `Option<Safety { number, verified, changed, blocked }>`. `number` is 60 digits in 12 groups of 5, the same on both sides. |
| `peer(contact_id)` | `Option<PeerRecord>` |
| `set_verified(contact_id, bool)`, `accept_change(contact_id)` | `()`. Either one unblocks sending after a key change. |
| `forget(contact_id)` | `()`. Drops sessions but keeps the pinned identity. |
| `note_peer(contact_id, identity)` | `()`. Records a server-published identity (key-change events); a change is flagged and blocks sending. |

## Call verification code

| Function | Returns |
|---|---|
| `sas_new_nonce()` | 64 lowercase hex characters |
| `sas_commitment(nonce)` | Hex SHA-256 of the nonce text. Send `{type:'commit', hash}` first. |
| `sas_check_reveal(peer_commitment, peer_nonce)` | `bool`. Reveal your own nonce only after receiving the peer's commitment. |
| `sas_code(local_sdp, remote_sdp, my_nonce, peer_nonce)` | `"123 456"`. Each SDP must contain exactly one `a=fingerprint:sha-256` value; anything else that looks like a fingerprint line fails closed. |

## Store

`store::Store` (`get`, `put`, `delete`, `delete_prefix`, atomic `batch`, with JSON values)
matches signal.js's backend contract:
- `SqliteStore` is the native implementation.
- `MemoryStore` is for tests.
- A WASM build can implement the trait over IndexedDB.

`core::Core` is the same logic as an instance (`Core::new(Box<dyn Store>)`), for tests and multi-account use.
