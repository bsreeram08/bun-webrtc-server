# Slack-like encrypted workspace — architecture plan

Status: proposal (2026-10-06); decisions recorded 2026-10-07; M0 built on `feat/wasm-core`. Grounded in `feat/key-rotation` (production), `feat/rust-core`, `feat/native-server`, `feat/flutter-app`.

## Decisions already made
- End-to-end encryption everywhere. Bots, plugins and the MCP server are real members with their own keys and only see channels they are invited to.
- Groups and channels use MLS (RFC 9420) via OpenMLS inside `crates/chatcore`, compiled to WebAssembly for the web client: one implementation on every platform.
- Linked devices (each device is an MLS leaf).
- Slash commands (built-ins now on `feat/slash-commands`, bot commands later).
- Later: bot accounts, SDK, events API, MCP server, plugins. Native push already exists on `feat/native-server`.

## Decisions (2026-10-07)
The user accepted the recommended answers to the open questions (§9):
- **DMs keep contact requests** (no workspace-wide DMs without acceptance).
- **New members see history from when they join.** An encrypted history share (§5, M14) is optional per channel, later.
- **`/burn` in groups:** admins delete for everyone; anyone deletes their own messages.
- **Mention-only notifications are filtered on the device.** No cleartext mention hint goes to the server.
- **Group calls later** (huddles with an encrypted media relay).
- **One workspace per deployment.**
- **The account identity key (AIK) lives on a single primary device.**
- **Verification is kept across a signed primary succession** (soft notice, no re-verification).
- **Device labels and platforms are encrypted** inside the DeviceList, not visible to the server.
- **`/remind` is local only** (no server-timed delivery).
- **Post-quantum later**, as a per-group ciphersuite upgrade.
- **Legacy 1:1 Double Ratchet stays receive-only for 60 days** after both sides support MLS.

## 0. Code facts that shape the design
| # | Fact | Consequence |
|---|---|---|
| F1 | Web Ed25519 identity signing key is a non-extractable CryptoKey; X25519 private keys are AES-GCM-wrapped. | The web account key can never move into WASM or to another device: linking is "approve from the key holder", not "copy the key". |
| F2 | Safety number = fingerprint(username, dh‖sign). | Keeping the account identity `{dh, sign}` means existing safety numbers survive migration unchanged. |
| F3 | chatcore pulls `rusqlite` unconditionally; `Store` is synchronous. | wasm32 needs a feature split and a journaled store over async IndexedDB. |
| F4 | Mailbox is per user; one identity row per user; identity change = takeover. | Becomes a device registry with per-device delivery. |
| F5 | 128 KiB request cap; 64 KiB envelopes; events socket accepts only ack/ringing frames. | New limits for commits and files, chunked blobs, new client frames. |
| F6 | Static allowlist; CSP `script-src 'self'`; `no-store` everywhere; fixed SW asset list. | WASM needs `'wasm-unsafe-eval'`, `application/wasm`, hashed immutable assets. |
| F7 | chat-store: 2,000 messages, 4 KB each, fixed schema, conversation id = `pairId`. | Message store v2; DM history carries over by reusing `pairId`. |
| F8 | Push payloads carry the sender username; FCM/APNs can read them. | New payloads carry only `{g, seq}`; the device decrypts. |
| F9 | Keys and messages gated by mutual contacts. | Workspace membership replaces contact gating (open question 3). |
| F10 | Native branch already has bearer sessions and session-bound push tokens. | Bots reuse bearer auth; devices bind to sessions. |

## 1. Data model and server
- **One implicit workspace per deployment** (invite → account → member). `workspace_id` columns reserved for later.
- Move to numbered migrations (`PRAGMA user_version`).
- Tables: `workspace`, `workspace_members(role owner|admin|member|guest|bot)`, `users.kind person|bot`.
- **Device registry:** `devices(id, user_id, label, platform, sig_key, cert, caps, created_at, last_seen_at, revoked_at)`, `device_lists(user_id, version, list, signature)`, `sessions.device_id`. A DeviceList `{userId, version, prevHash, devices[]}` is signed by the account identity key (AIK); clients pin the highest version and reject rollbacks or devices whose certificate doesn't chain to the pinned AIK.
- **Channels:** `channels(id = MLS group id, kind public|private|dm|group_dm|self, name (public only), epoch, seq, public_state, group_info)`, `channel_members` (a mirror for fan-out; authoritative roles live inside MLS), `dm_pairs` (one DM per pair), `channel_prefs` (only for push suppression).
- **DMs become 2-person MLS groups** (all devices of both users are leaves). Double Ratchet stays as the legacy/transition path.
- **Delivery service** (`mls-ds.ts`): stores and hands out KeyPackages per device; sequences epochs (accepts a commit only for the current epoch, else 409); rejects stale-epoch app messages; validates handshake messages with OpenMLS `PublicGroup` compiled to WASM for Bun; fans out group traffic by per-device cursors and Welcomes into a per-device inbox (replaces `mailbox`).
- New socket frames: `group`, `welcome`, `devices`, `channel`, `ephemeral` (server→client); `cursor`, `ack`, `ringing` (client→server).
- **What the server learns:** usernames, roles, device counts, public channel names, membership of every channel/DM and who added whom, sender device/size/time of each message, blob sizes. **Never:** content, edits, reactions, threads, mentions, file contents/names, private channel names/topics, read state, searches, command arguments.
- **Retention:** group log deleted once every member device has read it, or after 30 days; device inbox 30 days; KeyPackages 90 days; blobs 30 days (workspace setting).
- Split `accounts.ts` into `events.ts`, `devices.ts`, `link.ts`, `mls-ds.ts`, `channels.ts`, `blobs.ts`, `bots.ts`, `workspace.ts`.

## 2. MLS design
- **OpenMLS 0.7.x pinned exactly**; ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (same curves as today, pure Rust, builds for wasm). Post-quantum later.
- **Credentials:** each device has its own Ed25519 leaf key; the credential carries a DeviceCert signed by the AIK (signed in WebCrypto on web, in chatcore on native). Clients accept a device only if the cert verifies under the pinned AIK, the device is in the pinned DeviceList, and the leaf key matches.
- **Safety numbers stay per account and don't change** when devices are added. New devices show a local "alice linked a new device" notice. Optional per-epoch group code for in-person checks; calls keep their 6-digit code.
- **KeyPackages:** 100 one-time + 1 last-resort per device, top up below 20, 90-day lifetime.
- **Authorization inside MLS:** a `roles` group extension (owners, admins, post/join policy, bot scopes). Every client checks every commit against it (adds, removals, external joins); the server mirrors the same rules for UX only.
- **Concurrent commits:** commit with a digest; 200 → merge; 409 → fetch log, rebuild, retry (backoff, max 5); timeout → on reconnect, merge if the log contains our digest, else rebuild. Never process our own commit from the log.
- **Forward secrecy and healing:** message keys deleted after use, epoch secrets after 2 epochs; a device that hasn't refreshed its path for 7 days (DMs: 24 h) sends an update first; `/reset` forces one; removals always refresh.
- **Migration from 1:1 sessions:** when both users have an MLS-capable device, the first sender creates the DM group and sends a final Double Ratchet message pointing to it; the receiver accepts only if that pointer came over the pinned session and the group's leaves chain to the same AIK. History continues under `pairId`. Double Ratchet stays receive-only for 60 days.
- **Limits:** DM 2 users/16 leaves; group DM 9; private channel 500; public channel 1,000 users/2,500 leaves.
- **External joins** only for: public channel self-join, a user's own new device, and resync. Never for private channels or DMs.
- **History for new members:** none by default ("New members see messages from when they joined"); optional per-channel encrypted history share (≤30 days/10 MB) labelled as shared by the inviter.
- **WASM ↔ native interop** tested in the existing interop matrix, plus storage-format upgrade tests.

## 3. Linked devices
- **AIK = today's identity** (safety numbers unchanged). The device holding it is the **primary**; others are companions with their own leaf keys and an AIK-signed certificate (WhatsApp model; forced on web by F1).
- **Link by QR from an existing device** (default): new device shows a QR with an ephemeral key; primary scans, both derive a shared key, user confirms on the primary; primary signs the certificate, publishes DeviceList v+1, the server issues the new device a session; primary sends an encrypted provisioning bundle (cert, pinned contacts and verification flags, channel list, optional history); new device joins its groups.
- **Passkey sign-in without a primary** = recovery: new AIK, contacts see "security code changed" and must review. Passkey sign-in alone never lets the server add a trusted device.
- **Primary transfer:** old AIK signs a succession record; contacts see a soft notice and keep verification.
- **Revocation:** server cuts sessions/push immediately; remaining devices remove its leaves from every group.
- **Migration of today's users:** the active device becomes primary automatically; inactive browsers switch to "Link this browser from your primary device".

## 4. Web WASM
- Crates: `chatcore` (features native|wasm|ds), `chatcore-wasm` (wasm-bindgen), `chatcore-ds` (PublicGroup validation for the server).
- Build: release profile tuned for size, wasm-bindgen, wasm-opt, content-hashed files served immutable from `/core/*`; SW cache updated.
- **Size budget:** ≤2 MB raw / ≤700 KB brotli (CI gate).
- **Store:** async IndexedDB under a synchronous core via preload → run against an in-memory journal → apply all writes in one transaction; two-phase receive kept. **No CryptoKey objects in this store** (Safari lesson): every value AES-GCM-encrypted under a non-extractable AES key; private keys exist as bytes only inside WASM memory.
- CSP: add `'wasm-unsafe-eval'` and `blob:` for images/media.
- Run the core in a worker; one writer per account across tabs and the service worker via Web Locks.

### M0 as built (`feat/wasm-core`)
- **Crates:** `chatcore` has features `native` (default: SQLite, the apps and the interop CLI) and `wasm` (no SQLite; JS clock and randomness). `crates/chatcore-wasm` is the wasm-bindgen cdylib. `chatcore-ds` is not built yet (M3).
- **One command protocol:** `chatcore::commands` (JSON command in, `{ok}`/`{error,code}` out) is shared by the interop CLI, the WASM build, the node interop party and the browser worker, so all of them run the same dispatcher.
- **Store:** `JournaledStore` — the whole key database is preloaded into memory (it is small: identity, prekeys, sessions, pins, claims); every write applies in memory and is journaled; `ChatCore.call` returns the writes; the worker seals each value (AES-256-GCM, non-extractable AES key in `webrtc-bun-core-key-v1`, AAD `core1|<userId>|<row>`) and applies them in ONE IndexedDB transaction before answering. A failed persist drops the in-memory core so the next call reloads from disk. A marker row makes open fail closed (rows without a marker, or any row that won't authenticate, refuse the store; never a fresh identity).
- **Build output is committed** (`packages/signaling/public/core/`, content-hashed + `manifest.json`): the server has no Rust toolchain and deploys by `git pull`. Builds are reproducible (path remapping, pinned rustc 1.93.1 and wasm-bindgen 0.2.129, no wasm-opt); CI's `core` job rebuilds with `bun run build:wasm --check` and fails if the committed bytes differ, then runs the interop matrix. Size: 363 KB raw / 148 KB brotli wasm + 16 KB glue.
- **Server:** `/core/manifest.json` (no-cache) and `/core/chatcore[_bg].<hash>.{js,wasm}` (immutable, exact MIME, nosniff); CSP `script-src 'self' 'wasm-unsafe-eval'`.
- **Single writer:** `core.js` takes the `chatcore:<userId>` Web Lock if free (`ifAvailable`), otherwise follows over `BroadcastChannel` and queues to take over; only the leader runs `core-worker.js`.
- **Opt-in:** `localStorage['core-backend'] = 'wasm'` (or `?core=wasm`) makes account.js use `Core.box` instead of `Signal.box`. Default stays signal.js.
- **Migrating existing users (later, not in M0):** the WASM core can't read signal.js's store (different layout; AIK signing key is a non-extractable CryptoKey). Plan: when M1 registers devices, a browser on signal.js keeps its AIK in WebCrypto (signing via JS, as §2.2 already requires) and exports everything else — sessions, pins, prekeys, claims, wrapped X25519 bytes — into the core's store in one step behind a marker, then switches backend. Until then, turning the flag on for an existing account behaves like a new device (the active-device banner offers "Use this device instead").
- **Tests:** interop matrix now covers every direction between signal.js, native and WASM (878 checks; the WASM party is rebuilt from its persisted journal after every call); `tests/browser/webkit-wasm.mjs` (WebKit + Chromium: stable identity across reloads, every IndexedDB value sealed, decrypt after reload, two tabs → one leader + handover); `CORE=wasm node tests/browser/accounts.mjs` runs the whole accounts suite on the WASM core.

## 5. Slack features
Payload types inside MLS: `message` (text, thread, mentions, attachments, markdown), `edit` (sender only), `delete` (sender or admin), `reaction`, `pin`, `topic`/`settings`, `receipt` (DMs only), `poll`/`vote`, `command`, `bot.manifest`, `history.share`, `burn`, `typing` (ephemeral). Validated in Rust so web and apps behave identically.
- Message store v2 (100k messages, threads index, migration from v1). A per-user **self group** syncs read state, mutes, drafts and accepted security codes between your own devices.
- **P1** channels, DMs, group DMs, unread, presence. **P2** threads, mentions, reactions, edits/deletes, pins, topic, typing. **P3** encrypted files (64 KiB AES-GCM chunks, key inside the message, 25 MB default, members-only download). **P4** search on each device only. **P5** notification levels, Do Not Disturb.

## 6. Slash commands
- Shared registry spec on web and Flutter; built-ins first, then bot commands advertised by `bot.manifest` in that channel; collisions shown as `/deploy (bot)`.
- Built-ins: `/call /video /burn /reset /timer /me /shrug /poll /remind /invite /topic /mute` (plus `/help /verify /theme /clear /emoji` already on the web branch).
- Bot commands are encrypted `command` messages to the bot member (channel-visible or ephemeral via the user↔bot DM); the bot learns the caller from the authenticated sender.
- Permissions from the MLS roles extension; the bot enforces its own command permissions.

## 7. Bots, API, MCP, plugins
- **Bots:** admin creates a bot account and a one-time provisioning token; the bot registers its own keys and gets a revocable bearer token; joins channels only by invitation; 🤖 badge.
- Runtimes: Rust `crates/chatbot` and TypeScript `packages/sdk` (wraps the WASM core). There is no plaintext REST API by design — the SDK does the crypto.
- **Events:** same socket with a bot token, or long-poll; **webhooks** deliver ciphertext only, HMAC-signed, SSRF-checked.
- **MCP server:** a local process (`crates/chat-mcp`) running as its own bot account (not a linked device of a person). Tools: `list_channels`, `read_messages`, `post_message`, `reply_in_thread`, `search` (local index). Only channel admins can invite it; persistent "AI agent in this channel" banner; per-channel read/post scopes; optional confirm-before-post; no pre-join history. **Never server-side with plaintext** — that would make the server a reader of every channel it's in.
- **Plugins:** bots with signed manifests and admin-approved scopes; no third-party code in the web client.

## 8. Milestones (engineer-weeks)
| M | Scope | Effort |
|---|---|---|
| M0 | WASM foundation; port today's web 1:1 crypto onto WASM behind a flag (retire Safari/WASM risk early) | 3–4 |
| M1 | Device registry, DeviceList/certs, per-device inbox, auto-migration | 2–3 |
| M2 | MLS in chatcore (provider, credentials, policy, payloads, API) | 5–7 |
| M3 | Delivery service (epochs, logs, Welcomes, validation, retention) | 3–4 |
| M4 | Web channels + MLS DMs, store v2, self group | 4–5 |
| M5 | Linked devices (QR link, revoke, recovery) | 3–4 |
| M6 | Flutter parity + decrypt-on-device push (iOS Notification Service Extension, Android background, web SW) | 5–7 |
| M7 | Threads, mentions, reactions, edits, pins, typing | 2–3 |
| M8 | Slash commands (bot-aware) | 1.5–2 |
| M9 | Encrypted files | 2 |
| M10 | Local search | 1.5 |
| M11 | Bots, SDK, events, webhooks | 3–4 |
| M12 | MCP server | 1.5–2 |
| M13 | Plugins | 1.5–2 |
| M14 | History share (optional) | 1.5 |

Total ≈ 42–55 ew; minimum viable Slack-like E2E (M0–M5, M7–M8) ≈ 25–32 ew.

**Riskiest:** state forks (ambiguous commit outcomes, concurrent app/extension/tab writers), OpenMLS API/storage churn, WASM on Safari, migrating without false warnings, server-side PublicGroup validation performance, large channels on low-end phones.

## 9. Open questions
1. Account key on a single primary device (recommended) or copied to every native device?
2. Keep "verified" status across a signed primary transfer, or require re-verification?
3. Any workspace member can DM anyone (Slack-like), or keep contact requests?
4. Is "the server says they're a member" enough for public-channel joins, or admin-signed membership certificates?
5. Server log retention (default 30 days)? History share on by default for public channels?
6. "Mentions only" push: allow a cleartext mention hint to the server, or filter on the device?
7. `/burn` in groups: admin delete-for-everyone, sender-only, or local only?
8. Device labels/platforms visible to the server, or encrypted?
9. `/remind` on web: server-timed delivery (server learns the time) or only while the app is open?
10. Post-quantum ciphersuite now or later?
11. Group calls ("huddles" with an encrypted media relay) on the roadmap?
12. One workspace per deployment OK?
13. 60 days of receive-only legacy 1:1 crypto after both sides support MLS OK?
