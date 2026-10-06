# Calling API

This is the current development protocol for the Bun service. A separate chat or
identity application can create calling rooms through its trusted backend. No
administrator credentials belong in a participant's browser.

## HTTP

All paths are relative to `PUBLIC_ORIGIN`. Use HTTPS except for loopback
development. Successful and error JSON responses disable caching. Browser
requests with a foreign `Origin` are rejected; CLI requests may omit `Origin`.

| Method and path | Authorization | Result |
| --- | --- | --- |
| `GET /health` | None | `{ "status": "ok" }`; proves HTTP availability only. |
| `POST /rooms` | `Authorization: Bearer ADMIN_TOKEN` | HTTP 201 with `roomId`, `expiresAt` (Unix milliseconds), and two `participants` containing distinct `token` values and a `polite` boolean. |
| `GET /rooms/:roomId/ice` | Participant bearer token for this room | `{ "iceServers": [...], "iceTransportPolicy": "all" or "relay" }`, suitable for `RTCPeerConnection`. |
| `DELETE /rooms/:roomId` | Either participant's bearer token | `{ "status": "ended" }`; removes the room, revokes invitations, and closes both signaling sockets. |

The administrator token cannot substitute for a participant token on room ICE or
deletion endpoints. Invalid/expired credentials return 401, foreign origins 403,
source limits 429, and room capacity exhaustion 503. Deleting an already ended
room returns 401 because its credentials no longer exist.

### Account API (when `DATA_DIR` accounts are enabled)

Cookie-authenticated JSON endpoints under `/api`. Every non-GET request needs this app's `Origin`.

| Method and path | Result |
| --- | --- |
| `POST /api/register/options` `{ invite, username }` | Passkey creation options and a single-use `flowId`. 400 for a bad/used/expired invite or username, 409 if taken. |
| `POST /api/register/verify` `{ flowId, response }` | Creates the account, consumes the invite, sets the session cookie. |
| `POST /api/login/options` | Usernameless passkey request options and a `flowId`. |
| `POST /api/login/verify` `{ flowId, response }` | Sets a fresh session cookie. Failures are always `Sign-in failed.` |
| `GET /api/me` · `POST /api/logout[?all=1]` | Current user; sign out this session (or every session). |
| `POST /api/invites` | A new single-use invite `{ code, expiresAt }`, shown once. At most 20 unused per account. |
| `GET /api/contacts` | Mutual contacts (with `online`), incoming requests, and outgoing requests (by typed username, `id: null`). |
| `POST /api/contacts` `{ username }` | Always `202 { status: "requested" }` for any well-formed username; accepts if they already asked you. |
| `POST /api/contacts/:username/accept` · `DELETE /api/contacts/:username` | Accept a request; remove a contact or cancel/decline a request (also ends any live room). |
| `POST /api/conversations/:username/session` `{ kind: "chat" \| "voice" \| "video" }` | Mutual contacts only. Returns `{ roomId, token, online }` for the caller's own slot. Calls always replace the pair's room; chat reuses a live one. 409 if already connected. |
| `POST /api/conversations/:username/decline` `{ roomId }` | Ends a ringing call; the caller's socket closes with code 4002. |
| `PUT /api/keys` `{ identity: { dh, sign }, signedPreKey?: { id, key, signature }, oneTimePreKeys?: [{ id, key }] }` | Publishes this device's public keys (base64url X25519/Ed25519, 64-byte signature). The first upload, and any new identity, needs a signed prekey; a new identity voids old prekeys. Contacts get `keys` on the first upload and on every change. At most 100 one-time prekeys per upload and 200 waiting. Returns `{ oneTimePreKeys, changed }`. |
| `GET /api/keys/count` | `{ oneTimePreKeys, signedPreKeyId }` for this account, to decide when to top up or rotate. |
| `GET /api/keys/:username` | Mutual contacts only: `{ userId, identity, signedPreKey, oneTimePreKey }` (`oneTimePreKey` may be `null`). Atomically consumes one one-time prekey; a few per second per pair. |
| `GET /api/keys/:username/identity` | Mutual contacts only: `{ userId, identity }`, consuming nothing. |
| `POST /api/messages` `{ to, envelope }` | Mutual contacts only. `envelope` is base64url, at most 64 KiB decoded, opaque to the server. Stored until acknowledged (30-day TTL) and delivered at once to online devices. `201 { id, createdAt }`; 507 when the recipient's mailbox is full (1,000 / 50 MiB); 429 for the per-sender share (200 / 10 MiB) or the rate limit. |
| `GET /api/events` (WebSocket) | Stream of `hello` (online contacts), `presence`, `contacts` (refetch), `incoming` `{ from, kind, roomId, token }`, `ended`, `keys` `{ id }` (a contact's identity was set or changed: re-check it) and `envelope` `{ id, from: { id, username }, envelope, createdAt }` in order, at most 32 unacknowledged at once. The only client message is `{ "type": "ack", "id" }`, which deletes that envelope if it is addressed to this account; anything else closes the stream (1008). Closes with 4401 when the session ends. |

Room sockets for contact rooms close with 4001 when a newer call replaces the room and 4002 when the call is declined.

The default lifetime is one hour, and state is memory-only. Server restart ends
all rooms. Each invitation grants one participant slot; it is not proof of human
identity. The operator's `scripts/create-room.ts` command produces two browser
links with credentials in URL fragments. The browser removes that fragment from
the address bar and retains it only in page memory.

## WebSocket

Connect to `/rooms/:roomId/socket` with the two offered subprotocols:

```js
const socket = new WebSocket(socketURL, ['webrtc', participantToken]);
```

The request's `Origin` must exactly match `PUBLIC_ORIGIN`. The server selects
`webrtc`; it never echoes the credential. Do not log the offered subprotocol
header. Only one active connection is allowed per participant token.

Invitations are single-use. When a socket is accepted, the server replaces that
participant's credential and returns the new token in `welcome`; the token that
opened the socket immediately stops working for the socket, ICE and deletion
endpoints. Clients keep the rotated token in memory for reconnects, ICE refreshes
and hangup. A participant who loses it (for example by reloading the page) needs
a new invitation.

Server events:

| Type | Fields | Meaning |
| --- | --- | --- |
| `welcome` | `polite`, `token` | The participant is authenticated. `token` replaces the presented credential (single-use invitations). The non-polite participant initiates the first offer. |
| `ready` | `sessionId` | Both participants are connected. Create a fresh peer connection for this pairing. |
| `description` | `sessionId`, `description: { type, sdp }` | Offer or answer from the paired participant. |
| `candidate` | `sessionId`, `candidate` | ICE candidate, or `null` for end-of-candidates. |
| `peer-left` | None | The other signaling connection closed. Retire the current peer connection and wait for another `ready`. |
| `error` | `error` | Includes `Stale session`, `Peer unavailable`, and `Delivery failed`. |

Clients send `description` and `candidate` with the **exact `sessionId` from the
latest `ready` event**. Forwarded messages retain that identifier. Each new pairing
gets a fresh random identifier, including reconnects with the rotated participant
token. The server rejects missing/old identifiers, so delayed packets cannot
reach a replacement peer connection. Clients must also ignore incoming messages
from retired pairings and guard asynchronous callbacks from retired peers.

Candidate objects contain `candidate`, `sdpMid`, `sdpMLineIndex`, and optionally
`usernameFragment`. Preserve the username fragment when provided: it identifies
an ICE generation within a pairing. ICE restarts keep the pairing's `sessionId`
but negotiate fresh ICE credentials. Queue candidates arriving before their SDP,
with a finite queue limit. The reference browser uses perfect negotiation to
resolve colliding offers.

`{ "type": "hangup" }` ends the entire room over an active WebSocket. The browser
uses authenticated HTTP `DELETE` instead, allowing room closure even when its
WebSocket is disconnected. Capture stops locally immediately; if HTTP cannot
reach the server, the UI reports that room closure could not be confirmed.

## Recovery and limits

The reference browser retries unexpected signaling loss for about 90 seconds,
refreshing room/ICE authorization before reconnecting. Expired rooms stop retries.
It preserves local mute/camera state while reconnecting and stops all media tracks
when the user ends the call, leaves the page, or recovery is abandoned. Delayed
media-permission results cannot restart capture after cancellation.

ICE failure or a persistent disconnection triggers a bounded number of ICE
restarts. `peer-left` followed by `ready` creates a fresh peer connection rather
than reusing the old pairing. A successful signaling reconnect does not by itself
prove media recovery; inspect connection state and received media statistics.

Messages are capped at 64 KiB, SDP strings at 60,000 characters, and candidate
strings at 4,096 characters. Each socket has a 100-message-per-second budget and
bounded outgoing buffering. Signaling is not persisted or replayed; there are no
delivery receipts or durable messaging guarantees. Chat needs a separate protocol.

TURN credentials remain valid until their timestamp expires even after room
deletion. See [security boundaries](security.md) and [deployment](deployment.md).

## Custom emoji

All require a signed-in session; writes also require this app's Origin.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/emoji` | The workspace pack: `{ emoji: [{ name, url, animated, mine }] }`. `url` is always same-origin `/emoji/<sha256>.<png|gif|webp>`. |
| `POST /api/emoji` `{ name, image }` | Upload. `image` is base64 (optionally a `data:image/…;base64,` URL) of a PNG, GIF or WebP up to 512 KB. Names match `^[a-z0-9_+-]{2,32}$` and are unique. 201, or 400/409/413/429. |
| `POST /api/emoji/import` `{ name, url }` | The server fetches the image from an allowlisted https host (see security.md for the SSRF rules). |
| `DELETE /api/emoji/:name` | Only the person who added it, or `Authorization: Bearer <ADMIN_TOKEN>`. |
| `GET /emoji/<sha256>.<ext>` | The image, with a sandboxing CSP and an immutable cache. |

## Message payloads added for commands

Inside the encrypted envelope (and the guest data channel): `{v:1, type:'message', id, text, createdAt, expiresAt}` may add `kind:'action'` (a `/me` line) or `kind:'poll', poll:{question, options}`; `{v:1, type:'vote', id, poll, option}` records a vote (`option` an index, or `null` to clear).
