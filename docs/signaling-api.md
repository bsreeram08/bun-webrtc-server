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

Server events:

| Type | Fields | Meaning |
| --- | --- | --- |
| `welcome` | `polite` | The participant is authenticated. The non-polite participant initiates the first offer. |
| `ready` | `sessionId` | Both participants are connected. Create a fresh peer connection for this pairing. |
| `description` | `sessionId`, `description: { type, sdp }` | Offer or answer from the paired participant. |
| `candidate` | `sessionId`, `candidate` | ICE candidate, or `null` for end-of-candidates. |
| `peer-left` | None | The other signaling connection closed. Retire the current peer connection and wait for another `ready`. |
| `error` | `error` | Includes `Stale session`, `Peer unavailable`, and `Delivery failed`. |

Clients send `description` and `candidate` with the **exact `sessionId` from the
latest `ready` event**. Forwarded messages retain that identifier. Each new pairing
gets a fresh random identifier, including reconnects with the same participant
tokens. The server rejects missing/old identifiers, so delayed packets cannot
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
