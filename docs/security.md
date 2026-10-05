# Security model

This service provides two-person calling and chat, either through one-time room invitations or between signed-in contacts. Accounts authenticate with passkeys; there are still no persistent end-to-end identity keys and no independent security audit. Each call instead shows a six-digit verification code (below). No implementation can be guaranteed unhackable. Treat the current checks as specific protections with tested limits, not a general security certification.

## Invitations and trust

The administrator bearer token permits room creation. Setup generates an independent random administrator token and TURN shared secret. Each room receives two random 256-bit participant tokens; the signaling server retains their SHA-256 digests in memory. Possession of a participant token grants that participant's room access and permission to request TURN credentials. Each participant can have one active signaling socket. Invitations are single-use: accepting a socket rotates that participant's token and returns the replacement only to that socket, so a copied or leaked link stops working once used. A disconnected participant reconnects with the rotated token, kept in page memory, until the room ends or expires.

An invitation is a password, not proof of a person's identity. Share it privately and verify the other person through an independently trusted channel when needed. The browser puts invitation credentials in the URL fragment; WebSocket authentication transmits the token as an offered subprotocol over WSS, and the ICE endpoint uses a bearer header. Do not log authorization or WebSocket protocol headers. Browser history, extensions, compromised endpoints, screenshots or careless sharing can still expose invitations.

Room state is memory-only. Hangup removes the room and closes both signaling sockets; expiry also removes it. Restarting the signaling service invalidates all room invitations. The backend has no chat history; its optional account database holds identity metadata only (see below). Chat history and outgoing queues are stored only in each device’s browser, and optional exported backups are password-encrypted files; see [device chat](device-chat.md). Ending a room does not delete the device-local history. **Burn conversation** deletes the conversation on this device, asks the other device to delete its copy (it confirms over the encrypted channel within two seconds when connected) and ends the room. A burn cannot reach an offline device, exported backup files or copies made by screenshots or a modified client.

## Accounts, contacts and what the server stores

Accounts are optional and use passkeys (WebAuthn) verified with the pinned `@simplewebauthn/server` library; there are no passwords. Registration requires a single-use invite code that expires after seven days; only its SHA-256 hash is stored, and an invite is consumed in the same transaction that creates the account. Sign-in is usernameless (discoverable credentials), so the sign-in endpoints never reveal which usernames exist. Registration and sign-in challenges are stored server-side, expire after five minutes and are single-use even when verification fails. Authentication endpoints have a tighter per-source rate limit than the rest of the API.

A successful sign-in issues a fresh random 256-bit session token in an `HttpOnly`, `SameSite=Strict` cookie (`__Host-` prefixed and `Secure` over HTTPS) that lasts 30 days; the database stores only its hash. Every authenticated request rechecks expiry. Signing out deletes that session and closes its presence stream; **Sign out everywhere** deletes every session of the account. A sweep every second also closes presence streams whose session expired or was deleted. All state-changing API requests must carry this app's `Origin`.

Contact requests are addressed to a typed username and are stored the same way whether or not that account exists, so adding someone does not reveal whether they are registered; each account may have at most 20 pending outgoing requests (they lapse after 30 days). Contacts become mutual only when the other person accepts. Only mutual contacts see each other's presence or can start a conversation, and the server rechecks this on every conversation request. A conversation request returns a credential only for the caller's own slot in that pair's room; the other person's credential goes only to their own authenticated presence stream. Removing a contact cancels requests in both directions, ends any live room for the pair and stops presence updates both ways.

With accounts enabled the server therefore stores more metadata than invitation-only mode: usernames, the contact graph, session hashes, passkey public keys and credential counters, invite hashes, and in memory who is online and which pairs have a live room. It never receives message content, call media or chat history: chat still travels device-to-device over the encrypted WebRTC channel, and each account conversation keeps its history only on the devices, under an opaque per-pair identifier. A compromised server could still learn this metadata, register accounts with leaked invites, or serve modified app code; the per-call verification code remains the check against an active man in the middle.

## Notifications

Push notifications are opt-in per device. The server stores each subscription (push-service endpoint and the browser's public encryption keys) with the session that created it; signing out removes it, as do expired sessions and push-service `404`/`410` responses. Endpoints must be HTTPS URLs on known push services (Google FCM, Mozilla, Apple, Microsoft), so the server never sends requests to arbitrary hosts.

Payloads are encrypted to the receiving browser (RFC 8291) and contain only the event type, the sender's username and, for calls, the call kind and room id — never message text, invitation tokens or call credentials. The push service learns that a notification was sent to a device, when, its size and urgency, but not who sent it or what it says. Messages are pushed only when the recipient has no open app; calls are pushed when the callee is offline or their open app does not confirm within four seconds that the call is ringing on a visible screen. An unanswered call that ends becomes a "missed call" notification.

Tapping a notification only opens the app on that contact's conversation. Nothing from a notification or the page URL can start or answer a call or turn on the microphone or camera: an incoming call keeps ringing on its sheet until the user taps Accept in the app. A notification's Decline action ends the call through the user's own session.

## Verification code

Every new peer connection runs a commit-then-reveal exchange on a dedicated encrypted data channel: each device commits to a random 256-bit nonce, reveals it only after receiving the other's commitment, and both derive a six-digit code from the two DTLS certificate fingerprints and both nonces. If an intermediary (including a compromised signaling server rewriting SDP) terminates DTLS separately with each device, the devices hash different fingerprints and the codes differ, except with probability one in a million per attempt. Read the code aloud over the call; if it differs, end the call. The check relies on the browser running unmodified app code: a compromised server that serves altered JavaScript can also alter the displayed code, which a packaged app would address.

Each live pairing also has a fresh server-issued session identifier. SDP and ICE must carry that identifier, preventing delayed signaling from an old connection reaching a participant who has rejoined. A participant can end the room using authenticated HTTP deletion even if its WebSocket is disconnected. If the network is unavailable, local capture stops immediately but server-side room deletion cannot be confirmed until the request reaches the server or the room expires.

## Media and server trust

WebRTC protects media in transit with DTLS-SRTP, including media carried through a TURN relay. This does not authenticate the human holding the invitation. The application trusts the server that delivers its JavaScript and signaling: a compromised server can replace that code or alter the call setup. Browser compromise and recording by the other participant are outside this service's protections. See the [WebRTC security architecture](https://www.rfc-editor.org/rfc/rfc8827).

The signaling and TURN operators can observe connection metadata. Direct connections may reveal network addresses to the peer; relay-only calling can reduce direct address exposure, but does not hide metadata from the relay operator. The default deployment offers TURN over UDP and TCP 3478. TURN-over-TLS is not configured; encrypted WebRTC media does not imply that every TURN control exchange has TLS protection.

## TURN credentials and abuse limits

Only a valid, unexpired room participant can obtain ICE configuration. TURN REST credentials use an HMAC of a username containing the room expiry and room identifier. The browser receives the temporary credential, never the shared TURN secret. Credentials are shared by the two participants of a room and are not per-person identities.

**Hangup does not revoke already issued TURN credentials.** They remain usable until their timestamp expires. Existing relay allocations also have their own lifetimes; ending signaling is not a guarantee of immediate TURN allocation termination. Rotate the shared secret and restart TURN when an incident requires invalidating issued credentials. Update both secret copies together and expect running calls to be disrupted.

Generated coturn configuration requires authenticated allocations, applies per-user and global quotas and bandwidth limits, disables TCP peer relaying, and denies configured private, loopback, link-local and multicast destination ranges. Host firewall rules remain necessary to protect management services and public addresses that route to private infrastructure. These controls do not provide protection against all distributed traffic or bandwidth attacks.

## HTTP, WebSocket and proxy controls

Room creation requires the administrator bearer token. WebSocket upgrades require the exact configured browser origin and a token belonging to that room. Foreign origins are rejected for the application APIs. Incoming signaling messages are validated and rebuilt from allowed fields before forwarding to the other participant; clients cannot select another target room.

HTTP requests use one-second limits of 60 accepted requests per source and 2,000 globally, with at most 4,096 source entries retained in a window. A source's rejected requests do not consume the global allowance. Health checks bypass this budget. Each WebSocket separately permits 100 messages per second, caps incoming messages at 64 KiB and limits buffered output. These are application resource controls, not a substitute for host/network protection; many legitimate users behind one NAT share a source budget.

Proxy identity is disabled by default. With `TRUST_PROXY=true`, only a direct loopback connection may supply one valid `X-Real-IP` address. Production Compose binds signaling to loopback and places Caddy on the host network. Caddy overwrites `X-Real-IP` with its connection's remote address. Preserve these three settings together. Do not expose signaling publicly with proxy trust enabled or add another proxy without revisiting address trust. `X-Forwarded-For` is not trusted by this implementation.

Static responses restrict scripts, framing and resource origins through CSP, restrict browser media permissions, suppress referrers and use `nosniff`. Credentials and responses use `no-store`. Production HTTPS is terminated by Caddy with HSTS. Generated secrets have owner-only file permissions; the signaling container runs as a non-root user with a read-only filesystem and dropped capabilities.

## Deployment scope

The production image copies `packages/signaling`, `packages/stun-server/native`, and the operator's `scripts/create-room.ts` command, and starts the new signaling server. The repository's legacy manager, Auth0 integration, custom TURN experiments, old scripts and old `.env` are not part of that image. They are not covered by the current deployment's security claims and should not be exposed as additional services without review.

Follow [deployment instructions](deployment.md) for firewall rules, secrets and updates, and [verification status](status.md) for the current evidence and remaining checks.
