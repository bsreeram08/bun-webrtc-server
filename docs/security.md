# Security model

This service currently provides two-person calling through room invitations. It has no Signal-style identity keys, safety numbers, account verification or independent security audit. No implementation can be guaranteed unhackable. Treat the current checks as specific protections with tested limits, not a general security certification.

## Invitations and trust

The administrator bearer token permits room creation. Setup generates an independent random administrator token and TURN shared secret. Each room receives two random 256-bit participant tokens; the signaling server retains their SHA-256 digests in memory. Possession of a participant token grants that participant's room access and permission to request TURN credentials. Each participant can have one active signaling socket. A disconnected participant can reconnect until the room ends or expires.

An invitation is a password, not proof of a person's identity. Share it privately and verify the other person through an independently trusted channel when needed. The browser puts invitation credentials in the URL fragment; WebSocket authentication transmits the token as an offered subprotocol over WSS, and the ICE endpoint uses a bearer header. Do not log authorization or WebSocket protocol headers. Browser history, extensions, compromised endpoints, screenshots or careless sharing can still expose invitations.

Room state is memory-only. Hangup removes the room and closes both signaling sockets; expiry also removes it. Restarting the signaling service invalidates all room invitations. There is no persistent chat history or user-account database in this deployment.

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
