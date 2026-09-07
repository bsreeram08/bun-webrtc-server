# Self-hosted audio and video calls

This deployment runs Bun signaling, coturn authenticated media relay, and Caddy HTTPS. It does not require hosted identity services. Room creation requires the administrator token; participant invite links grant access to one room. It is an initial one-to-one calling and device-to-device chat service, not a Signal replacement. Message history stays on devices; the server has no chat storage. No system can be guaranteed unhackable.

## Prepare a Linux server

Use a Linux machine with Docker Engine and Docker Compose, Bun 1.4.0 for setup, a public IPv4 address, and two DNS A records (`calls.example.com` and `turn.example.com`) pointing to it. This Compose file uses host networking for Caddy and coturn; Docker Desktop is not the production target. Remove DNS AAAA records unless you also configure and test IPv6. Do not put TURN behind an HTTP-only CDN proxy.

Allow inbound TCP 80 and 443 for HTTPS certificates and the application, UDP and TCP 3478 for TURN, and UDP 49160–49259 for relay traffic. Keep TCP 3000 private. Permit outbound UDP to public peers, DNS and HTTPS. The host firewall should also block TURN access to private infrastructure and management service ports (while allowing the relay port range). If the host is behind NAT, forward the same relay port range without port translation, and pass its local/private IPv4 address as the optional fifth setup argument (after the email). Setup writes `relay-ip=PRIVATE_IP` and `external-ip=PUBLIC_IP/PRIVATE_IP`; without that argument it binds the public IPv4 address directly.

## Configure and start

From the repository root, substitute your real values:

```sh
bun --no-env-file scripts/setup.ts calls.example.com turn.example.com 203.0.113.10 admin@example.com
docker compose --env-file deploy/.env config --quiet
docker compose --env-file deploy/.env up -d --build
docker compose --env-file deploy/.env ps
curl --fail https://calls.example.com/health
```

Setup generates independent random administrator and TURN secrets in `deploy/.env` and `deploy/turnserver.conf`, with owner-only file permissions. It refuses to overwrite either file and never changes the old repository `.env`. Run setup as the account that owns the deployment; its UID/GID are used so coturn can read its restricted configuration. Keep both generated files private and out of source control. Do not paste `docker compose config` without `--quiet`: it includes expanded secrets.

Create participant invitations from the trusted server:

```sh
docker compose --env-file deploy/.env exec signaling bun --no-env-file scripts/create-room.ts
```

Privately share the two distinct participant links. The administrator token stays on the server. Treat invite links as passwords. The browser must receive microphone/camera permission. Use two physical devices on different networks to test both audio and video. For relay verification add `RELAY_ONLY=true` to `deploy/.env`, recreate signaling, and confirm the selected ICE pair uses `relay` candidates in browser WebRTC diagnostics. A passing HTTP health check alone does not verify calls.

## Operation and security boundaries

Rooms and participant credentials live in memory and are lost when Bun restarts. Rooms expire automatically. HTTPS protects signaling; WebRTC encrypts peer media with DTLS-SRTP even when coturn relays it. The service still handles connection metadata, and this is not Signal-style identity verification. Protect administrator credentials and the server/software supply chain. TURN credentials are short-lived and authenticated; quotas and denied private peer ranges limit relay abuse. Default TURN uses UDP/TCP 3478, with encrypted WebRTC media; TURN-over-TLS on 5349/443 is not configured, so networks that block these TURN transports may require a separate TLS TURN endpoint.

To inspect services, use `docker compose --env-file deploy/.env logs --tail=100`. Review logs locally before sharing them because peer addresses may appear. To update, review changes, back up `deploy/.env`, `deploy/turnserver.conf`, and the Caddy data volume, then rebuild with the start command above. Rotate both TURN secret copies together and restart signaling and TURN; rotate the administrator token in `deploy/.env` and restart signaling if compromised. Recreate containers with `docker compose --env-file deploy/.env up -d --force-recreate` after editing environment values. Running sessions will be interrupted.

The deployment images use explicit versions. Keep those versions updated after reviewing release notes and validating calls. Persistent user identities, group conferencing and abuse administration remain separate future work. The browser app supports device-local chat history and encrypted backup files; see [device chat and phone migration](device-chat.md).

References: [coturn configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf), [coturn Docker setup](https://github.com/coturn/coturn/tree/master/docker/coturn), [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).
