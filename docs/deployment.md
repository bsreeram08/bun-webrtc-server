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

Privately share the two distinct participant links. The administrator token stays on the server.

### Accounts (passkeys and contacts)

Accounts are on by default. The signaling service keeps an SQLite database in `DATA_DIR` (Compose: the `signaling_data` volume at `/data`; elsewhere `./data` relative to the working directory). It is created with owner-only permissions (directory `0700`, file `0600`). Set `ACCOUNTS=off` to run invitation links only. Passkeys are bound to the hostname of `PUBLIC_ORIGIN`; changing the domain later invalidates every registered passkey.

Sign-up needs a single-use invite code (valid seven days). Create the first one on the server, then open the printed link and register with a passkey:

```sh
docker compose --env-file deploy/.env exec -e PUBLIC_ORIGIN=https://calls.example.com signaling bun --no-env-file scripts/create-invite.ts
```

Signed-in people create further invites from the app (⋯ → Invite someone). After that, contacts call and message each other from the app without anyone running `create-room.ts`.

Contact messages are end-to-end encrypted on the devices. They wait in the same database (the `mailbox` table, ciphertext only) until the recipient's device acknowledges them, for at most 30 days; plan for up to 50 MiB of waiting envelopes per account in the worst case. Each account should use one messaging device: signing in on another browser creates a new encryption identity, which contacts see as a security-code change.

Back up the account database together with `deploy/.env`: stop signaling or use SQLite's online backup (`sqlite3 accounts.sqlite ".backup accounts-backup.sqlite"`), and keep the copy private. It holds usernames, the contact graph, session hashes, passkey and encryption public keys, and undelivered message ciphertext — no readable messages and no private keys — but it is still sensitive metadata. Losing it means everyone re-registers with new invites; message history on devices is unaffected.

The third-party runtime dependencies are the passkey verifier `@simplewebauthn/server` and the Web Push sender `web-push`, both pinned exactly in `packages/signaling/package.json` with its full dependency tree locked in `packages/signaling/bun.lock`. The image installs it with `bun install --production --frozen-lockfile`, which fails instead of resolving different versions. Install the same way on any non-Docker host, from inside `packages/signaling` with no parent `package.json` workspace above it, and never with `--no-save` or without the lockfile. Review lockfile diffs when updating. Treat invite links as passwords. The browser must receive microphone/camera permission. Use two physical devices on different networks to test both audio and video. For relay verification add `RELAY_ONLY=true` to `deploy/.env`, recreate signaling, and confirm the selected ICE pair uses `relay` candidates in browser WebRTC diagnostics. A passing HTTP health check alone does not verify calls.

### Notifications (Web Push)

Signed-in users can turn on notifications for messages and calls. On first start the service generates a VAPID key pair in `DATA_DIR/vapid.json` (owner-only `0600`; it is never overwritten). Back it up with the account database: losing or replacing it invalidates every device subscription, and users must turn notifications on again. To manage the keys yourself, set `VAPID_PUBLIC_KEY` and `VAPID_PRIVATE_KEY` (and optionally `VAPID_SUBJECT`, default `PUBLIC_ORIGIN`). The service sends pushes outbound over HTTPS to the browsers' push services (Google FCM, Mozilla, Apple, Microsoft), so allow outbound HTTPS from the host. Subscriptions are only accepted for those services' hosts.

On iPhone and iPad, Web Push works only after the user adds the app to the Home Screen and opens it from there (iOS 16.4 or later); the app shows that hint instead of the button. Ringtones are synthesized in the browser and play only while the app is open; a closed app relies on the notification.

### Native apps (iOS, Android, desktop)

The same server serves the native apps. They sign in with passkeys and receive a bearer token instead of a cookie, and they get notifications through Firebase Cloud Messaging (Android) and APNs (iOS). Everything below is optional: without it the web app works as before, the `/.well-known` files return 404 and native push is reported as not configured.

Passkeys and app links need the domain to vouch for the apps. Set these in `deploy/.env` (Compose) or the service environment, then restart signaling:

| Variable | Value | Where it comes from |
| --- | --- | --- |
| `APPLE_APP_IDS` | `TEAMID1234.in.sreerams.calls` (comma-separated) | Apple Developer → Membership (Team ID) + the app's bundle ID. Served in `/.well-known/apple-app-site-association` for `webcredentials` (passkeys) and `applinks`. |
| `ANDROID_PACKAGE` | `in.sreerams.calls` | The Android application ID. |
| `ANDROID_CERT_SHA256` | `AB:CD:…` (32 colon-separated bytes, comma-separated list) | `keytool -list -v -keystore release.jks` or Play Console → App integrity → App signing key certificate. Use the Play signing key for store builds, plus the upload/debug key while testing. Served in `/.well-known/assetlinks.json`, and also accepted as the Android passkey origin. |
| `ANDROID_APK_KEY_HASHES` | unpadded base64url SHA-256 (optional) | Extra `android:apk-key-hash:` passkey origins; normally derived from `ANDROID_CERT_SHA256`. |

Apple fetches the association file through its CDN, so it must be reachable over HTTPS on the exact `PUBLIC_ORIGIN` host without redirects; Caddy/nginx must pass `/.well-known/*` to signaling. Startup fails on malformed values rather than silently breaking sign-in.

Native push (all optional, configure the platforms you ship):

| Variable | Purpose |
| --- | --- |
| `FCM_SERVICE_ACCOUNT_JSON_PATH` | Path to a Firebase service-account JSON key: Firebase console → Project settings → Service accounts → Generate new private key. Grant it only the Firebase Cloud Messaging role. Store it beside the other secrets, mode `0600`. |
| `APNS_KEY_PATH`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID` | An APNs authentication key (`AuthKey_XXXX.p8`) from Apple Developer → Certificates, Identifiers & Profiles → Keys (enable Apple Push Notifications service), its 10-character key ID, your Team ID and the app's bundle ID. One key covers alerts and VoIP pushes (topic `<bundle>.voip`). |
| `APNS_ENV` | `sandbox` for development builds, `production` for TestFlight/App Store. Tokens from one environment are rejected by the other. |

With Compose, put the key files in `deploy/native/` (git-ignored, owner-only, readable by the deployment UID) and point the variables at `/native/…`, e.g. `FCM_SERVICE_ACCOUNT_JSON_PATH=/native/fcm.json` and `APNS_KEY_PATH=/native/AuthKey_ABC123DEFG.p8`. The service sends to `fcm.googleapis.com`, `oauth2.googleapis.com` and `api(.sandbox).push.apple.com` over HTTPS (APNs uses HTTP/2 on 443), so allow outbound HTTPS. Back up the FCM JSON and the `.p8` key with `deploy/.env`; both can be revoked and reissued from the consoles if lost or leaked (revoke immediately on leak: they let anyone push to your users' devices). Device tokens live in the `push_native` table and are removed on sign-out, session expiry and when Google/Apple report them invalid.

`GET /api/version` returns `{ api, minClient }`; raise the minimum versions in `packages/signaling/accounts.ts` (`MIN_CLIENT`) when an app release becomes incompatible.

## Operation and security boundaries

Rooms and participant credentials live in memory and are lost when Bun restarts. Rooms expire automatically. HTTPS protects signaling; WebRTC encrypts peer media with DTLS-SRTP even when coturn relays it. The service still handles connection metadata, and this is not Signal-style identity verification. Protect administrator credentials and the server/software supply chain. TURN credentials are short-lived and authenticated; quotas and denied private peer ranges limit relay abuse. Default TURN uses UDP/TCP 3478, with encrypted WebRTC media; TURN-over-TLS on 5349/443 is not configured, so networks that block these TURN transports may require a separate TLS TURN endpoint.

To inspect services, use `docker compose --env-file deploy/.env logs --tail=100`. Review logs locally before sharing them because peer addresses may appear. To update, review changes, back up `deploy/.env`, `deploy/turnserver.conf`, and the Caddy data volume, then rebuild with the start command above. Rotate both TURN secret copies together and restart signaling and TURN; rotate the administrator token in `deploy/.env` and restart signaling if compromised. Recreate containers with `docker compose --env-file deploy/.env up -d --force-recreate` after editing environment values. Running sessions will be interrupted.

The deployment images use explicit versions. Keep those versions updated after reviewing release notes and validating calls. Persistent user identities, group conferencing and abuse administration remain separate future work. The browser app supports device-local chat history and encrypted backup files; see [device chat and phone migration](device-chat.md).

References: [coturn configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf), [coturn Docker setup](https://github.com/coturn/coturn/tree/master/docker/coturn), [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).

## Custom emoji

Custom emoji images are stored in `DATA_DIR/emoji/` (content-addressed) and listed in `accounts.sqlite`; back the folder up with the database. Imports by URL are allowed from `emojis.slackmojis.com` and `slackmojis.com`; add more hosts with `EMOJI_IMPORT_HOSTS=host1,host2` (exact host names, https only). The server needs outbound HTTPS to those hosts for imports. nginx must allow request bodies of at least 768 KiB on `/api/emoji` (`client_max_body_size 1m;` covers it; the default 1 MiB already does).

## WebAssembly messaging core

`packages/signaling/public/core/` holds the browser build of `crates/chatcore` (content-hashed files plus `manifest.json`). It is committed, so a server deploy needs no Rust toolchain. After changing `crates/chatcore` or `crates/chatcore-wasm`, rebuild with `bun run build:wasm` (rustc 1.93.1, target `wasm32-unknown-unknown`; the script installs the pinned wasm-bindgen CLI) and commit the result. CI's `core` job runs `bun run build:wasm --check` (fails if the committed core wasn't built from the current source) and then the interop matrix against the committed bytes. The web app only uses this core on a device whose user chose it in Settings → Advanced; signal.js remains the default. Never set `ALLOW_TEST_FLAGS` on a public server (it is ignored unless `PUBLIC_ORIGIN` is a loopback address).
