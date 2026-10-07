# webrtc-bun

Self-hosted one-to-one audio and video calls, using Bun for signaling and coturn for media relay. The browser client supports camera calls, audio-only calls, mute, camera controls, and ending a room. No Auth0 account, Redis server, or hosted communication service is required by the new runtime.

This is a working foundation under active development. The installable browser app adds device-to-device text chat, device-local history, disappearing messages, and encrypted backup files you can keep in Google Drive. See [chat and phone migration](docs/device-chat.md). Account management, group calling, and Signal-style identity verification are future work. See [current status](docs/status.md) and [security boundaries](docs/security.md).

To integrate calls into your own application, use the [calling API](docs/signaling-api.md). Room creation stays on your trusted backend; each participant receives a separate invitation.

## Try locally

Install Bun 1.4.0 or newer. The signaling runtime uses only built-ins, so it can start without installing the repository's legacy dependencies.

For a single-room demo, run this from the repository root:

```sh
bun --no-env-file run demo
```

Open its two private links in separate browser windows and join. Stop with Ctrl+C. The demo generates its own administrator credential and keeps it out of the links.

To manage several rooms locally, use these commands instead:

```sh
export ADMIN_TOKEN="$(bun --no-env-file -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))')"
export PUBLIC_ORIGIN=http://localhost:3000
bun --no-env-file run start &
CALL_SERVER_PID=$!
curl --fail --retry 10 --retry-delay 1 --retry-connrefused http://localhost:3000/health
bun --no-env-file run room:create
```

Open the two different participant links in separate browser windows, then click **Join call** in each. Allow camera/microphone access. Select **Audio only** before joining to skip the camera. These local links work on this machine; use the HTTPS deployment below for other devices and networks. Keep each participant link private, and never send the administrator token to a participant.

When finished with this local server:

```sh
kill "$CALL_SERVER_PID"
```

`bun --no-env-file run dev` runs the signaling server with automatic restart. Rooms live in memory and disappear on restart. Runtime commands explicitly disable loading the repository's old `.env` file; provide configuration through environment variables.

## Self-host on your server

Follow the [deployment guide](docs/deployment.md) for a Linux Docker Compose setup with HTTPS, private administrator credentials, authenticated TURN, firewall ports, and real-network verification. It generates isolated configuration under `deploy/` and preserves existing configuration. WebRTC media is encrypted, including through TURN, but no system is guaranteed unhackable.

The small standalone Bun STUN implementation is available through `bun --no-env-file run stun`; production deployments use coturn for both STUN and TURN. Bun handles signaling rather than terminating or transcoding media.

## Verify changes

```sh
bun install --frozen-lockfile
bun --no-env-file run typecheck
bun --no-env-file test
```

For browser checks, use Node.js 22 or newer and keep the local server running with the same exported `ADMIN_TOKEN`. Install Chromium once, then run:

```sh
bunx playwright-core install chromium
TEST_ORIGIN=http://localhost:3000 bun --no-env-file run test:browser
```

The browser test creates two isolated browser contexts, checks increasing received audio/video bytes and decoded video, verifies mute/camera controls, and checks hangup and invite revocation. It uses synthetic media. `BROWSER_EXECUTABLE=/absolute/path/to/chromium` selects an existing browser; `TEST_MODE=audio` or `TEST_MODE=video` narrows the run. Set `RELAY_ONLY=true` on the server with valid `TURN_SECRET` and `TURN_URLS`, then set `EXPECT_RELAY=true` when running the test to require relay candidates. `REUSE_BROWSER=true` tests consecutive calls in the same browser. Actual devices on different networks are also required before declaring a deployment ready.

The older Auth0/Redis manager and older STUN experiment remain for reference and are outside the supported runtime; do not use them as production entrypoints.
