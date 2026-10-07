# Browser call verification

Start the signaling server, install `playwright-core` and its Chromium browser,
then run with a local test administrator token (never a production token):

```sh
ADMIN_TOKEN=... TEST_ORIGIN=http://localhost:3000 node tests/browser/call.mjs
```

`BROWSER_EXECUTABLE` can select an existing Chromium executable.
`PLAYWRIGHT_MODULE` can select an existing Playwright module by absolute path.
The runner creates two isolated browser contexts with fake microphone/camera
devices and grants media permission explicitly. It never prints invitation tokens.

Options:

- `REUSE_BROWSER=true`: run successive video and audio calls in the same browser.
- `EXPECT_RELAY=true`: assert both selected local candidates are TURN relays.
- `TEST_PERMISSIONS=true`: first deny microphone permission, grant microphone and
  camera access, retry Join, verify live tracks and signaling, then hang up and
  assert stopped capture and revoked invitation.
- `TEST_MODE=permissions`: run only that denial-and-retry gate without peer calls.
- `TEST_MODE=audio` or `video`: isolate one media mode.
- `LOCAL_NETWORK_ACCESS=true`: additionally grant Chromium's local-network
  permission for diagnosis; this does not disable browser security.

Success requires received audio bytes to increase over a one-second interval on
both sides. Video calls additionally require increasing received video bytes and
decoded frames. Tests verify mute, camera disable, hangup, peer connection cleanup,
and revoked room credentials. Connection failures print signaling order, candidate
application results, SDP fingerprints/ICE generation identifiers, and transport
statistics. These diagnostics contain local network addresses; review before sharing.

Local macOS verification on 2026-09-07 passed repeated forced-TURN video/audio
calls with sustained bidirectional media and permission-denied recovery.
The default `all` ICE policy with TURN configured also passed successive video
and audio calls, selecting a peer-reflexive/relay pair and receiving increasing
media counters in both directions.
Direct
host-only calls were intermittent: candidates arrived in order and
`addIceCandidate` resolved, but failed runs exposed no remote candidate pairs.
Both Chromium builds 1223 and 1243 showed this behavior; granting Chromium local
network permission and preserving candidate `usernameFragment` did not eliminate
it. Do not interpret a single direct-call success as reliable cross-network proof.

## Encrypted chat, device history and backups

Run against a disposable signaling instance with TURN configured. This creates a
room, exchanges private test messages, downloads an encrypted backup into a
temporary directory, and removes its room/browser state/artifact afterwards:

```sh
ADMIN_TOKEN=... TEST_ORIGIN=http://localhost:3000 EXPECT_RELAY=true node tests/browser/chat.mjs
```

Set `RELAY_ONLY=true` on the server when requiring a relay-only assertion. The
same `BROWSER_EXECUTABLE` and `PLAYWRIGHT_MODULE` overrides are supported. For an
isolated HTTPS fixture with a local test certificate, `TEST_INSECURE_TLS=true`
permits the exception only for a loopback origin; do not use it for deployment
verification against a public server.

The chat gate checks two separate browser/device contexts with media permissions
denied: no microphone/camera API calls, reliable ordered data-channel delivery,
recipient acknowledgements, safe rendering of hostile text, and absence of chat
markers from captured HTTP and signaling WebSocket traffic. It then verifies
device history after reload and a service-worker-controlled reload with browser
networking actually disabled, encrypted export without plaintext credentials,
wrong-password rejection, restoration into a fresh context, expiry purge and
prevention of resurrection from an older backup. Expiry uses the browser test
clock; this does not prove resistance to a device owner changing their clock or
retaining copies. It also does not prove human peer identity or protection
against a compromised server replacing the application's JavaScript.
