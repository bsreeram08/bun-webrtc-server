# Direct-only ICE isolation

`tests/browser/direct-repro.mjs` deliberately excludes Bun, the signaling server, application
JavaScript, WebSockets, STUN servers, and TURN servers. Node serves an empty HTML
page. Native browser peer connections exchange descriptions and candidates in
memory, either within one page or between two isolated browser contexts through
Playwright bindings. Candidate dictionaries preserve `usernameFragment`.

Run with Playwright installed and a selected Chromium executable:

```sh
ROUNDS=2 REPRO_MODE=separate-contexts node tests/browser/direct-repro.mjs
```

Optional `PLAYWRIGHT_MODULE`, `BROWSER_EXECUTABLE`, `TIMEOUT_MS`, `ROUNDS`,
`REPRO_MODE`, and `REPRO_OUTPUT` control the runner. The default timeout is 30
seconds. Full local diagnostics are written to `/private/tmp/webrtc-direct-repro.json`;
they include network addresses and should be reviewed before sharing.
The process exits nonzero if any round fails to receive media, after writing
diagnostics and closing the browser and local server. `ROUNDS` accepts 1–20,
`TIMEOUT_MS` accepts 1000–120000, and unsupported modes are rejected before startup.

On this macOS host, Chromium 153.0.8010.12 reproduced the application symptom
without application code:

- At 15 seconds, two separate-context video rounds each had all candidate calls
  accepted, four remote candidates per peer, active `sendrecv` transceivers,
  approximately 239 ICE connectivity requests per peer, and zero responses.
  No media arrived.
- Other rounds in the same run established direct connections and received audio
  and video, confirming the failure was intermittent.
- A separate 30-second run passed video, then failed audio. Both audio peers had
  nine accepted candidate calls, connection state `failed`, zero remaining
  remote candidates, and no media. This matches the original application trace.

The zero remote-candidate count after failure therefore does **not** prove that
signaling dropped candidates: earlier samples show those candidates present while
connectivity checks fail. The failure is reproduced in the browser's host ICE
transport path independently of Bun and the application's negotiation code.
These results do not distinguish a Chromium defect from a host network filter or
OS policy, so they do not justify an upstream Bun or Chromium bug report yet.

Use configured TURN for deployable calls; both forced relay and the default `all`
policy with TURN fallback have separate sustained-media verification. Further
host-only diagnosis should compare this same reproduction on a clean second host
or collect OS packet evidence; changing signaling based on the final empty
candidate statistics would target the wrong layer.

`tests/browser/direct-repro-evidence.json` contains sanitized aggregate results from the two
control runs, retaining no candidate addresses or invitation credentials.

## Read-only host checks

The default interface was `en0`; system proxy configuration was empty. Two VPN
network extensions were enabled. Their presence is not evidence that either
caused the failure; no extension settings were changed.

Independent Node UDP probes sent 32 packets in each direction between two local
sockets bound to the same interface address:

| Interface | Address family | Received in each direction |
| --- | --- | --- |
| Loopback | IPv4 | 32 / 32 |
| en0 | IPv4 | 32 / 32 |
| en0, first global address | IPv6 | 32 / 32 |
| en0, second global address | IPv6 | 32 / 32 |
| utun5 | IPv4 | 32 / 32 |
| utun5 | IPv6 | 0 / 0 |

General native UDP connectivity on the LAN works; overlay IPv6 does not pass this
local probe. Since failed Chrome calls also had unanswered checks on other
interfaces, the overlay IPv6 result alone does not explain the full failure.
Browser-specific behavior or per-process filtering remain possible. No network,
proxy, firewall, extension, or privacy settings were changed.

A final run of the completed reproduction failed both video and audio at 30
seconds, wrote its evidence, closed its browser/server, and exited with status 1.
Invalid mode and round-count checks also exit with status 1 before server startup.
