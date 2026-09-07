# Verification status

Snapshot: 2026-09-07. The target is independently deployable calling and device-to-device chat with no backend chat storage. The current implementation uses two-person invitations, device-local history and encrypted portable backups. It is not yet verified as ready for public production use.

## Evidence collected

| Area | Verified scope |
| --- | --- |
| Automated runtime checks | 83 tests with 23,371 assertions passed across `tests/unit/`: real Bun HTTP/WebSockets, IPv4/IPv6 UDP, malformed STUN datagrams, room isolation, reconnects, expiry, limits, configuration and setup. The actual browser script is also tested against controlled permission, network and timing events. TypeScript validation and a frozen-lockfile installation passed. |
| Burst delivery | 40 rooms exchanged 2,560 signaling messages with exact ordering and contents, including large SDP followed by simultaneous ICE bursts. No Bun delivery loss was reproduced. |
| ICE credential API | Tests verify room-bound authorization, HMAC credentials, expiry, absence of shared secrets in responses and relay-only configuration. |
| Browser response policy | Tests verify CSP, permissions policy, referrer protection, content-type protection and static path restrictions. |
| Deployment artifact | The Bun Docker image built and its running HTTP health endpoint responded successfully. |
| Reverse proxy | Caddy accepted the deployment configuration. Public DNS and certificate issuance are separate checks. |
| TURN relay | Fixed explicit relay binding after reproducing ChannelBind 403 with a wildcard relay address. Independent coturn client received 20/20 relayed messages; invalid/expired credentials failed. The production-generated configuration starts with the chosen local relay address. An isolated same-server NAT relay test also received 20/20 messages with private-subnet denial active; a request to a private management destination failed with ChannelBind 403. |
| Browser forced-relay media | Chromium completed consecutive video and audio-only calls in the same browser through the isolated local coturn test instance. Both peers selected relay candidates. In video mode, inbound audio increased from 451 to 2,925 bytes and video from about 17 KiB to 69 KiB, with decoded frames increasing from 4 to 24; the next audio-only call increased from 451 to 2,903 bytes on both peers. Mute, camera disable, hangup, capture cleanup and invitation revocation passed. Synthetic media was used. |
| Default policy with TURN | Consecutive video and audio-only calls also passed with the deployment's default `iceTransportPolicy: all`. Selected pairs used TURN fallback (relay/peer-reflexive). Audio increased from 606 to 3,121 bytes in video mode, video increased from about 20 KiB to 74 KiB and frames from 4 to 24; the next audio-only call increased from 482 to 2,937 bytes on both peers. |
| Permission handling | The browser suite denied microphone permission, verified capture had not started, then granted permission and retried successfully. |
| Reconnect isolation | A real-socket regression reproduced stale ICE reaching a rejoined participant. Server-issued pairing sessions now prevent that. Participant-authenticated HTTP deletion ends the room even when its WebSocket is disconnected. |
| Browser lifetime controls | Tests exercise online events during pending permission, cancellation followed by late media acquisition, stuck WebSocket handshakes, bounded retries, capture cleanup and accurate offline-hangup status. |
| Device-only chat and migration | Chromium passed chat-only sessions with no media requests, acknowledged bidirectional text, sender-device queuing while the peer was offline, ACK backpressure recovery, inert HTML rendering, and chat alongside video/reconnect. Distinct message markers were absent from captured HTTP and signaling frames. Real browser IndexedDB history survived reload and a genuinely offline reload. Encrypted exports restored in fresh browser contexts; wrong passwords failed, original expiry was preserved, and expired messages did not return from old backups. The full suite passed through TURN over both UDP and TCP. |
| Full deployment call path | The repeatable Docker harness passed Caddy HTTPS/WSS and sustained bidirectional audio/video through coturn over UDP and TCP. Signaling reconnection preserved capture tracks and mute state. Four consecutive healthy ICE restarts passed on UDP, and another passed on TCP. These use synthetic media and disposable browser contexts that bypass certificate validation for the local test certificate; public ACME issuance is not covered. All test containers, newly pulled images and the dedicated builder/cache were removed and cleanup verified. |

The deployment and container checks above were performed during the current implementation session. Re-run them after changing images, configuration or networking. A health response proves that HTTP is serving, not that a call succeeds.

## Remaining completion checks

- Direct host-candidate failures were independently reproduced with native browser peers exchanging signaling in memory, with no Bun or application code. This identifies the local host ICE path as the failing boundary but does not establish a browser defect or a specific network-filter cause. Configured TURN works around that path. See [the diagnosis and reproduction](browser-network-diagnosis.md).
- Browser reconnection across real network changes, Safari/Firefox/mobile behavior and multiple physical devices remain separate validation tasks.
- Deploy with real DNS, HTTPS certificates and firewall settings on a Linux host, then test two physical devices on different networks.
- Verify physical microphones/cameras, missing-camera and unsupported-browser behavior. Synthetic audio-only and permission-denial/retry checks have passed.
- Chat migration is encrypted file export/import, with manual Google Drive storage. Installation and file selection on physical Android/iOS devices remain unverified. Automatic Drive upload and native background notifications are not implemented. See [device chat and migration](device-chat.md).
- Persistent user identities, multi-device contact continuity, group calls and Signal-style identity verification are not implemented. Queued device messages need both apps connected within the invitation lifetime; this is not a background or server-mailbox delivery service.

## Reproduce automated checks

```sh
bun --no-env-file run typecheck
bun --no-env-file test tests/unit
bun --no-env-file tests/deployment/run.ts
```

Socket tests require permission to bind loopback ports. The deployment harness requires Docker and Chromium; see [its instructions](../tests/deployment/README.md). See [deployment instructions](deployment.md) for container startup and external call checks, and [security model](security.md) for the boundaries of the implementation.
