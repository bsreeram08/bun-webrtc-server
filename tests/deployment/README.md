# Disposable full-stack verification

With Docker running, Node.js, Bun, and Playwright Chromium installed:

```sh
bun --no-env-file tests/deployment/run.ts
```

An existing browser can be selected with `BROWSER_EXECUTABLE`; `PLAYWRIGHT_MODULE` can point at an external `playwright-core` installation. Ports 9443/TCP, 33479/TCP+UDP, and 49400–49439/UDP must be available locally.

The runner builds the current application using a dedicated disposable Buildx builder. It starts Bun, Caddy with a local internal CA, and coturn, then verifies actual HTTPS, WSS, sustained two-peer audio/video, and selected relay candidates in separate UDP-only and TCP-only TURN runs. Caddy shares Bun's network namespace, exercising the production loopback reverse-proxy trust boundary. Certificate validation is bypassed inside disposable browser contexts to accept the local test CA. The chat test also allows the exact local fixture certificate public-key fingerprint in its disposable Chromium process, because service-worker script fetches do not inherit the context exception; the exception is restricted to localhost test origins. This verifies HTTPS/WSS encryption and routing, not certificate identity or public ACME issuance.

Each run also interrupts a WebSocket, verifies a fresh room session and recovered media while retaining capture tracks and mute state, and triggers an ICE restart through the client's online-event handler. The UDP pass repeats four healthy ICE restarts; the TCP pass checks one. Every restart must change ICE credentials and sustain media afterward.

Chat is exercised alongside video and after reconnect. The separate device-chat test runs with media permissions denied, checks acknowledged text delivery and absence of plaintext in HTTP/WebSocket signaling, reloads local history offline, exports an encrypted backup and restores it in a fresh browser context. Wrong passwords must fail, and old backups must not resurrect expired disappearing messages.

This local test has explicitly isolated loopback TURN allowances. It does not relax production configuration or verify public certificate issuance, public DNS, a host firewall, NAT forwarding, or external physical devices.

Cleanup runs in `finally`: task containers and anonymous volumes, the dedicated builder/cache, newly downloaded image tags, and temporary files are removed. Images present before the test are retained. No shared image/cache prune runs. Interrupting with an uncatchable kill or terminating Docker itself may require removing resources beginning with the printed `webrtc-stack-` identifier manually.
