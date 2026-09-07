// Run against a local signaling server: ADMIN_TOKEN=... bun tests/browser/call.mjs
// Install playwright-core and its Chromium browser first. Optional BROWSER_EXECUTABLE
// and PLAYWRIGHT_MODULE support an existing browser installation.
import assert from 'node:assert/strict';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const origin = process.env.TEST_ORIGIN || 'http://localhost:3000';
assert(process.env.ADMIN_TOKEN, 'ADMIN_TOKEN is required');
const launchOptions = {
  headless: true,
  executablePath: process.env.BROWSER_EXECUTABLE || undefined,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required'],
};
let browser;
const errors = [];
try {
  if (process.env.TEST_PERMISSIONS === 'true' || process.env.TEST_MODE === 'permissions') {
    browser = await chromium.launch({ ...launchOptions, args: ['--use-fake-device-for-media-stream'] });
    const response = await fetch(`${origin}/rooms`, { method: 'POST', headers: { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` } });
    assert.equal(response.status, 201);
    const room = await response.json();
    // Granting only camera explicitly leaves microphone denied in this context.
    const context = await browser.newContext({ permissions: ['camera'] });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${origin}/#roomId=${room.roomId}&token=${room.participants[0].token}`);
    await page.getByRole('button', { name: 'Join call', exact: true }).click();
    await page.waitForFunction(() => document.getElementById('status').textContent.includes('permission denied'));
    assert.equal(await page.getByRole('button', { name: 'Join call', exact: true }).isEnabled(), true);
    assert.equal(await page.evaluate(() => document.getElementById('local').srcObject), null);
    assert.equal(await page.getByRole('button', { name: 'End call', exact: true }).isDisabled(), true);
    await context.grantPermissions(['microphone', 'camera']);
    await page.getByRole('button', { name: 'Join call', exact: true }).click();
    await page.waitForFunction(() => {
      const stream = document.getElementById('local').srcObject;
      return stream?.getAudioTracks().some(track => track.readyState === 'live') &&
        stream?.getVideoTracks().some(track => track.readyState === 'live') &&
        document.getElementById('status').textContent.includes('Waiting for the other participant') &&
        !document.getElementById('hangup').disabled;
    });
    await page.evaluate(() => { window.permissionTestTracks = document.getElementById('local').srcObject.getTracks(); });
    await page.getByRole('button', { name: 'End call', exact: true }).click();
    await page.waitForFunction(() => document.getElementById('local').srcObject === null &&
      window.permissionTestTracks.every(track => track.readyState === 'ended'));
    const revoked = await fetch(`${origin}/rooms/${room.roomId}/ice`, { headers: { Authorization: `Bearer ${room.participants[0].token}` } });
    assert.equal(revoked.status, 401, 'Retried and ended invitation is revoked');
    console.log(JSON.stringify({ microphoneDenied: true, permissionGranted: true, retryJoined: true, liveAudioVideo: true, mediaStoppedAfterHangup: true, invitationRevoked: true }));
    await context.close(); await browser.close(); browser = null;
  }
  for (const audioOnly of process.env.TEST_MODE === 'permissions' ? [] : process.env.TEST_MODE === 'audio' ? [true] : process.env.TEST_MODE === 'video' ? [false] : [false, true]) {
    browser ||= await chromium.launch(launchOptions);
    const response = await fetch(`${origin}/rooms`, { method: 'POST', headers: { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` } });
    assert.equal(response.status, 201);
    const room = await response.json();
    const permissions = ['microphone', 'camera'];
    if (process.env.LOCAL_NETWORK_ACCESS === 'true') permissions.push('local-network-access');
    const contexts = await Promise.all([0, 1].map(() => browser.newContext({ permissions })));
    const pages = await Promise.all(contexts.map(context => context.newPage()));
    // Capture native peer statistics without adding debug or secret-exposing hooks to the app.
    await Promise.all(pages.map(async (page, index) => {
      page.on('pageerror', error => errors.push(error.message));
      await page.addInitScript(() => {
        const Native = window.RTCPeerConnection;
        window.testPeers = [];
        window.testIceAdds = [];
        window.RTCPeerConnection = class extends Native {
          constructor(...args) { super(...args); window.testPeers.push(this); }
          async addIceCandidate(candidate) {
            const record = { candidate, state: 'pending' }; window.testIceAdds.push(record);
            try { const result = await super.addIceCandidate(candidate); record.state = 'added'; return result; }
            catch (error) { record.state = error.message; throw error; }
          }
        };
        const NativeSocket = window.WebSocket;
        window.testSignals = [];
        const summarize = raw => { const message = JSON.parse(raw); return { type: message.type, description: message.description?.type, candidate: message.candidate?.candidate, polite: message.polite }; };
        window.WebSocket = class extends NativeSocket {
          constructor(...args) { super(...args); this.addEventListener('message', event => window.testSignals.push({ direction: 'in', ...summarize(event.data) })); }
          send(raw) { window.testSignals.push({ direction: 'out', ...summarize(raw) }); super.send(raw); }
        };
      });
      await page.goto(`${origin}/#roomId=${room.roomId}&token=${room.participants[index].token}`);
      assert.equal(new URL(page.url()).hash, '', 'Invitation removed from address/history');
      if (audioOnly) await page.getByLabel('Audio only').check();
      await page.getByRole('button', { name: 'Join call', exact: true }).click();
    }));
    await Promise.all(pages.map(page => page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Connected'), null, { timeout: 30000 }).catch(async error => {
      console.error('Connection diagnostic', JSON.stringify(await page.evaluate(async () => ({ status: document.getElementById('status').textContent, signals: window.testSignals, iceAdds: window.testIceAdds, peers: await Promise.all(window.testPeers.map(async peer => ({ state: peer.connectionState, signaling: peer.signalingState, ice: peer.iceConnectionState, local: peer.localDescription?.sdp.split('\r\n').filter(line => /fingerprint|ice-ufrag/.test(line)), remote: peer.remoteDescription?.sdp.split('\r\n').filter(line => /fingerprint|ice-ufrag/.test(line)), stats: Array.from((await peer.getStats()).values()).filter(stat => ['candidate-pair', 'local-candidate', 'remote-candidate', 'transport'].includes(stat.type)) }))) }))));
      throw error;
    })));
    const media = await Promise.all(pages.map(async page => {
      const deadline = Date.now() + 30000;
      let incoming = [];
      while (Date.now() < deadline) {
        incoming = await page.evaluate(async () => Array.from((await window.testPeers.at(-1).getStats()).values())
          .filter(stat => stat.type === 'inbound-rtp' && stat.bytesReceived > 0)
          .map(({ kind, bytesReceived, framesDecoded }) => ({ kind, bytesReceived, framesDecoded })));
        if (incoming.some(stat => stat.kind === 'audio') && (audioOnly || incoming.some(stat => stat.kind === 'video' && stat.framesDecoded > 0))) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          const later = await page.evaluate(async () => Array.from((await window.testPeers.at(-1).getStats()).values())
            .filter(stat => stat.type === 'inbound-rtp')
            .map(({ kind, bytesReceived, framesDecoded }) => ({ kind, bytesReceived, framesDecoded })));
          if (incoming.every(first => later.some(last => last.kind === first.kind && last.bytesReceived > first.bytesReceived && (first.kind !== 'video' || last.framesDecoded > first.framesDecoded)))) return { before: incoming, after: later };
        }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      assert.fail(`Missing received ${audioOnly ? 'audio' : 'audio/video'} media: ${JSON.stringify(incoming)}`);
    }));
    const routes = await Promise.all(pages.map(page => page.evaluate(async () => {
      const stats = await window.testPeers.at(-1).getStats();
      const transport = Array.from(stats.values()).find(stat => stat.type === 'transport' && stat.selectedCandidatePairId);
      const pair = stats.get(transport?.selectedCandidatePairId);
      return { local: stats.get(pair?.localCandidateId)?.candidateType, remote: stats.get(pair?.remoteCandidateId)?.candidateType, protocol: stats.get(pair?.localCandidateId)?.protocol };
    })));
    if (process.env.EXPECT_RELAY === 'true') for (const route of routes) assert.equal(route.local, 'relay', 'Selected local candidate must use TURN');
    await pages[0].getByRole('button', { name: 'Mute microphone', exact: true }).click();
    assert.equal(await pages[0].evaluate(() => document.getElementById('local').srcObject.getAudioTracks()[0].enabled), false);
    if (!audioOnly) {
      await pages[0].getByRole('button', { name: 'Turn camera off', exact: true }).click();
      assert.equal(await pages[0].evaluate(() => document.getElementById('local').srcObject.getVideoTracks()[0].enabled), false);
    }
    await pages[0].getByRole('button', { name: 'End call', exact: true }).click();
    await pages[1].waitForFunction(() => document.getElementById('status').textContent.startsWith('Call ended'));
    for (const page of pages) {
      assert.equal(await page.evaluate(() => document.getElementById('local').srcObject), null);
      assert.equal(await page.evaluate(() => window.testPeers.every(peer => peer.connectionState === 'closed')), true);
    }
    const expired = await fetch(`${origin}/rooms/${room.roomId}/ice`, { headers: { Authorization: `Bearer ${room.participants[0].token}` } });
    assert.equal(expired.status, 401, 'Ended room invitation is revoked');
    console.log(JSON.stringify({ mode: audioOnly ? 'audio' : 'video', received: media, routes, mute: true, hangup: true }));
    await Promise.all(contexts.map(context => context.close()));
    if (process.env.REUSE_BROWSER !== 'true') { await browser.close(); browser = null; }
  }
  assert.deepEqual(errors, []);
} finally { await browser?.close(); }
