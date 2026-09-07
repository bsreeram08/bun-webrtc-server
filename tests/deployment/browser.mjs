import assert from 'node:assert/strict';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const browser = await chromium.launch({
  executablePath: process.env.BROWSER_EXECUTABLE || undefined,
  headless: true,
  args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required'],
});
try {
  const contexts = await Promise.all([0, 1].map(() => browser.newContext({
    // Disable certificate validation only in these isolated local test contexts.
    ignoreHTTPSErrors: true, permissions: ['camera', 'microphone'],
  })));
  const origin = process.env.TEST_ORIGIN;
  const health = await contexts[0].request.get(`${origin}/health`);
  assert.equal(health.status(), 200);
  const response = await contexts[0].request.post(`${origin}/rooms`, { headers: { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` } });
  assert.equal(response.status(), 201);
  const room = await response.json();
  const pages = await Promise.all(contexts.map(context => context.newPage()));
  const sockets = [];
  await Promise.all(pages.map(async (page, index) => {
    page.on('websocket', socket => sockets.push(new URL(socket.url()).protocol));
    await page.addInitScript(() => {
      const Native = window.RTCPeerConnection;
      window.testPeers = [];
      window.RTCPeerConnection = class extends Native { constructor(...args) { super(...args); window.testPeers.push(this); } };
      const NativeSocket = window.WebSocket;
      window.testSockets = []; window.testSessions = [];
      window.WebSocket = class extends NativeSocket {
        constructor(...args) {
          super(...args); window.testSockets.push(this);
          this.addEventListener('message', event => { const message = JSON.parse(event.data); if (message.type === 'ready') window.testSessions.push(message.sessionId); });
        }
      };
    });
    await page.goto(`${origin}/#roomId=${room.roomId}&token=${room.participants[index].token}`);
    assert.equal(await page.evaluate(() => isSecureContext), true);
    await page.getByRole('button', { name: 'Join call', exact: true }).click();
  }));
  const results = await Promise.all(pages.map(async page => {
    await page.waitForFunction(() => document.getElementById('status').textContent.startsWith('Connected'), null, { timeout: 45000 });
    const read = () => page.evaluate(async () => {
      const stats = await window.testPeers.at(-1).getStats();
      const transport = [...stats.values()].find(s => s.type === 'transport' && s.selectedCandidatePairId);
      const pair = stats.get(transport?.selectedCandidatePairId);
      const local = stats.get(pair?.localCandidateId);
      const incoming = [...stats.values()].filter(s => s.type === 'inbound-rtp').map(({ kind, bytesReceived, framesDecoded }) => ({ kind, bytesReceived, framesDecoded }));
      return { local: local?.candidateType, relayProtocol: local?.relayProtocol, incoming };
    });
    let before;
    for (let i = 0; i < 40; i++) {
      before = await read();
      if (before.incoming.some(s => s.kind === 'audio' && s.bytesReceived > 0) && before.incoming.some(s => s.kind === 'video' && s.framesDecoded > 0)) break;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    await new Promise(resolve => setTimeout(resolve, 1500));
    const after = await read();
    assert.equal(after.local, 'relay');
    assert.equal(after.relayProtocol, process.env.TURN_TRANSPORT);
    for (const kind of ['audio', 'video']) {
      const a = before.incoming.find(s => s.kind === kind), b = after.incoming.find(s => s.kind === kind);
      assert(a && b && b.bytesReceived > a.bytesReceived, `Sustained ${kind} required`);
      if (kind === 'video') assert(b.framesDecoded > a.framesDecoded);
    }
    return after;
  }));
  assert.deepEqual(sockets, ['wss:', 'wss:']);
  async function exchangeChat(label) {
    const message = `${label}-${crypto.randomUUID()}`;
    await pages[0].locator('#chat-input').fill(message);
    await pages[0].locator('#chat-send').click();
    await pages[1].locator('#chat-log .message-text').filter({ hasText: message }).waitFor();
    await pages[0].waitForFunction(text => [...document.querySelectorAll('#chat-log li')].some(row => row.dataset.status === 'delivered' && row.querySelector('.message-text')?.textContent === text), message);
  }
  await exchangeChat('video-chat');
  console.log(JSON.stringify({ stage: 'initial-media', turnTransport: process.env.TURN_TRANSPORT, peers: results }));
  const sustained = async () => {
    const read = page => page.evaluate(async () => ({ peerCount: window.testPeers.length,
      incoming: [...(await window.testPeers.at(-1).getStats()).values()]
        .filter(s => s.type === 'inbound-rtp').map(({ kind, bytesReceived, framesDecoded }) => ({ kind, bytesReceived, framesDecoded })),
    }));
    let before;
    for (let attempt = 0; attempt < 120; attempt++) {
      before = await Promise.all(pages.map(read));
      if (before.every(sample => sample.incoming.some(s => s.kind === 'audio' && s.bytesReceived > 0) && sample.incoming.some(s => s.kind === 'video' && s.framesDecoded > 0))) break;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
    await new Promise(resolve => setTimeout(resolve, 1500));
    const after = await Promise.all(pages.map(read));
    for (let i = 0; i < 2; i++) for (const kind of ['audio', 'video']) {
      assert.equal(after[i].peerCount, before[i].peerCount, 'Peer must remain stable during recovered media sampling');
      const a = before[i].incoming.find(s => s.kind === kind), b = after[i].incoming.find(s => s.kind === kind);
      assert(a && b, `Missing recovery ${kind}: ${JSON.stringify({ before, after, state: await Promise.all(pages.map(page => page.evaluate(() => ({ peers: window.testPeers.map(p => p.connectionState), sessionCount: window.testSessions.length, status: document.getElementById('status').textContent })))) })}`);
      assert(a.bytesReceived > 0, `Recovered ${kind} baseline must contain media`);
      assert(b.bytesReceived > a.bytesReceived, `Recovery must sustain ${kind}`);
      if (kind === 'video') assert(b.framesDecoded > a.framesDecoded);
    }
  };
  const beforeRecovery = await Promise.all(pages.map(page => page.evaluate(() => ({
    session: window.testSessions.at(-1), tracks: document.getElementById('local').srcObject.getTracks().map(t => t.id),
  }))));
  await pages[0].getByRole('button', { name: 'Mute microphone', exact: true }).click();
  await pages[0].evaluate(() => window.testSockets.at(-1).close(4000, 'Test transport interruption'));
  await Promise.all(pages.map((page, index) => page.waitForFunction(previous =>
    window.testSessions.at(-1) !== previous && window.testPeers.at(-1).connectionState === 'connected', beforeRecovery[index].session, { timeout: 45000 })));
  for (let i = 0; i < 2; i++) assert.deepEqual(await pages[i].evaluate(() => document.getElementById('local').srcObject.getTracks().map(t => t.id)), beforeRecovery[i].tracks);
  assert.equal(await pages[0].evaluate(() => document.getElementById('local').srcObject.getAudioTracks()[0].enabled), false);
  await pages[0].getByRole('button', { name: 'Unmute microphone', exact: true }).click();
  await sustained();
  await exchangeChat('recovered-video-chat');
  const restartCount = process.env.TURN_TRANSPORT === 'udp' ? 4 : 1;
  for (let restart = 0; restart < restartCount; restart++) {
    const previousUfrag = await pages[0].evaluate(() => window.testPeers.at(-1).localDescription.sdp.match(/a=ice-ufrag:([^\r\n]+)/)[1]);
    await pages[0].evaluate(() => window.dispatchEvent(new Event('online')));
    try {
      await pages[0].waitForFunction(previous => {
        const peer = window.testPeers.at(-1);
        return peer.localDescription.sdp.match(/a=ice-ufrag:([^\r\n]+)/)[1] !== previous && peer.signalingState === 'stable' && peer.connectionState === 'connected';
      }, previousUfrag, { timeout: 30000 });
      await sustained();
      for (const page of pages) assert((await page.locator('#status').textContent()).startsWith('Connected'), 'Healthy ICE refresh must retain connected UI');
    } catch (error) {
      console.error('ICE restart diagnostic', JSON.stringify({ restart: restart + 1, states: await Promise.all(pages.map(page => page.evaluate(() => ({ status: document.getElementById('status').textContent, peers: window.testPeers.map(p => ({ connection: p.connectionState, ice: p.iceConnectionState, signaling: p.signalingState })) })))) }));
      throw error;
    }
  }
  await pages[0].getByRole('button', { name: 'End call', exact: true }).click();
  await pages[1].waitForFunction(() => document.getElementById('status').textContent.startsWith('Call ended'));
  console.log(JSON.stringify({ https: true, wss: true, turnTransport: process.env.TURN_TRANSPORT, peers: results, websocketRecovery: true, mutePreserved: true, sameCaptureTracks: true, iceRestarts: restartCount, hangup: true }));
} finally { await browser.close(); }
