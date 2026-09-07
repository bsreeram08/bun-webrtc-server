// Browser-only causal control: no Bun, app code, WebSocket, STUN, or TURN.
import { createServer } from 'node:http';
import { writeFile } from 'node:fs/promises';
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright-core');
const rounds = Number(process.env.ROUNDS || 2);
const timeoutMs = Number(process.env.TIMEOUT_MS || 30000);
const modes = process.env.REPRO_MODE ? [process.env.REPRO_MODE] : ['same-page', 'separate-contexts'];
if (!Number.isSafeInteger(rounds) || rounds < 1 || rounds > 20) throw new Error('ROUNDS must be an integer from 1 to 20');
if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) throw new Error('TIMEOUT_MS must be an integer from 1000 to 120000');
if (modes.some(mode => !['same-page', 'separate-contexts'].includes(mode))) throw new Error('REPRO_MODE must be same-page or separate-contexts');
const server = createServer((_, response) => { response.setHeader('Content-Type', 'text/html'); response.end('<!doctype html><title>Direct WebRTC control</title>'); });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ executablePath: process.env.BROWSER_EXECUTABLE || undefined, headless: true, args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream'] });
const results = { browser: await browser.version(), rounds: [] };
try {
  for (const mode of modes) {
    for (let round = 0; round < rounds; round++) {
      const video = round % 2 === 0;
      const contexts = await Promise.all(Array.from({ length: mode === 'same-page' ? 1 : 2 }, () => browser.newContext({ permissions: ['microphone', 'camera'] })));
      const pages = await Promise.all(contexts.map(context => context.newPage()));
      for (const page of pages) await page.goto(origin);
      if (mode === 'same-page') {
        await pages[0].evaluate(async video => {
          window.peers = [new RTCPeerConnection(), new RTCPeerConnection()];
          window.streams = []; window.added = [[], []];
          const queues = [[], []];
          for (let index = 0; index < 2; index++) {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video }); window.streams.push(stream);
            for (const track of stream.getTracks()) peers[index].addTrack(track, stream);
            peers[index].onicecandidate = async event => {
              const candidate = event.candidate?.toJSON() ?? null;
              const other = 1 - index;
              if (!peers[other].remoteDescription) { queues[other].push(candidate); return; }
              try { await peers[other].addIceCandidate(candidate); added[other].push({ candidate, accepted: true }); }
              catch (error) { added[other].push({ error: error.message }); }
            };
          }
          await peers[0].setLocalDescription();
          await peers[1].setRemoteDescription(peers[0].localDescription);
          for (const candidate of queues[1].splice(0)) { await peers[1].addIceCandidate(candidate); added[1].push({ candidate, accepted: true }); }
          await peers[1].setLocalDescription();
          await peers[0].setRemoteDescription(peers[1].localDescription);
          for (const candidate of queues[0].splice(0)) { await peers[0].addIceCandidate(candidate); added[0].push({ candidate, accepted: true }); }
        }, video);
      } else {
        const pending = [[], []]; let ready = [false, false];
        for (let index = 0; index < 2; index++) {
          await pages[index].exposeFunction('deliverCandidate', async candidate => {
            const other = 1 - index;
            if (!ready[other]) { pending[other].push(candidate); return; }
            await pages[other].evaluate(async candidate => { try { await peers[0].addIceCandidate(candidate); added[0].push({ candidate, accepted: true }); } catch (error) { added[0].push({ error: error.message }); } }, candidate);
          });
          await pages[index].evaluate(async video => {
            window.peers = [new RTCPeerConnection()]; window.added = [[]];
            window.streams = [await navigator.mediaDevices.getUserMedia({ audio: true, video })];
            for (const track of streams[0].getTracks()) peers[0].addTrack(track, streams[0]);
            peers[0].onicecandidate = ({ candidate }) => window.deliverCandidate(candidate?.toJSON() ?? null);
          }, video);
        }
        const offer = await pages[0].evaluate(async () => { await peers[0].setLocalDescription(); return peers[0].localDescription.toJSON(); });
        await pages[1].evaluate(description => peers[0].setRemoteDescription(description), offer); ready[1] = true;
        for (const candidate of pending[1].splice(0)) await pages[1].evaluate(async candidate => { await peers[0].addIceCandidate(candidate); added[0].push({ candidate, accepted: true }); }, candidate);
        const answer = await pages[1].evaluate(async () => { await peers[0].setLocalDescription(); return peers[0].localDescription.toJSON(); });
        await pages[0].evaluate(description => peers[0].setRemoteDescription(description), answer); ready[0] = true;
        for (const candidate of pending[0].splice(0)) await pages[0].evaluate(async candidate => { await peers[0].addIceCandidate(candidate); added[0].push({ candidate, accepted: true }); }, candidate);
      }
      let evidence;
      const deadline = Date.now() + timeoutMs;
      do {
        evidence = (await Promise.all(pages.map(page => page.evaluate(async () => Promise.all(peers.map(async (peer, index) => ({ state: peer.connectionState, ice: peer.iceConnectionState, accepted: added[index], transceivers: peer.getTransceivers().map(t => ({ stopped: t.stopped, direction: t.currentDirection })), stats: Array.from((await peer.getStats()).values()).filter(s => ['inbound-rtp', 'local-candidate', 'remote-candidate', 'candidate-pair', 'transport'].includes(s.type)) }))))))).flat();
        if (evidence.every(peer => peer.stats.some(stat => stat.type === 'inbound-rtp' && stat.kind === 'audio' && stat.bytesReceived > 500) && (!video || peer.stats.some(stat => stat.type === 'inbound-rtp' && stat.kind === 'video' && stat.framesDecoded >= 3)))) break;
        await new Promise(resolve => setTimeout(resolve, 250));
      } while (Date.now() < deadline);
      const pass = evidence.every(peer => peer.state === 'connected' && peer.stats.some(stat => stat.type === 'inbound-rtp' && stat.kind === 'audio' && stat.bytesReceived > 500) && (!video || peer.stats.some(stat => stat.type === 'inbound-rtp' && stat.kind === 'video' && stat.framesDecoded >= 3)));
      results.rounds.push({ mode, round, video, pass, evidence });
      console.log(JSON.stringify({ mode, round, video, pass, peers: evidence.map(peer => ({ state: peer.state, accepted: peer.accepted.length, remoteCandidates: peer.stats.filter(stat => stat.type === 'remote-candidate').length, incoming: peer.stats.filter(stat => stat.type === 'inbound-rtp').map(({ kind, bytesReceived, framesDecoded }) => ({ kind, bytesReceived, framesDecoded })) })) }));
      for (const page of pages) await page.evaluate(() => { peers.forEach(peer => peer.close()); streams.forEach(stream => stream.getTracks().forEach(track => track.stop())); });
      await Promise.all(contexts.map(context => context.close()));
    }
  }
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve));
  await writeFile(process.env.REPRO_OUTPUT || '/private/tmp/webrtc-direct-repro.json', JSON.stringify(results, null, 2));
  if (results.rounds.some(round => !round.pass)) process.exitCode = 1;
}
