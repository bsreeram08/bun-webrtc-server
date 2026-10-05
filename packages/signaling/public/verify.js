'use strict';
(() => {
  // Short authentication string: both people read the code aloud. A relay that terminates
  // DTLS on each side (for example a compromised signaling server rewriting SDP) sees
  // different fingerprints per leg, and commit-then-reveal stops it from choosing nonces
  // after seeing ours, so its two codes match only by chance (1 in 1,000,000).
  const LABEL = 'webrtc-bun-sas-v1', HEX = /^[0-9a-f]{64}$/, encoder = new TextEncoder();
  const hex = buffer => [...new Uint8Array(buffer)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const sha256 = async text => crypto.subtle.digest('SHA-256', encoder.encode(text));
  function fingerprints(sdp) {
    const values = new Set();
    for (const line of (sdp || '').split(/\r?\n/)) {
      const match = /^a=fingerprint:(\S+) ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+)$/.exec(line.trim());
      if (match) values.add(`${match[1].toLowerCase()} ${match[2].toUpperCase()}`);
    }
    return [...values].sort().join(',');
  }
  async function sasCode(prints, nonces) {
    if (prints.length !== 2 || nonces.length !== 2 || prints.some(value => !value) || nonces.some(value => !HEX.test(value))) throw new Error('Invalid verification input');
    const digest = await sha256([LABEL, ...[...prints].sort(), ...[...nonces].sort()].join('\n'));
    const code = String(new DataView(digest).getUint32(0) % 1000000).padStart(6, '0');
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  /** Runs the exchange on a dedicated negotiated channel; reports { code } or { error } once. */
  function attach(peer, channel, report) {
    const nonce = hex(crypto.getRandomValues(new Uint8Array(32))), commitment = sha256(nonce).then(hex);
    let queue = Promise.resolve(), committed = false, revealed = false, peerCommit = null, peerNonce = null, done = false;
    const finish = result => { if (!done) { done = true; report(result); } };
    const fail = () => { if (!done) { channel.close(); finish({ error: 'Verification failed — end the call. Someone may be in the middle.' }); } };
    const send = value => { if (channel.readyState === 'open') channel.send(JSON.stringify(value)); };
    // Reveal only after both commitments exist, so neither side can pick a nonce after seeing the other's.
    const reveal = () => { if (committed && peerCommit && !revealed) { revealed = true; send({ type: 'reveal', nonce }); } };
    const step = task => { queue = queue.then(() => done ? undefined : task()).catch(fail); };
    channel.onopen = () => step(async () => { send({ type: 'commit', hash: await commitment }); committed = true; reveal(); });
    channel.onmessage = event => step(async () => {
      if (typeof event.data !== 'string' || event.data.length > 256) throw new Error('Invalid verification packet');
      const packet = JSON.parse(event.data);
      if (!packet || typeof packet !== 'object' || Object.keys(packet).length !== 2) throw new Error('Invalid verification packet');
      if (packet.type === 'commit' && !peerCommit && HEX.test(packet.hash)) { peerCommit = packet.hash; reveal(); return; }
      if (packet.type !== 'reveal' || !revealed || peerNonce || !HEX.test(packet.nonce)) throw new Error('Invalid verification packet');
      if (hex(await sha256(packet.nonce)) !== peerCommit) throw new Error('Commitment mismatch');
      peerNonce = packet.nonce;
      const prints = [fingerprints(peer.localDescription?.sdp), fingerprints(peer.remoteDescription?.sdp)];
      finish({ code: await sasCode(prints, [nonce, peerNonce]) });
    });
    if (channel.readyState === 'open') channel.onopen();
  }
  window.Verify = Object.freeze({ sasCode, fingerprints, attach });
})();
