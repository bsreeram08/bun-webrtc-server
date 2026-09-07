'use strict';
const $ = id => document.getElementById(id);
const status = message => { $('status').textContent = message; };
const invite = new URLSearchParams(location.hash.slice(1));
const roomId = invite.get('roomId'), token = invite.get('token');
history.replaceState(null, '', location.pathname);
const validInvite = /^[A-Za-z0-9_-]{43}$/.test(roomId || '') && /^[A-Za-z0-9_-]{43}$/.test(token || '');
let socket, stream, pc, config, sessionId, polite = false, ready = false, makingOffer = false;
let ignoreOffer = false, settingAnswer = false, candidates = [], generation = 0, lifecycle = 0;
let active = false, joining = false, connecting = false, reconnectTimer, restartTimer, handshakeTimer, reconnectSince = 0, reconnectAttempt = 0, iceRestarts = 0;
let messages = Promise.resolve();

function send(message) {
  if (socket?.readyState !== WebSocket.OPEN) return false;
  if (message.type === 'description' || message.type === 'candidate') {
    if (!sessionId) return false;
    message = { ...message, sessionId };
  }
  socket.send(JSON.stringify(message));
  return true;
}
function closePeer() {
  generation++;
  clearTimeout(restartTimer); restartTimer = undefined;
  if (pc) { pc.onconnectionstatechange = null; pc.close(); }
  pc = null; sessionId = null; ready = false; candidates = [];
  makingOffer = false; ignoreOffer = false; settingAnswer = false; iceRestarts = 0;
  $('remote').srcObject = null;
}
function cleanup(message) {
  active = false; lifecycle++;
  clearTimeout(reconnectTimer); reconnectTimer = undefined;
  clearTimeout(handshakeTimer); handshakeTimer = undefined;
  closePeer();
  stream?.getTracks().forEach(track => track.stop()); stream = null;
  $('local').srcObject = null;
  const previous = socket; socket = null; previous?.close();
  for (const id of ['mute', 'camera', 'hangup']) $(id).disabled = true;
  $('play').hidden = true; joining = false; connecting = false; reconnectSince = 0; reconnectAttempt = 0;
  status(message);
}
function matchesGeneration(peer, candidate) {
  return !candidate?.usernameFragment || peer.remoteDescription?.sdp.split('\r\n')
    .some(line => line === 'a=ice-ufrag:' + candidate.usernameFragment);
}
function recoverIce(peer, immediate = false) {
  if (pc !== peer || !active || !ready || socket?.readyState !== WebSocket.OPEN || restartTimer) return;
  const current = generation;
  restartTimer = setTimeout(() => {
    restartTimer = undefined;
    if (current !== generation || !active || socket?.readyState !== WebSocket.OPEN) return;
    const broken = ['failed', 'disconnected'].includes(peer.connectionState);
    if (!immediate && !broken) return;
    if (broken && iceRestarts >= 3) { cleanup('The connection could not recover. Reopen your invitation to try again.'); return; }
    // A healthy connection can renegotiate without emitting another connected
    // event. Do not charge these refreshes against the failed-recovery budget.
    iceRestarts = broken ? iceRestarts + 1 : 0;
    if (broken) status('Connection interrupted. Reconnecting your call…');
    peer.restartIce();
  }, immediate ? 0 : polite ? 6000 : 3000);
}
function createPeer() {
  const peer = new RTCPeerConnection(config); pc = peer;
  for (const track of stream.getTracks()) peer.addTrack(track, stream);
  peer.onicecandidate = ({ candidate }) => { if (pc === peer) send({ type: 'candidate', candidate }); };
  peer.ontrack = ({ track, streams }) => {
    if (pc !== peer) return;
    const remote = streams[0] || $('remote').srcObject || new MediaStream();
    if (!remote.getTracks().includes(track)) remote.addTrack(track);
    $('remote').srcObject = remote;
    $('remote').play().catch(() => { if (pc === peer) $('play').hidden = false; });
  };
  peer.onconnectionstatechange = () => {
    if (pc !== peer) return;
    if (peer.connectionState === 'connected') {
      clearTimeout(restartTimer); restartTimer = undefined; iceRestarts = 0;
      status('Connected — your call is live.');
    } else if (['disconnected', 'failed'].includes(peer.connectionState)) {
      status('Connection interrupted. Reconnecting your call…');
      recoverIce(peer);
    }
  };
  peer.onnegotiationneeded = async () => {
    if (!ready || pc !== peer || socket?.readyState !== WebSocket.OPEN) return;
    if (polite && !peer.remoteDescription) return;
    try {
      makingOffer = true;
      await peer.setLocalDescription();
      if (pc === peer) send({ type: 'description', description: peer.localDescription });
    } catch { if (pc === peer) cleanup('Could not negotiate this call. Reopen your invitation to try again.'); }
    finally { if (pc === peer) makingOffer = false; }
  };
  return peer;
}
async function receive(message) {
  if (message.type === 'welcome') { polite = message.polite; reconnectSince = 0; reconnectAttempt = 0; return; }
  if (message.type === 'ready') {
    closePeer(); sessionId = message.sessionId; ready = true; createPeer();
    status('Connecting to the other participant…'); return;
  }
  if (message.type === 'peer-left') { closePeer(); status('The other participant disconnected. Waiting for them to return…'); return; }
  if (message.type === 'error') {
    // These refer to a retired pairing; its messages must not affect the new one.
    if (message.error !== 'Stale session') status('Waiting for the other participant to reconnect…');
    return;
  }
  const peer = pc, current = generation;
  if (!peer || !ready || message.sessionId !== sessionId) return;
  if (message.type === 'description') {
    const description = message.description;
    const offerCollision = description.type === 'offer' && (makingOffer || !(peer.signalingState === 'stable' || settingAnswer));
    ignoreOffer = !polite && offerCollision;
    if (ignoreOffer) { candidates = []; return; }
    settingAnswer = description.type === 'answer';
    try { await peer.setRemoteDescription(description); }
    finally { if (current === generation) settingAnswer = false; }
    if (current !== generation) return;
    for (const candidate of candidates.splice(0)) {
      if (matchesGeneration(peer, candidate)) await peer.addIceCandidate(candidate);
      if (current !== generation) return;
    }
    if (description.type === 'offer') {
      await peer.setLocalDescription();
      if (current === generation) send({ type: 'description', description: peer.localDescription });
    }
  } else if (message.type === 'candidate' && !ignoreOffer) {
    if (!peer.remoteDescription || !matchesGeneration(peer, message.candidate)) {
      // A new ICE generation can arrive before its SDP; keep a bounded queue.
      if (candidates.length >= 128) throw new Error('Too many pending candidates');
      candidates.push(message.candidate);
    } else await peer.addIceCandidate(message.candidate);
  }
}
function scheduleReconnect() {
  if (!active || reconnectTimer) return;
  reconnectSince ||= Date.now();
  if (Date.now() - reconnectSince >= 90000) {
    cleanup('Unable to reconnect. Reopen your invitation when your connection returns.'); return;
  }
  status('Call connection lost. Reconnecting… Your camera and microphone remain on locally.');
  const current = lifecycle;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = undefined;
    if (active && current === lifecycle) connectSocket(current);
  }, Math.min(500 * 2 ** Math.min(reconnectAttempt++, 4), 8000));
}
async function loadIce(current) {
  const response = await fetch(`/rooms/${roomId}/ice`, {
    headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  if (!active || current !== lifecycle) return false;
  if (response.status === 401) { cleanup('Call ended or invitation expired. Request a new invitation to call again.'); return false; }
  if (!response.ok) throw new Error('Call server unavailable');
  const next = await response.json();
  if (!active || current !== lifecycle) return false;
  config = next;
  return true;
}
async function connectSocket(current) {
  if (!active || !stream || current !== lifecycle || connecting || socket && socket.readyState < WebSocket.CLOSING) return;
  connecting = true;
  try {
    if (!await loadIce(current)) return;
    const connection = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/rooms/${roomId}/socket`, ['webrtc', token]);
    socket = connection;
    handshakeTimer = setTimeout(() => {
      if (!active || socket !== connection || connection.readyState !== WebSocket.CONNECTING) return;
      handshakeTimer = undefined; socket = null;
      connection.close(); scheduleReconnect();
    }, 10000);
    connection.onopen = () => {
      if (socket !== connection) return;
      clearTimeout(handshakeTimer); handshakeTimer = undefined;
      status('Waiting for the other participant…');
    };
    connection.onmessage = event => {
      messages = messages.then(() => { if (active && socket === connection) return receive(JSON.parse(event.data)); }).catch(() => {
        if (active && socket === connection) cleanup('Call negotiation failed. Reopen your invitation to try again.');
      });
    };
    connection.onclose = event => {
      if (!active || socket !== connection) return;
      clearTimeout(handshakeTimer); handshakeTimer = undefined;
      socket = null; closePeer();
      if (event.code === 1000 || event.code === 1008) cleanup('Call ended or invitation expired. Request a new invitation to call again.');
      else scheduleReconnect();
    };
    // The close event carries the reconnect decision; errors must not race it.
    connection.onerror = () => {};
  } catch {
    if (active && current === lifecycle) scheduleReconnect();
  } finally { if (current === lifecycle) connecting = false; }
}
$('join-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (joining || !validInvite) return;
  joining = true; active = true; const current = ++lifecycle;
  $('join').disabled = true; $('audio-only').disabled = true; $('hangup').disabled = false;
  status('Preparing your microphone and call connection…');
  try {
    if (!await loadIce(current)) return;
    const acquired = await navigator.mediaDevices.getUserMedia({ audio: true, video: !$('audio-only').checked });
    if (!active || current !== lifecycle) { acquired.getTracks().forEach(track => track.stop()); return; }
    stream = acquired; $('local').srcObject = stream;
    $('mute').disabled = false; $('camera').disabled = stream.getVideoTracks().length === 0;
    $('mute').setAttribute('aria-pressed', 'false'); $('mute').textContent = 'Mute microphone';
    $('camera').setAttribute('aria-pressed', 'false'); $('camera').textContent = 'Turn camera off';
    await connectSocket(current);
  } catch (error) {
    if (current !== lifecycle) return;
    cleanup(error.name === 'NotAllowedError' ? 'Microphone or camera permission denied. Allow access, then try again.' : error.name === 'NotFoundError' ? 'No microphone or camera found. Connect a device or try audio only.' : 'Unable to join. Check your invitation, connection, and media permissions.');
    $('join').disabled = false; $('audio-only').disabled = false;
  }
});
$('mute').onclick = () => {
  const muted = $('mute').getAttribute('aria-pressed') !== 'true';
  stream?.getAudioTracks().forEach(track => { track.enabled = !muted; });
  $('mute').setAttribute('aria-pressed', String(muted)); $('mute').textContent = muted ? 'Unmute microphone' : 'Mute microphone';
};
$('camera').onclick = () => {
  const off = $('camera').getAttribute('aria-pressed') !== 'true';
  stream?.getVideoTracks().forEach(track => { track.enabled = !off; });
  $('camera').setAttribute('aria-pressed', String(off)); $('camera').textContent = off ? 'Turn camera on' : 'Turn camera off';
};
$('play').onclick = () => $('remote').play().then(() => { $('play').hidden = true; }).catch(() => status('Use your browser’s audio controls to allow playback.'));
$('hangup').onclick = async () => {
  // Stop capture immediately, including when signaling or a permission prompt is pending.
  cleanup('Call stopped. Ending the room…');
  try {
    const response = await fetch(`/rooms/${roomId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
    status(response.ok || response.status === 401 ? 'Call ended.' : 'Call stopped locally. Could not confirm the room ended.');
  } catch { status('Call stopped locally. Could not end the room while offline.'); }
};
window.addEventListener('online', () => {
  if (!active || !stream) return;
  if (socket?.readyState !== WebSocket.OPEN) {
    clearTimeout(reconnectTimer); reconnectTimer = undefined; scheduleReconnect();
  } else if (pc) recoverIce(pc, true);
});
window.addEventListener('pagehide', () => cleanup('Call closed.'));
if (!window.isSecureContext || !navigator.mediaDevices || !window.RTCPeerConnection) status('Calls require a supported browser over HTTPS (or localhost for development).');
else if (!validInvite) status('Open your personal invitation link to join a call. Ask your server administrator for an invitation.');
else { status('Invitation ready. Choose audio only or join with your camera.'); $('join').disabled = false; }
