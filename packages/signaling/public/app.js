'use strict';
const $ = id => document.getElementById(id);
const status = message => { $('status').textContent = message; $('status').classList?.remove('idle'); };
let roomId = null, token = null, validInvite = false;
let socket, stream, pc, config, sessionId, polite = false, ready = false, makingOffer = false;
let ignoreOffer = false, settingAnswer = false, candidates = [], generation = 0, lifecycle = 0;
let active = false, joining = false, connecting = false, sessionPrepared = false, reconnectTimer, restartTimer, handshakeTimer, reconnectSince = 0, reconnectAttempt = 0, iceRestarts = 0;
let messages = Promise.resolve(), verifyTimer, verified = false;
let dataChannel = null, flushTimer, requestChatFlush = null, chatBusy = false, historyRevision = 0, selectedHistory = '', transcriptSignature = '';
let burnAck = null, peerBurned = false;
// Account conversations keep one stable ChatStore id per contact pair across rooms; guest links use the room id.
let conversationId = null, peerName = 'the other participant', accountChat = false;
const encoder = new TextEncoder();
const messageIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const chatStatus = text => { $('chat-status').textContent = text; };
// Body data attributes drive layout: lobby, call or chat, plus the open sheet/panel.
const view = (key, value) => { $('app').dataset[key] = value; };
const setJoinable = on => {
  for (const id of ['join', 'join-audio', 'join-chat']) $(id).disabled = !on;
  $('audio-only').disabled = !on || $('chat-only').checked; $('chat-only').disabled = !on;
};
const clock = time => new Date(time).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

function parseInvitation(value) {
  const url = new URL(value);
  if (url.origin !== location.origin || url.pathname !== '/' || url.search || url.username || url.password) throw new Error('Use a personal invitation from this server.');
  const parts = new URLSearchParams(url.hash.slice(1));
  if (parts.getAll('roomId').length !== 1 || parts.getAll('token').length !== 1 || [...parts.keys()].some(key => !['roomId', 'token'].includes(key))) throw new Error('This invitation is incomplete.');
  const id = parts.get('roomId'), credential = parts.get('token');
  if (!/^[A-Za-z0-9_-]{43}$/.test(id || '') || !/^[A-Za-z0-9_-]{43}$/.test(credential || '')) throw new Error('This invitation is incomplete.');
  return { id, credential };
}
function openInvitation(value) {
  if (active || joining || chatBusy) throw new Error('Finish this conversation or message before opening another invitation.');
  const next = parseInvitation(value);
  lifecycle++; roomId = next.id; token = next.credential; validInvite = true; conversationId = selectedHistory = roomId; peerBurned = false; accountChat = false; peerName = 'the other participant';
  $('invitation-input').value = ''; $('invitation-panel').open = false;
  setJoinable(true);
  status('Invitation ready. Choose how to join.');
  refreshHistory();
}
function updateComposer() {
  const canCompose = (validInvite || accountChat) && selectedHistory === conversationId && Boolean(window.ChatStore);
  $('chat-input').disabled = !canCompose || chatBusy;
  $('chat-send').disabled = !canCompose || chatBusy;
  $('burn').disabled = $('conv-burn').disabled = !(validInvite || accountChat) || chatBusy;
}
async function refreshHistory() {
  const revision = ++historyRevision;
  try {
    if (!window.ChatStore) throw new Error('Local message storage is unavailable.');
    const records = await window.ChatStore.list();
    if (revision !== historyRevision) return;
    const ids = [...new Set(records.map(record => record.conversationId))].reverse(), lastAt = new Map();
    for (const record of records) lastAt.set(record.conversationId, Math.max(lastAt.get(record.conversationId) || 0, record.createdAt));
    if (conversationId && !ids.includes(conversationId)) ids.unshift(conversationId);
    if (!selectedHistory || !ids.includes(selectedHistory)) selectedHistory = conversationId || ids[0] || '';
    const selector = $('history-select'); selector.replaceChildren();
    if (!ids.length) selector.add(new Option('No conversations yet', ''));
    for (const id of ids) selector.add(new Option(id === conversationId ? 'This conversation' : `Earlier conversation — ${new Date(lastAt.get(id)).toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${clock(lastAt.get(id))}`, id));
    view('history', ids.length ? 'yes' : 'no');
    selector.value = selectedHistory;
    const log = $('chat-log'), wasNearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    const visible = records.filter(record => record.conversationId === selectedHistory).slice(-2000);
    const signature = JSON.stringify(visible);
    if (transcriptSignature !== signature) {
      transcriptSignature = signature; log.replaceChildren();
      for (const record of visible) {
        const row = document.createElement('li'); row.className = record.direction;
        row.dataset.messageId = record.id; row.dataset.status = record.status;
        const text = document.createElement('p'); text.className = 'message-text'; text.textContent = record.text;
        const meta = document.createElement('small'); meta.className = 'message-meta';
        const delivery = { queued: 'Queued on this device', sent: 'Sent · delivery unconfirmed', delivered: 'Delivered to device', uncertain: 'Restored · delivery unconfirmed' }[record.status];
        const detail = `${record.direction === 'outgoing' ? 'You' : peerName === 'the other participant' ? 'Other participant' : peerName} · ${new Date(record.createdAt).toLocaleString()} · ${delivery}${record.expiresAt ? ' · Disappears ' + new Date(record.expiresAt).toLocaleString() : ''}`;
        const mark = record.direction === 'outgoing' ? { queued: ' 🕓', sent: ' ✓', delivered: ' ✓✓', uncertain: ' ?' }[record.status] : '';
        // Messages that arrived under a changed security code stay marked until the code is reviewed.
        const flagged = Boolean(window.App?.flagged?.(record));
        meta.textContent = `${flagged ? '⚠ ' : ''}${record.expiresAt ? '⏱ ' : ''}${clock(record.createdAt)}${mark}`;
        if (flagged) row.classList.add('flagged');
        const label = flagged ? `${detail} · Sent under a new security code` : detail;
        meta.setAttribute('aria-label', label); row.title = label;
        row.append(text, meta); log.append(row);
      }
      if (wasNearBottom) log.scrollTop = log.scrollHeight;
    }
    updateComposer();
  } catch (error) { chatStatus(error.message || 'Could not read local history.'); $('chat-input').disabled = true; $('chat-send').disabled = true; }
}
function detachChat() {
  clearTimeout(flushTimer); flushTimer = undefined;
  requestChatFlush = null;
  const previous = dataChannel; dataChannel = null;
  if (previous) { previous.onclose = null; previous.close(); }
  chatStatus(accountChat ? '' : 'Messages stay on this device. Queued messages need both participants connected with a valid invitation.');
}
function attachChat(peer, channel) {
  if (pc !== peer || !active || channel.label !== 'chat-v1' || !channel.ordered || channel.maxRetransmits !== null || channel.maxPacketLifeTime !== null || dataChannel) { channel.close(); return; }
  dataChannel = channel;
  const current = generation, conversation = conversationId, sent = new Set(), pendingAcks = new Set();
  let queue = Promise.resolve(), queued = 0, windowStart = Date.now(), count = 0, flushing = false, pendingWake = false;
  const isCurrent = () => active && pc === peer && dataChannel === channel && generation === current;
  const fail = text => { if (isCurrent()) { channel.close(); chatStatus(text); } };
  const transmit = packet => {
    if (!isCurrent() || channel.readyState !== 'open' || channel.bufferedAmount > 65536) return false;
    channel.send(JSON.stringify(packet)); return true;
  };
  function scheduleFlush(delay = 0) {
    if (!isCurrent() || channel.readyState !== 'open') return;
    pendingWake = true;
    if (!flushing && !flushTimer) flushTimer = setTimeout(flush, delay);
  }
  requestChatFlush = scheduleFlush;
  async function flush() {
    flushTimer = undefined;
    if (!isCurrent() || channel.readyState !== 'open') return;
    flushing = true; pendingWake = false;
    let more = false;
    try {
      // A stored incoming message must not lose its acknowledgment merely because
      // the channel is temporarily full. Drain bounded priority batches first.
      more = pendingAcks.size > 0;
      for (const id of [...pendingAcks].slice(0, 16)) {
        if (!transmit({ v: 1, type: 'ack', id })) return;
        pendingAcks.delete(id);
      }
      more = pendingAcks.size > 0;
      if (more) return;
      const records = await window.ChatStore.list();
      if (!isCurrent()) return;
      if (pendingAcks.size) { more = true; return; }
      const pending = records.filter(record => record.conversationId === conversation && record.direction === 'outgoing' && ['queued', 'sent'].includes(record.status) && !sent.has(record.id));
      const next = pending[0];
      more = Boolean(next); // Keep bounded retries while channel backpressure prevents sending.
      if (next && transmit({ v: 1, type: 'message', id: next.id, text: next.text, createdAt: next.createdAt, expiresAt: next.expiresAt })) {
        sent.add(next.id);
        more = pending.length > 1;
        await window.ChatStore.setStatus(conversation, next.id, 'sent');
        refreshHistory();
      }
    } catch (error) { if (isCurrent()) chatStatus(error.message || 'Could not send a saved message.'); }
    finally {
      flushing = false;
      // An enqueue during either storage await must not lose its wake-up.
      if (isCurrent() && (more || pendingWake)) scheduleFlush(100);
    }
  }
  channel.bufferedAmountLowThreshold = 32768;
  channel.onbufferedamountlow = () => { if (isCurrent()) scheduleFlush(); };
  channel.onopen = () => { if (isCurrent()) { chatStatus('Encrypted device-to-device chat connected.'); scheduleFlush(); } };
  channel.onclose = () => { if (isCurrent()) { dataChannel = null; requestChatFlush = null; clearTimeout(flushTimer); flushTimer = undefined; chatStatus('Chat disconnected. New messages will wait on this device.'); } };
  channel.onerror = () => { if (isCurrent()) chatStatus('Chat connection interrupted. Messages remain on this device.'); };
  channel.onmessage = event => {
    if (!isCurrent()) return;
    if (Date.now() - windowStart >= 10000) { windowStart = Date.now(); count = 0; }
    if (++count > 240 || queued >= 128 || typeof event.data !== 'string' || encoder.encode(event.data).length > 32768) { fail('Chat closed because the peer exceeded message limits.'); return; }
    queued++;
    queue = queue.then(async () => {
      if (!isCurrent()) return;
      const packet = JSON.parse(event.data);
      if (packet?.v === 1 && Object.keys(packet).length === 2 && packet.type === 'burned') { burnAck?.(); return; }
      if (packet?.v === 1 && Object.keys(packet).length === 2 && packet.type === 'burn') {
        // The other participant burned the conversation: delete our copy and confirm.
        peerBurned = true;
        await window.ChatStore.removeConversation(conversation);
        if (isCurrent()) transmit({ v: 1, type: 'burned' });
        status('The other person burned this conversation. It was deleted on this device.');
        refreshHistory(); return;
      }
      if (!packet || packet.v !== 1 || !messageIdPattern.test(packet.id || '') || !['message', 'ack'].includes(packet.type)) throw new Error('Invalid chat packet');
      const records = await window.ChatStore.list();
      if (!isCurrent()) return;
      const existing = records.find(record => record.id === packet.id && record.conversationId === conversation);
      if (packet.type === 'ack') {
        if (existing?.direction === 'outgoing' && sent.has(packet.id)) { await window.ChatStore.setStatus(conversation, existing.id, 'delivered'); refreshHistory(); }
        return;
      }
      if (typeof packet.text !== 'string' || !packet.text.trim() || encoder.encode(packet.text).length > 4096 || !Number.isSafeInteger(packet.createdAt) || packet.createdAt < 0 || packet.createdAt > Date.now() + 300000 || !(packet.expiresAt === null || Number.isSafeInteger(packet.expiresAt) && packet.expiresAt > packet.createdAt && packet.expiresAt <= packet.createdAt + 2592000000)) throw new Error('Invalid chat message');
      if (packet.expiresAt !== null && packet.expiresAt <= Date.now()) return;
      const record = { id: packet.id, conversationId: conversation, direction: 'incoming', text: packet.text, createdAt: packet.createdAt, status: 'delivered', expiresAt: packet.expiresAt };
      if (existing && (existing.direction !== 'incoming' || existing.text !== record.text || existing.createdAt !== record.createdAt || existing.expiresAt !== record.expiresAt)) throw new Error('Conflicting message identifier');
      await window.ChatStore.put(record);
      if (!isCurrent()) return;
      // The acknowledgment means durable receiver storage, never merely arrival.
      // Deduplicate and bound the queue; ordinary channel backpressure is retried.
      if (!pendingAcks.has(packet.id) && pendingAcks.size >= 128) throw new Error('Too many pending chat acknowledgments');
      pendingAcks.add(packet.id); scheduleFlush();
      refreshHistory();
    }).catch(error => fail(error.message === 'Invalid chat packet' || error.message === 'Invalid chat message' || error.message === 'Conflicting message identifier' ? 'Chat closed because a message was invalid.' : 'Chat could not save a message. Check local storage capacity.')).finally(() => { queued--; });
  };
  if (channel.readyState === 'open') channel.onopen();
}

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
  detachChat();
  clearTimeout(restartTimer); restartTimer = undefined;
  if (pc) { pc.onconnectionstatechange = null; pc.close(); }
  pc = null; sessionId = null; ready = false; candidates = [];
  makingOffer = false; ignoreOffer = false; settingAnswer = false; iceRestarts = 0;
  $('remote').srcObject = null;
  clearTimeout(verifyTimer); verifyTimer = undefined;
  $('verify-code').hidden = true; $('verify-digits').textContent = ''; $('verify-label').textContent = '';
}
function cleanup(message) {
  active = false; sessionPrepared = false; lifecycle++;
  clearTimeout(reconnectTimer); reconnectTimer = undefined;
  clearTimeout(handshakeTimer); handshakeTimer = undefined;
  closePeer();
  stream?.getTracks().forEach(track => track.stop()); stream = null;
  $('local').srcObject = null;
  const previous = socket; socket = null; previous?.close();
  for (const id of ['mute', 'camera', 'hangup']) $(id).disabled = true;
  $('play').hidden = true; joining = false; connecting = false; reconnectSince = 0; reconnectAttempt = 0;
  $('invitation-load').disabled = false; $('invitation-input').disabled = false;
  view('state', 'lobby'); view('sheet', ''); view('panel', ''); $('chat-toggle').setAttribute('aria-expanded', 'false');
  status(message);
  window.App?.onEnd?.();
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
  for (const track of stream?.getTracks() || []) peer.addTrack(track, stream);
  peer.ondatachannel = ({ channel }) => {
    // Contact chats travel through the end-to-end encrypted mailbox, not the call's data channel.
    if (pc !== peer || !polite || accountChat) { channel.close(); return; }
    attachChat(peer, channel);
  };
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
      status(stream ? 'Connected — your call is live.' : 'Connected — chat is end-to-end encrypted.');
      if (!verified && !verifyTimer) verifyTimer = setTimeout(() => { verifyTimer = undefined; if (pc === peer && !verified) showVerification('warn', 'Could not verify — treat this call as untrusted and end it.'); }, 15000);
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
  if (!polite && !accountChat) attachChat(peer, peer.createDataChannel('chat-v1', { ordered: true }));
  // Fail closed: no code (missing script, blocked channel, timeout) is shown as an untrusted call.
  const showVerification = (kind, label, code = '') => {
    if (pc !== peer) return;
    const badge = $('verify-code'); badge.hidden = false; badge.dataset.kind = kind;
    $('verify-digits').textContent = code; $('verify-label').textContent = label;
    badge.title = code ? `Verification code ${code}. Read it aloud with the other person. If it doesn't match, end the call: someone is in the middle.` : label;
  };
  verified = false;
  if (!window.Verify) showVerification('warn', 'Verification unavailable — treat this call as untrusted.');
  else {
    showVerification('pending', 'Verifying this call…');
    window.Verify.attach(peer, peer.createDataChannel('verify-v1', { negotiated: true, id: 1000, ordered: true }), result => {
      if (pc !== peer) return;
      verified = Boolean(result.code); clearTimeout(verifyTimer); verifyTimer = undefined;
      if (result.code) showVerification('ok', 'Same code on their screen? No one is listening in.', result.code);
      else showVerification('warn', result.error);
    });
  }
  return peer;
}
async function receive(message) {
  if (message.type === 'welcome') {
    // The server retires the invitation on every accepted connection; keep only the fresh credential.
    if (typeof message.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.token)) throw new Error('Invalid welcome');
    token = message.token; polite = message.polite; reconnectSince = 0; reconnectAttempt = 0; return;
  }
  if (message.type === 'ready') {
    closePeer(); sessionId = message.sessionId; ready = true; createPeer(); window.App?.onPeerJoined?.();
    status(`Connecting to ${peerName}…`); return;
  }
  if (message.type === 'peer-left') { closePeer(); status(`${peerName[0].toUpperCase() + peerName.slice(1)} disconnected. Waiting for them to return…`); return; }
  if (message.type === 'error') {
    // These refer to a retired pairing; its messages must not affect the new one.
    if (message.error !== 'Stale session') status(`Waiting for ${peerName} to reconnect…`);
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
  status(stream ? 'Call connection lost. Reconnecting… Your camera and microphone remain on locally.' : 'Chat connection lost. Reconnecting… Messages remain on this device.');
  const current = lifecycle;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = undefined;
    if (active && current === lifecycle) connectSocket(current);
  }, Math.min(500 * 2 ** Math.min(reconnectAttempt++, 4), 8000));
}
async function loadIce(current, attempt = 0) {
  const response = await fetch(`/rooms/${roomId}/ice`, {
    headers: { Authorization: `Bearer ${token}` }, cache: 'no-store', signal: AbortSignal.timeout(10000),
  });
  if (!active || current !== lifecycle) return false;
  // Devices sharing one address (home Wi-Fi) can briefly hit the per-source limit; retry a few times.
  if (response.status === 429 && attempt < 3) { await new Promise(resolve => setTimeout(resolve, 700 * (attempt + 1))); return loadIce(current, attempt + 1); }
  if (response.status === 401) { validInvite = false; token = null; updateComposer(); cleanup('Call ended or invitation expired. Request a new invitation to call again.'); return false; }
  if (!response.ok) throw new Error(`Call server unavailable (HTTP ${response.status})`);
  const next = await response.json();
  if (!active || current !== lifecycle) return false;
  config = next;
  return true;
}
async function connectSocket(current) {
  if (!active || !sessionPrepared || current !== lifecycle || connecting || socket && socket.readyState < WebSocket.CLOSING) return;
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
      status(accountChat && stream ? `Calling ${peerName}…` : `Waiting for ${peerName}…`);
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
      if ([1000, 1008, 4001, 4002].includes(event.code)) {
        // 4001: the pair's room was replaced by a newer call; 4002: the call was declined.
        validInvite = false; token = null; updateComposer();
        cleanup(peerBurned ? 'The other person burned this conversation. It was deleted on this device.' : event.code === 4002 ? `${peerName[0].toUpperCase() + peerName.slice(1)} declined the call.` : event.code === 4001 ? 'Switched to a new call.' : accountChat ? 'Conversation ended.' : 'Call ended or invitation expired. Request a new invitation to call again.');
      }
      else scheduleReconnect();
    };
    // The close event carries the reconnect decision; errors must not race it.
    connection.onerror = () => {};
  } catch {
    if (active && current === lifecycle) scheduleReconnect();
  } finally { if (current === lifecycle) connecting = false; }
}
$('join-form').addEventListener('submit', event => { event.preventDefault(); return join(event.submitter?.value); });
async function join(choice) {
  if (joining || !validInvite) return;
  if (choice) { $('chat-only').checked = choice === 'chat'; $('audio-only').checked = choice === 'audio'; }
  joining = true; active = true; sessionPrepared = false; const current = ++lifecycle;
  setJoinable(false); $('hangup').disabled = false;
  view('state', $('chat-only').checked ? 'chat' : 'call'); view('media', $('audio-only').checked ? 'audio' : 'video');
  $('invitation-load').disabled = true; $('invitation-input').disabled = true;
  status($('chat-only').checked ? 'Preparing your chat connection…' : 'Preparing your microphone and call connection…');
  try {
    if (!await loadIce(current)) return;
    if (!$('chat-only').checked) {
      const acquired = await navigator.mediaDevices.getUserMedia({ audio: true, video: !$('audio-only').checked });
      if (!active || current !== lifecycle) { acquired.getTracks().forEach(track => track.stop()); return; }
      stream = acquired; $('local').srcObject = stream;
    }
    if (!active || current !== lifecycle) return;
    sessionPrepared = true;
    $('mute').disabled = !stream; $('camera').disabled = !stream?.getVideoTracks().length;
    $('mute').setAttribute('aria-pressed', 'false'); $('mute').setAttribute('aria-label', 'Mute microphone'); $('mute-cap').textContent = 'Mute';
    $('camera').setAttribute('aria-pressed', 'false'); $('camera').setAttribute('aria-label', 'Turn camera off'); $('camera-cap').textContent = 'Camera';
    await connectSocket(current);
  } catch (error) {
    if (current !== lifecycle) return;
    cleanup(error.name === 'NotAllowedError' ? 'Microphone or camera permission denied. Allow access, then try again.' : error.name === 'NotFoundError' ? 'No microphone or camera found. Connect a device or try audio only.' : 'Unable to join. Check your invitation, connection, and media permissions.');
    setJoinable(!accountChat);
  }
}
$('mute').onclick = () => {
  const muted = $('mute').getAttribute('aria-pressed') !== 'true';
  stream?.getAudioTracks().forEach(track => { track.enabled = !muted; });
  $('mute').setAttribute('aria-pressed', String(muted)); $('mute').setAttribute('aria-label', muted ? 'Unmute microphone' : 'Mute microphone'); $('mute-cap').textContent = muted ? 'Unmute' : 'Mute';
};
$('camera').onclick = () => {
  const off = $('camera').getAttribute('aria-pressed') !== 'true';
  stream?.getVideoTracks().forEach(track => { track.enabled = !off; });
  $('camera').setAttribute('aria-pressed', String(off)); $('camera').setAttribute('aria-label', off ? 'Turn camera on' : 'Turn camera off'); $('camera-cap').textContent = off ? 'Camera on' : 'Camera';
};
$('play').onclick = () => $('remote').play().then(() => { $('play').hidden = true; }).catch(() => status('Use your browser’s audio controls to allow playback.'));
async function endRoom(ended) {
  // Stop capture immediately, including when signaling or a permission prompt is pending.
  const endingRoom = roomId, endingToken = token;
  cleanup('Call stopped. Ending the room…');
  const stoppedLifecycle = lifecycle;
  validInvite = false; token = null; updateComposer();
  try {
    const response = await fetch(`/rooms/${endingRoom}`, { method: 'DELETE', headers: { Authorization: `Bearer ${endingToken}` }, signal: AbortSignal.timeout(5000) });
    if (stoppedLifecycle === lifecycle) status(response.ok || response.status === 401 ? ended : 'Call stopped locally. Could not confirm the room ended.');
  } catch { if (stoppedLifecycle === lifecycle) status('Call stopped locally. Could not end the room while offline.'); }
}
$('hangup').onclick = () => endRoom('Call ended.');
$('burn').onclick = () => { $('menu').open = false; $('burn-confirm').hidden = false; };
$('settings-open').onclick = () => { $('menu').open = false; $('settings').open = true; view('panel', 'settings'); };
$('settings-close').onclick = () => view('panel', '');
const toggleChat = open => {
  view('sheet', open ? 'open' : ''); $('chat-toggle').setAttribute('aria-expanded', String(open));
  if (open) { const log = $('chat-log'); log.scrollTop = log.scrollHeight; }
};
$('chat-toggle').onclick = () => toggleChat($('app').dataset.sheet !== 'open');
$('chat-close').onclick = () => toggleChat(false);
$('burn-cancel').onclick = () => { $('burn-confirm').hidden = true; };
$('burn-confirm-yes').onclick = async () => {
  $('burn-confirm').hidden = true;
  if (accountChat && window.App?.onBurn && !chatBusy) {
    chatBusy = true; updateComposer();
    try { await window.App.onBurn(); }
    catch (error) { chatStatus(error.message || 'Could not burn this conversation.'); }
    finally { chatBusy = false; updateComposer(); refreshHistory(); }
    return;
  }
  if (!validInvite || chatBusy) return;
  chatBusy = true; updateComposer();
  const conversation = conversationId;
  let confirmed = false;
  try {
    if (dataChannel?.readyState === 'open') {
      // Wait briefly for the other device to confirm deletion before the room closes the channel.
      dataChannel.send(JSON.stringify({ v: 1, type: 'burn' }));
      confirmed = await new Promise(resolve => { burnAck = () => resolve(true); setTimeout(() => resolve(false), 2000); });
      burnAck = null;
    }
    await endRoom(confirmed ? 'Conversation burned on both devices. The room is closed.' : 'Conversation burned on this device. The other device did not confirm. The room is closed.');
    await window.ChatStore.removeConversation(conversation);
  } catch (error) { status(error.message || 'Could not burn this conversation.'); }
  finally { chatBusy = false; updateComposer(); refreshHistory(); }
};
window.addEventListener('online', () => {
  if (!active || !sessionPrepared) return;
  if (socket?.readyState !== WebSocket.OPEN) {
    clearTimeout(reconnectTimer); reconnectTimer = undefined; scheduleReconnect();
  } else if (pc) recoverIce(pc, true);
});
window.addEventListener('pagehide', () => cleanup('Call closed.'));
$('invitation-form').addEventListener('submit', event => {
  event.preventDefault();
  try { openInvitation($('invitation-input').value.trim()); }
  catch (error) { status(error.message); }
});
window.addEventListener('hashchange', () => {
  const incoming = location.href; history.replaceState(null, '', location.pathname);
  const invite = new URLSearchParams(new URL(incoming).hash.slice(1)).get('invite');
  if (invite) { window.pendingAccountInvite = invite; window.App?.onInvite?.(invite); return; }
  try { openInvitation(incoming); } catch (error) { status(error.message); }
});
$('history-select').onchange = () => { selectedHistory = $('history-select').value; refreshHistory(); };
$('chat-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (chatBusy || !(validInvite || accountChat) || selectedHistory !== conversationId) return;
  const text = $('chat-input').value;
  if (!text.trim() || encoder.encode(text).length > 4096) { chatStatus('Enter a message up to 4096 UTF-8 bytes.'); return; }
  chatBusy = true; updateComposer();
  const createdAt = Date.now(), duration = Number($('disappear').value) || 0;
  try {
    await window.ChatStore.put({ id: crypto.randomUUID(), conversationId, direction: 'outgoing', text, createdAt, status: 'queued', expiresAt: duration ? createdAt + duration : null });
    $('chat-input').value = ''; resizeComposer();
    if (accountChat) window.App?.onQueued?.(); // Encrypted and posted to the mailbox by account.js.
    else if (requestChatFlush?.(), dataChannel?.readyState === 'open') chatStatus('');
    else chatStatus('Queued on this device. Both participants need a valid invitation and a connection to exchange it.');
    await refreshHistory();
  } catch (error) { chatStatus(error.message || 'Could not save this message.'); }
  finally { chatBusy = false; updateComposer(); }
});
// Single-row composer that grows with its text; Enter sends on devices with a keyboard.
function resizeComposer() { const input = $('chat-input'); if (!input.style) return; input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 160)}px`; }
$('chat-input').oninput = resizeComposer;
$('chat-input').onkeydown = event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && matchMedia('(pointer: fine)').matches) { event.preventDefault(); $('chat-form').requestSubmit(); }
};
const disappearingPreferenceKey = 'private-chat-disappearing-v1';
try { const preference = localStorage.getItem(disappearingPreferenceKey); if (['off', '3600000', '86400000', '604800000'].includes(preference)) $('disappear').value = preference; } catch {}
$('disappear').onchange = () => { try { localStorage.setItem(disappearingPreferenceKey, $('disappear').value); } catch {} };
async function backupAction(action) {
  $('backup-export').disabled = true; $('backup-import').disabled = true;
  $('backup-status').textContent = 'Working on your device…';
  try { await action(); }
  catch (error) { $('backup-status').textContent = error.message || 'Backup operation failed.'; }
  finally { $('backup-password').value = ''; $('backup-export').disabled = false; $('backup-import').disabled = false; }
}
$('backup-export').onclick = () => backupAction(async () => {
  const blob = await window.ChatStore.exportBackup($('backup-password').value);
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `private-conversations-${new Date().toISOString().slice(0, 10)}.json`; document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  $('backup-status').textContent = 'Encrypted backup downloaded. Save this file to Google Drive if you want to move it to another phone.';
});
$('backup-import').onclick = () => backupAction(async () => {
  const file = $('backup-file').files[0];
  if (!file) throw new Error('Choose an encrypted backup file.');
  const count = await window.ChatStore.importBackup(file, $('backup-password').value);
  $('backup-file').value = ''; await refreshHistory();
  $('backup-status').textContent = `Restored ${count} messages. Original expiry times are preserved. Restored history does not reopen conversations or resend messages.`;
});
$('history-clear').onclick = () => { $('clear-confirm').hidden = false; };
$('history-clear-cancel').onclick = () => { $('clear-confirm').hidden = true; };
$('history-clear-confirm').onclick = async () => {
  try { await window.ChatStore.clear(); await refreshHistory(); $('clear-confirm').hidden = true; $('backup-status').textContent = 'Local history deleted. Other devices and backup files are unchanged.'; }
  catch (error) { $('backup-status').textContent = error.message || 'Could not delete local history.'; }
};
setInterval(() => { refreshHistory(); }, 5000);
if (!window.isSecureContext || !window.RTCPeerConnection) status('Conversations require a supported browser over HTTPS (or localhost for development).');
else {
  const incoming = location.href; history.replaceState(null, '', location.pathname);
  const hash = new URLSearchParams(new URL(incoming).hash.slice(1));
  // Account invitations (#invite=…) belong to the sign-up screen, not the call flow.
  if (hash.has('invite')) { window.pendingAccountInvite = hash.get('invite'); status('Create your account with this invitation.'); }
  // Notification taps open a contact's conversation (#open=username); account.js picks it up after sign-in.
  // It only selects a conversation: nothing in a URL may start or answer a call or capture media.
  else if (hash.has('open')) window.pendingOpen = { user: hash.get('open'), call: hash.has('call') };
  else if (new URL(incoming).hash) { try { openInvitation(incoming); } catch (error) { status(error.message); $('invitation-panel').open = true; } }
  else { status('Open your invitation link to connect. Saved messages stay below.'); $('status').classList?.add('idle'); $('invitation-panel').open = true; }
}
  // Hooks for account.js: contact conversations reuse this call and chat engine unchanged.
window.App = {
  get active() { return active; }, get roomId() { return roomId; }, get conversationId() { return conversationId; },
  status, chatStatus, refreshHistory, view,
  openConversation(next) {
    if (active && conversationId !== next.conversationId) throw new Error('busy');
    conversationId = selectedHistory = next.conversationId; peerName = next.peerName; accountChat = true; transcriptSignature = '';
    if (!active) { validInvite = false; chatStatus(''); }
    refreshHistory();
  },
  closeConversation() { if (!active) { accountChat = false; conversationId = null; selectedHistory = ''; refreshHistory(); } },
  async start(next) {
    if (active) { cleanup('Switching conversation…'); }
    lifecycle++; roomId = next.roomId; token = next.token; validInvite = true; peerBurned = false;
    conversationId = selectedHistory = next.conversationId; peerName = next.peerName; accountChat = true;
    $('remote').closest('figure').querySelector('figcaption').textContent = next.peerName;
    await join(next.kind === 'chat' ? 'chat' : next.kind === 'voice' ? 'audio' : 'video');
  },
  end: () => endRoom('Conversation ended.'),
  leave() { if (active) cleanup('Conversation closed.'); },
};
refreshHistory();
