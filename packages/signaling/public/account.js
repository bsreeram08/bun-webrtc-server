'use strict';
// Passkey accounts, contacts, presence and end-to-end encrypted messaging. Contact messages travel
// as Signal-protocol envelopes (signal.js) through the server mailbox, which can never read them;
// calls still run device-to-device through app.js.
(() => {
  const $ = id => document.getElementById(id);
  const body = $('app'), App = window.App;
  let me = null, contacts = [], events = null, retry = 0, retryTimer, current = null, ringing = null;
  let box = null, ready = Promise.resolve(false), inbound = Promise.resolve(), flushing = false, flushAgain = false, flushTimer;
  let unread = {}, flagged = new Set();
  const pairs = new Map(), mismatched = new Set();
  let missTimer, noAnswerTimer;
  const Ring = window.Ring || { incoming() {}, outgoing() {}, stop() {}, unlock() {} };
  const RING_TIMEOUT = 45000, USERNAME = /^[a-z0-9_]{3,20}$/;
  const clock = time => new Date(time).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const say = (id, text) => { $(id).textContent = text; };
  const initial = name => (name || '?').slice(0, 1).toUpperCase();

  async function api(path, method = 'GET', payload) {
    const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error(data.error || 'Something went wrong. Try again.'), { status: response.status });
    return data;
  }
  // One stable, opaque ChatStore id per pair, so history survives across rooms and devices.
  async function pairId(otherId) {
    const key = [me.id, otherId].sort().join(':');
    if (!pairs.has(key)) {
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`webrtc-bun-pair-v1:${key}`)));
      pairs.set(key, btoa(String.fromCharCode(...digest)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    }
    return pairs.get(key);
  }
  const contactById = id => contacts.find(contact => contact.id === id);

  // ---------- Welcome: passkey sign-in and invite sign-up ----------
  async function guard(button, statusId, task) {
    button.disabled = true; say(statusId, '');
    try { await task(); }
    catch (error) { say(statusId, error.name === 'NotAllowedError' ? 'Passkey request was cancelled.' : error.message || 'Something went wrong.'); }
    finally { button.disabled = false; }
  }
  $('signin').onclick = () => guard($('signin'), 'account-status', async () => {
    const { flowId, options } = await api('/api/login/options', 'POST', {});
    const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
    signedIn((await api('/api/login/verify', 'POST', { flowId, response })).user);
  });
  $('register-form').addEventListener('submit', event => {
    event.preventDefault();
    guard($('register-submit'), 'account-status', async () => {
      const invite = $('register-invite').value.trim(), username = $('register-username').value.trim().toLowerCase();
      const { flowId, options } = await api('/api/register/options', 'POST', { invite, username });
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
      signedIn((await api('/api/register/verify', 'POST', { flowId, response })).user);
      $('register-invite').value = ''; $('register-username').value = '';
    });
  });

  function signedIn(user) {
    me = user; body.dataset.auth = 'in'; body.dataset.screen = 'list';
    say('me-name', `@${user.username}`); say('account-status', '');
    try { unread = JSON.parse(localStorage.getItem(`unread-v1:${me.id}`) || '{}') || {}; } catch { unread = {}; }
    ready = setupKeys(user);
    loadContacts(); connectEvents(); window.Alerts?.signedIn();
  }
  function signedOut(message = '') {
    me = null; contacts = []; current = null; pairs.clear(); box = null; ready = Promise.resolve(false); flagged = new Set(); mismatched.clear();
    clearTimeout(retryTimer); clearTimeout(flushTimer); const previous = events; events = null; previous?.close();
    if (App.active) App.end(); App.closeConversation(); $('key-banner').hidden = true;
    body.dataset.auth = 'out'; body.dataset.screen = ''; say('account-status', message);
    hideRing(); stopCalling(); window.Alerts?.signedOut();
  }
  async function signOut(everywhere) {
    $('account-menu').open = false;
    try { await api(everywhere ? '/api/logout?all=1' : '/api/logout', 'POST', {}); } catch {}
    signedOut(everywhere ? 'Signed out on every device.' : 'Signed out.');
  }
  $('signout').onclick = () => signOut(false);
  $('signout-all').onclick = () => signOut(true);

  // ---------- Encryption keys ----------
  async function setupKeys(user) {
    if (!window.Signal || !await window.Signal.supported()) {
      say('chats-status', 'This browser is too old for encrypted messaging. Update it to send and receive messages; calls still work.');
      return false;
    }
    // One key store per account on this device. Private keys never leave it.
    const store = window.Signal.indexedDbBackend(`webrtc-bun-signal-v1-${user.id}`);
    box = window.Signal.box(store, { identityChanged: contactId => identityChanged(contactId) });
    flagged = new Set(await store.get('flagged') || []);
    flagged.store = store;
    try { await publishKeys(); } catch (error) { say('chats-status', `Could not publish encryption keys: ${error.message}`); }
    return true;
  }
  async function publishKeys() {
    if (!box || !me) return;
    const keys = await box.prekeys(), count = await api('/api/keys/count');
    const upload = { identity: keys.identity, signedPreKey: keys.signedPreKey };
    if (count.oneTimePreKeys < 20 || count.signedPreKeyId === null) upload.oneTimePreKeys = await box.oneTimePreKeys(100 - Math.min(count.oneTimePreKeys, 100) || 100);
    if (upload.oneTimePreKeys || keys.rotated || count.signedPreKeyId !== keys.signedPreKey.id) await api('/api/keys', 'PUT', upload);
  }
  async function rememberFlag(id) {
    flagged.add(id);
    await flagged.store?.put('flagged', [...flagged].slice(-500));
  }

  // ---------- Presence and mailbox stream ----------
  function connectEvents() {
    if (!me || events) return;
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/events`);
    events = socket;
    socket.onopen = () => { retry = 0; };
    socket.onmessage = event => {
      let message; try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === 'hello') {
        for (const contact of contacts) contact.online = message.online.includes(contact.id);
        render(); ready.then(ok => { if (ok) { publishKeys().catch(() => {}); flushOutgoing(); } });
      }
      else if (message.type === 'presence') presence(message.id, message.online);
      else if (message.type === 'contacts') loadContacts();
      else if (message.type === 'incoming') incoming(message);
      else if (message.type === 'envelope') inbound = inbound.then(() => receiveEnvelope(socket, message)).catch(() => {});
      else if (message.type === 'keys') checkIdentity(message.id).then(flushOutgoing).catch(() => {});
      else if (message.type === 'ended' && ringing?.roomId === message.roomId) { const ring = ringing; ringing = null; hideRing(); say('chats-status', `Missed ${ring.kind} call from ${ring.contact.username} · ${clock(Date.now())}`); }
    };
    socket.onclose = event => {
      if (events !== socket) return;
      events = null;
      if (event.code === 4401) { signedOut('Your session ended. Sign in again.'); return; }
      retryTimer = setTimeout(connectEvents, Math.min(1000 * 2 ** retry++, 15000));
    };
  }
  function presence(id, online) {
    const contact = contactById(id);
    if (!contact) return;
    contact.online = online; render();
  }

  // ---------- Receiving ----------
  const coded = (code, text) => Object.assign(new Error(text), { code });
  // Shape only; message content is validated by ChatStore.receive, the same rules every stored record meets.
  function checkPayload(payload) {
    if (!payload || payload.v !== 1 || !window.ChatStore.isMessageId(payload.id)) throw coded('invalid', 'Invalid message');
    const size = Object.keys(payload).length;
    if (!((payload.type === 'receipt' || payload.type === 'burn') && size === 3 || payload.type === 'message' && size === 6)) throw coded('invalid', 'Invalid message');
  }
  const attempts = new Map();
  async function receiveEnvelope(socket, message) {
    if (!await ready || !box) return; // Unacknowledged: redelivered once this device can decrypt.
    const from = message.from, conversationId = await pairId(from.id), viewing = () => body.dataset.screen === 'conversation' && current?.id === from.id;
    let receipt = null, burned = false, failure = null;
    try {
      await box.decryptFrom(from.id, message.envelope, async (payload, info) => {
        checkPayload(payload);
        // Defence in depth only: the pinned identity in signal.js (peer:<user id>, never deleted by burn,
        // contact removal or forget) is the trust boundary, because a hostile server controls this lookup too.
        // A mismatch with the published key still catches a mislabelled `from` from an honest-but-buggy relay.
        if (info.identity) {
          // A lookup that fails for network reasons is retried; only a real mismatch is discarded.
          const published = await api(`/api/keys/${from.username}/identity`).then(result => result.identity, error => { throw coded(error.status === 403 ? 'mismatch' : 'storage', error.message); });
          if (published.dh !== info.identity.dh || published.sign !== info.identity.sign) throw coded('mismatch', 'Identity mismatch');
        }
        // Until the user accepts a changed security code, the new identity may deliver (flagged) messages
        // but may not burn history or mark our messages delivered.
        const untrusted = info.identityChanged || Boolean((await box.peer(from.id))?.blocked);
        if (untrusted && payload.type !== 'message') return;
        try {
          if (payload.type === 'receipt') await window.ChatStore.setStatus(conversationId, payload.id, 'delivered');
          else if (payload.type === 'burn') { await window.ChatStore.removeConversation(conversationId); burned = true; }
          else if (await window.ChatStore.receive(conversationId, payload) === 'stored') {
            // Idempotent by message id: duplicates are neither shown, counted nor acknowledged twice.
            if (untrusted) await rememberFlag(payload.id.toLowerCase());
            if (!viewing()) unread[from.id] = (unread[from.id] || 0) + 1;
            receipt = payload.id;
          }
        } catch (error) { throw error.code ? error : coded('storage', error.message); }
      });
    } catch (error) { failure = error; }
    const tries = (attempts.get(message.id) || 0) + 1;
    const outcome = window.ChatStore.inboundDisposition(failure, tries);
    if (!outcome.ack) { attempts.set(message.id, tries); say('chats-status', 'Could not save an incoming message yet. Retrying…'); return; }
    attempts.delete(message.id);
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ack', id: message.id }));
    const notice = {
      'storage-full': `A message from ${from.username} was discarded: this device holds 2,000 messages. Clear some history to receive more.`,
      'conversation-full': `A message from ${from.username} was discarded: this conversation holds 500 incoming messages. Burn or clear it to receive more from them.`,
      invalid: `A message from ${from.username} was invalid or did not match their published security code, and was discarded.`,
      'gave-up': `A message from ${from.username} could not be saved after several tries and was discarded.`,
      undecryptable: `A message from ${from.username} could not be decrypted and was discarded.`,
    }[outcome.notice];
    if (notice) { if (viewing()) App.chatStatus(notice); else say('chats-status', notice); }
    try { localStorage.setItem(`unread-v1:${me.id}`, JSON.stringify(unread)); } catch {}
    if (burned) {
      delete unread[from.id];
      if (viewing()) App.chatStatus(`${from.username} burned this conversation. It was deleted on this device.`);
      else say('chats-status', `${from.username} burned your conversation. It was deleted on this device.`);
    }
    if (viewing()) { App.refreshHistory(); updateBanner(); }
    render();
    if (receipt) sendControl(from, { v: 1, type: 'receipt', id: receipt }).catch(() => {});
  }

  // ---------- Sending ----------
  const bundleFor = contact => () => api(`/api/keys/${contact.username}`);
  async function sendControl(contact, payload) {
    if (!box) throw new Error('Encrypted messaging is unavailable in this browser.');
    const envelope = await box.encryptTo(contact.id, payload, bundleFor(contact));
    await api('/api/messages', 'POST', { to: contact.username, envelope });
  }
  /** Encrypts and posts every queued outgoing message, oldest first, one contact at a time. */
  async function flushOutgoing() {
    if (!me || !await ready || !box) return;
    if (flushing) { flushAgain = true; return; }
    flushing = true; flushAgain = false; clearTimeout(flushTimer);
    let retryLater = false;
    try {
      const records = await window.ChatStore.list();
      for (const contact of contacts.filter(value => value.state === 'mutual')) {
        const conversationId = await pairId(contact.id);
        for (const record of records.filter(value => value.conversationId === conversationId && value.direction === 'outgoing' && value.status === 'queued')) {
          try {
            await sendControl(contact, { v: 1, type: 'message', id: record.id, text: record.text, createdAt: record.createdAt, expiresAt: record.expiresAt });
            await window.ChatStore.setStatus(conversationId, record.id, 'sent');
          } catch (error) {
            if (current?.id === contact.id) App.chatStatus(error.code === 'identity-blocked' ? `${contact.username}'s security code changed. Review it to keep sending.` : error.status === 404 ? `${contact.username} has not opened the app since encryption was enabled. Messages wait on this device.` : `Not sent yet: ${error.message}`);
            if (error.code === 'identity-blocked') updateBanner();
            else retryLater = true;
            break; // Keep this contact's order; try the next contact.
          }
        }
      }
    } finally {
      flushing = false;
      if (current) App.refreshHistory();
      render();
      if (flushAgain) flushOutgoing();
      else if (retryLater) flushTimer = setTimeout(flushOutgoing, 15000);
    }
  }
  App.onQueued = () => { if (current) App.chatStatus(''); flushOutgoing(); };
  App.onBurn = async () => {
    const contact = current && contactById(current.id);
    if (!contact) throw new Error('Open the conversation to burn it.');
    const conversationId = await pairId(contact.id);
    await sendControl(contact, { v: 1, type: 'burn', id: crypto.randomUUID() });
    await window.ChatStore.removeConversation(conversationId);
    App.chatStatus(`Burned on this device. ${contact.username}'s device deletes its copy when the encrypted request arrives.`);
  };
  App.flagged = record => flagged.has(record.id.toLowerCase());

  // ---------- Security codes ----------
  async function checkIdentity(contactId) {
    const contact = contactById(contactId);
    if (!contact || !box) return;
    const { identity } = await api(`/api/keys/${contact.username}/identity`);
    await box.notePeer(contactId, identity);
    if (current?.id === contactId) updateBanner();
  }
  // Cross-check a changed identity against the server's published one; a mismatch is suspicious.
  async function identityChanged(contactId) {
    const contact = contactById(contactId);
    try {
      const published = contact ? (await api(`/api/keys/${contact.username}/identity`)).identity : null;
      const peer = await box.peer(contactId);
      if (published && peer && (published.dh !== peer.identity.dh || published.sign !== peer.identity.sign)) mismatched.add(contactId); else mismatched.delete(contactId);
    } catch {}
    if (current?.id === contactId) updateBanner();
    render();
  }
  async function updateBanner() {
    const banner = $('key-banner');
    if (!current || !box) { banner.hidden = true; return; }
    const peer = await box.peer(current.id);
    if (!peer || !(peer.changed || peer.blocked)) { banner.hidden = true; return; }
    const name = current.username;
    say('key-banner-text', mismatched.has(current.id)
      ? `Warning: ${name}'s security code changed, and the server publishes a different one. Verify in person before trusting new messages.`
      : peer.blocked ? `${name}'s security code changed. Sending is paused until you review it.` : `${name}'s security code changed. Compare it again to be sure no one is in the middle.`);
    banner.hidden = false;
  }
  async function openSafety() {
    $('conv-menu').open = false;
    const contact = current && contactById(current.id);
    if (!contact || !box) { App.chatStatus('Encrypted messaging is unavailable in this browser.'); return; }
    try {
      if (!await box.peer(contact.id)) await box.notePeer(contact.id, (await api(`/api/keys/${contact.username}/identity`)).identity);
      const safety = await box.safety(me.username, contact.id, contact.username);
      say('safety-title', `Security code with ${contact.username}`);
      say('safety-number', safety.number);
      say('safety-state', safety.verified ? 'Verified on this device.' : safety.changed ? 'This code changed recently. Compare it before trusting new messages.' : 'Not verified yet. Compare these 60 digits with the ones on their screen, in person or on a call. If they match, no one — not even this server — can read your messages.');
      $('safety-verify').textContent = safety.verified ? 'Clear verification' : 'Mark as verified';
      $('safety-accept').hidden = !safety.blocked;
      $('safety').hidden = false; $('safety-close').focus();
    } catch (error) { App.chatStatus(error.status === 404 ? `${contact.username} has not set up encrypted messaging yet.` : error.message); }
  }
  $('conv-safety').onclick = openSafety;
  $('key-banner-review').onclick = openSafety;
  $('safety-close').onclick = () => { $('safety').hidden = true; };
  $('safety-verify').onclick = async () => {
    const safety = await box.safety(me.username, current.id, current.username);
    await box.setVerified(current.id, !safety.verified);
    $('safety').hidden = true; updateBanner(); flushOutgoing();
  };
  $('safety-accept').onclick = async () => { await box.acceptChange(current.id); $('safety').hidden = true; updateBanner(); flushOutgoing(); };

  // ---------- Contacts and chat list ----------
  async function loadContacts() {
    if (!me) return;
    try {
      const online = new Set(contacts.filter(contact => contact.online).map(contact => contact.id));
      contacts = (await api('/api/contacts')).contacts.map(contact => ({ ...contact, online: contact.online || online.has(contact.id) }));
      render(); flushOutgoing(); openPending();
    } catch (error) { if (error.status === 401) signedOut('Your session ended. Sign in again.'); }
  }
  async function render() {
    if (!me) return;
    const records = window.ChatStore ? await window.ChatStore.list().catch(() => []) : [];
    const last = new Map(); for (const record of records) last.set(record.conversationId, record);
    const list = $('contact-list'), rows = [];
    for (const contact of contacts) {
      const row = document.createElement('li'); row.className = `contact ${contact.state}`;
      const avatar = document.createElement('span'); avatar.className = 'avatar'; avatar.textContent = initial(contact.username); avatar.setAttribute('aria-hidden', 'true');
      if (contact.state === 'mutual') avatar.dataset.online = String(contact.online);
      const text = document.createElement('span'); text.className = 'contact-text';
      const name = document.createElement('strong'); name.textContent = contact.username;
      const sub = document.createElement('small');
      text.append(name, sub); row.append(avatar, text);
      if (contact.state === 'mutual') {
        const recent = last.get(await pairId(contact.id)), count = unread[contact.id] || 0;
        sub.textContent = recent ? `${recent.direction === 'outgoing' ? 'You: ' : ''}${recent.text}` : contact.online ? 'Online' : 'Tap to chat';
        const side = document.createElement('span'); side.className = 'contact-side';
        const time = document.createElement('time'); time.textContent = recent ? clock(recent.createdAt) : '';
        side.append(time);
        if (count) { const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = count > 99 ? '99+' : String(count); side.append(badge); row.classList.add('unread'); }
        const open = document.createElement('button'); open.type = 'button'; open.className = 'row-button';
        open.setAttribute('aria-label', `Open conversation with ${contact.username}${count ? `, ${count} unread` : ''}${contact.online ? ', online' : ''}`);
        open.onclick = () => openConversation(contact);
        row.append(side, open);
      } else if (contact.state === 'incoming') {
        sub.textContent = 'Wants to add you';
        row.append(action('Accept', 'primary', async () => { await api(`/api/contacts/${contact.username}/accept`, 'POST', {}); loadContacts(); }),
          action('Decline', '', async () => { await api(`/api/contacts/${contact.username}`, 'DELETE'); loadContacts(); }));
      } else {
        sub.textContent = 'Request sent';
        row.append(action('Cancel', '', async () => { await api(`/api/contacts/${contact.username}`, 'DELETE'); loadContacts(); }));
      }
      rows.push(row);
    }
    list.replaceChildren(...rows);
    $('contacts-empty').hidden = rows.length > 0;
    if (current) updateHeader();
  }
  function action(label, kind, task) {
    const button = document.createElement('button'); button.type = 'button'; button.textContent = label; if (kind) button.className = kind;
    button.onclick = () => guard(button, 'chats-status', task);
    return button;
  }
  $('contact-form').addEventListener('submit', event => {
    event.preventDefault();
    guard($('contact-add'), 'chats-status', async () => {
      const username = $('contact-input').value.trim().toLowerCase();
      await api('/api/contacts', 'POST', { username });
      $('contact-input').value = '';
      say('chats-status', `Request sent to @${username}. They appear in your chats once they accept.`);
      loadContacts();
    });
  });
  $('invite-create').onclick = () => { $('account-menu').open = false; guard($('invite-create'), 'chats-status', async () => {
    const { code, expiresAt } = await api('/api/invites', 'POST', {});
    $('invite-link').value = `${location.origin}/#invite=${code}`;
    say('invite-expiry', `Works once, until ${new Date(expiresAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}. Share it privately.`);
    $('invite-result').hidden = false;
  }); };
  $('invite-copy').onclick = async () => {
    try { await navigator.clipboard.writeText($('invite-link').value); say('invite-expiry', 'Copied. Share it privately; it works once.'); }
    catch { $('invite-link').select(); }
  };
  $('invite-close').onclick = () => { $('invite-result').hidden = true; $('invite-link').value = ''; };
  $('account-settings').onclick = () => { $('account-menu').open = false; $('settings').open = true; App.view('panel', 'settings'); };

  // ---------- Conversation ----------
  function updateHeader() {
    const contact = contactById(current.id) || current;
    say('conv-name', contact.username); say('conv-avatar', initial(contact.username));
    $('conv-avatar').dataset.online = String(Boolean(contact.online));
    say('conv-presence', contact.state !== 'mutual' ? 'not a contact' : contact.online ? 'online' : 'offline');
    $('conv-voice').disabled = $('conv-video').disabled = !contact.online || contact.state !== 'mutual';
  }
  async function openConversation(contact) {
    const conversationId = await pairId(contact.id);
    if (App.active && App.conversationId !== conversationId) await App.end();
    current = contact; body.dataset.screen = 'conversation'; updateHeader();
    delete unread[contact.id]; try { localStorage.setItem(`unread-v1:${me.id}`, JSON.stringify(unread)); } catch {}
    if (!App.active) App.openConversation({ conversationId, peerName: contact.username, online: contact.online });
    if (!await ready) App.chatStatus('This browser is too old for encrypted messaging. Update it to send and receive messages.');
    updateBanner(); flushOutgoing();
  }
  /** Notification taps only choose which conversation to show. They never start or answer a call:
   *  an incoming call keeps ringing on its sheet until the user taps Accept in the app. */
  async function openPending() {
    const pending = window.pendingOpen;
    if (!pending || !me) return;
    window.pendingOpen = null;
    const contact = USERNAME.test(pending.user || '') && contacts.find(value => value.username === pending.user && value.state === 'mutual');
    if (!contact || App.active) return;
    if (!pending.call) { openConversation(contact); return; }
    // A call notification must not start chat here: that would take over the waiting call's room.
    current = contact; body.dataset.screen = 'conversation'; updateHeader();
    App.openConversation({ conversationId: await pairId(contact.id), peerName: contact.username, online: contact.online });
  }
  if (window.Alerts) window.Alerts.onOpen = data => { window.pendingOpen = { user: data.user, call: Boolean(data.call) }; openPending(); };
  function stopCalling() { clearTimeout(noAnswerTimer); noAnswerTimer = undefined; Ring.stop(); }
  async function call(kind) {
    if (!current) return;
    const contact = current;
    try {
      const conversationId = await pairId(contact.id);
      Ring.unlock(); // This click is the gesture that lets the ringback play.
      if (App.active) App.leave();
      const session = await api(`/api/conversations/${contact.username}/session`, 'POST', { kind });
      await App.start({ ...session, kind, conversationId, peerName: contact.username });
      if (!App.active) return;
      Ring.outgoing();
      clearTimeout(noAnswerTimer);
      noAnswerTimer = setTimeout(async () => {
        noAnswerTimer = undefined; Ring.stop();
        if (App.roomId !== session.roomId) return;
        await App.end();
        App.status(`No answer from ${contact.username}.`); say('chats-status', `No answer from ${contact.username} · ${clock(Date.now())}`);
      }, RING_TIMEOUT);
    } catch (error) { stopCalling(); App.status(error.message); }
  }
  $('conv-voice').onclick = () => call('voice');
  $('conv-video').onclick = () => call('video');
  $('conv-back').onclick = () => {
    body.dataset.screen = 'list'; $('key-banner').hidden = true;
    if (!App.active) { App.closeConversation(); current = null; }
    render();
  };
  $('conv-burn').onclick = () => { $('conv-menu').open = false; if (!$('burn').disabled) $('burn').click(); };
  $('conv-remove').onclick = () => { $('conv-menu').open = false; $('remove-confirm').hidden = false; };
  $('remove-cancel').onclick = () => { $('remove-confirm').hidden = true; };
  $('remove-yes').onclick = () => guard($('remove-yes'), 'chats-status', async () => {
    $('remove-confirm').hidden = true;
    const contact = current;
    if (App.active) App.leave();
    await api(`/api/contacts/${contact.username}`, 'DELETE');
    current = null; App.closeConversation(); body.dataset.screen = 'list'; $('key-banner').hidden = true;
    say('chats-status', `Removed @${contact.username}. Messages on this device are unchanged.`);
    loadContacts();
  });

  // ---------- Incoming calls ----------
  async function incoming(message) {
    // Contact chats use the encrypted mailbox now; only calls ring.
    if (message.kind === 'chat') return;
    const contact = contactById(message.from.id) || { ...message.from, state: 'mutual', online: true };
    const conversationId = await pairId(contact.id);
    ringing = { ...message, contact, conversationId };
    say('incoming-avatar', initial(contact.username)); say('incoming-title', contact.username);
    say('incoming-kind', message.kind === 'video' ? 'Incoming video call' : 'Incoming voice call');
    $('incoming').hidden = false; $('incoming-accept').focus();
    Ring.incoming(); acknowledgeRinging();
    clearTimeout(missTimer);
    missTimer = setTimeout(() => {
      if (ringing?.roomId !== message.roomId) return;
      ringing = null; hideRing();
      say('chats-status', `Missed ${message.kind} call from ${contact.username} · ${clock(Date.now())}`);
    }, RING_TIMEOUT);
  }
  // Tells the server this call is ringing on a visible screen, so it need not wake the phone by push.
  function acknowledgeRinging() {
    if (ringing && document.visibilityState === 'visible' && events?.readyState === WebSocket.OPEN) events.send(JSON.stringify({ type: 'ringing', roomId: ringing.roomId }));
  }
  document.addEventListener('visibilitychange', acknowledgeRinging);
  function hideRing() { $('incoming').hidden = true; clearTimeout(missTimer); missTimer = undefined; Ring.stop(); }
  $('incoming-accept').onclick = async () => {
    Ring.unlock();
    const ring = ringing; ringing = null; hideRing();
    if (!ring) return;
    if (App.active) App.leave();
    current = ring.contact; body.dataset.screen = 'conversation'; updateHeader(); updateBanner();
    await App.start({ roomId: ring.roomId, token: ring.token, kind: ring.kind, conversationId: ring.conversationId, peerName: ring.contact.username });
  };
  $('incoming-decline').onclick = async () => {
    const ring = ringing; ringing = null; hideRing();
    if (ring) { try { await api(`/api/conversations/${ring.contact.username}/decline`, 'POST', { roomId: ring.roomId }); } catch {} }
  };

  App.onInvite = invite => { if (!me) { $('register-invite').value = invite; $('register-panel').open = true; $('register-username').focus(); } };
  App.onEnd = () => { stopCalling(); if (me) { if (current) updateHeader(); render(); } };
  App.onPeerJoined = () => stopCalling();

  // ---------- Start ----------
  (async () => {
    if (window.pendingAccountInvite) App.onInvite(window.pendingAccountInvite);
    try { signedIn((await api('/api/me')).user); }
    catch (error) { body.dataset.auth = error.status === 404 ? 'off' : 'out'; if (body.dataset.auth === 'out' && !App.roomId) $('invitation-panel').open = false; }
  })();
})();
