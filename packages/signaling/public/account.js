'use strict';
// Passkey accounts, contacts and presence. The server introduces contacts; calls and chat
// still run device-to-device through app.js, and message content never touches this file's requests.
(() => {
  const $ = id => document.getElementById(id);
  const body = $('app'), App = window.App;
  let me = null, contacts = [], events = null, retry = 0, retryTimer, current = null, ringing = null;
  const pairs = new Map();
  const clock = time => new Date(time).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const say = (id, text) => { $(id).textContent = text; };
  const initial = name => (name || '?').slice(0, 1).toUpperCase();

  async function api(path, method = 'GET', payload) {
    const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers: payload === undefined ? {} : { 'Content-Type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw Object.assign(new Error(data.error || 'Something went wrong. Try again.'), { status: response.status });
    return data;
  }
  // One stable, opaque ChatStore id per pair, so history survives across rooms.
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
    loadContacts(); connectEvents();
  }
  function signedOut(message = '') {
    me = null; contacts = []; current = null; pairs.clear();
    clearTimeout(retryTimer); const previous = events; events = null; previous?.close();
    if (App.active) App.end(); App.closeConversation();
    body.dataset.auth = 'out'; body.dataset.screen = ''; say('account-status', message);
  }
  async function signOut(everywhere) {
    $('account-menu').open = false;
    try { await api(everywhere ? '/api/logout?all=1' : '/api/logout', 'POST', {}); } catch {}
    signedOut(everywhere ? 'Signed out on every device.' : 'Signed out.');
  }
  $('signout').onclick = () => signOut(false);
  $('signout-all').onclick = () => signOut(true);

  // ---------- Presence stream ----------
  function connectEvents() {
    if (!me || events) return;
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/events`);
    events = socket;
    socket.onopen = () => { retry = 0; };
    socket.onmessage = event => {
      let message; try { message = JSON.parse(event.data); } catch { return; }
      if (message.type === 'hello') { for (const contact of contacts) contact.online = message.online.includes(contact.id); render(); }
      else if (message.type === 'presence') presence(message.id, message.online);
      else if (message.type === 'contacts') loadContacts();
      else if (message.type === 'incoming') incoming(message);
      else if (message.type === 'ended' && ringing?.roomId === message.roomId) { hideRing(); say('chats-status', `Missed call from ${ringing?.from.username ?? 'a contact'}.`); }
    };
    socket.onclose = event => {
      if (events !== socket) return;
      events = null;
      if (event.code === 4401) { signedOut('Your session ended. Sign in again.'); return; }
      retryTimer = setTimeout(connectEvents, Math.min(1000 * 2 ** retry++, 15000));
    };
  }
  async function presence(id, online) {
    const contact = contactById(id);
    if (!contact) return;
    contact.online = online; render();
    if (!online || App.active) return;
    // Deliver messages queued while they were away, in the background if need be.
    const conversationId = await pairId(id);
    const queued = (await window.ChatStore.list()).some(record => record.conversationId === conversationId && record.direction === 'outgoing' && ['queued', 'sent'].includes(record.status));
    if (queued && (body.dataset.screen === 'list' || current?.id === id)) startChat(contact);
  }

  // ---------- Contacts and chat list ----------
  async function loadContacts() {
    if (!me) return;
    try {
      const online = new Set(contacts.filter(contact => contact.online).map(contact => contact.id));
      contacts = (await api('/api/contacts')).contacts.map(contact => ({ ...contact, online: contact.online || online.has(contact.id) }));
      render();
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
        const recent = last.get(await pairId(contact.id));
        sub.textContent = recent ? `${recent.direction === 'outgoing' ? 'You: ' : ''}${recent.text}` : contact.online ? 'Online' : 'Tap to chat';
        const time = document.createElement('time'); time.textContent = recent ? clock(recent.createdAt) : '';
        const open = document.createElement('button'); open.type = 'button'; open.className = 'row-button';
        open.setAttribute('aria-label', `Open conversation with ${contact.username}${contact.online ? ', online' : ''}`);
        open.onclick = () => openConversation(contact);
        row.append(time, open);
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
    if (!App.active) {
      App.openConversation({ conversationId, peerName: contact.username, online: contact.online });
      if (contact.online) startChat(contact);
    }
  }
  async function startChat(contact) {
    if (App.active) return;
    try {
      const session = await api(`/api/conversations/${contact.username}/session`, 'POST', { kind: 'chat' });
      if (App.active) return;
      await App.start({ ...session, kind: 'chat', conversationId: await pairId(contact.id), peerName: contact.username });
      if (current) updateHeader();
    } catch (error) { if (error.status !== 409) say('chats-status', error.message); }
  }
  async function call(kind) {
    if (!current) return;
    const contact = current;
    try {
      const conversationId = await pairId(contact.id);
      if (App.active) App.leave();
      const session = await api(`/api/conversations/${contact.username}/session`, 'POST', { kind });
      await App.start({ ...session, kind, conversationId, peerName: contact.username });
    } catch (error) { App.status(error.message); }
  }
  $('conv-voice').onclick = () => call('voice');
  $('conv-video').onclick = () => call('video');
  $('conv-back').onclick = () => {
    body.dataset.screen = 'list';
    // A connected chat keeps running in the background; an idle conversation just closes.
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
    current = null; App.closeConversation(); body.dataset.screen = 'list';
    say('chats-status', `Removed @${contact.username}. Messages on this device are unchanged.`);
    loadContacts();
  });

  // ---------- Incoming sessions ----------
  async function incoming(message) {
    const contact = contactById(message.from.id) || { ...message.from, state: 'mutual', online: true };
    const conversationId = await pairId(contact.id);
    if (message.kind === 'chat') {
      // Chat connects silently when it cannot disturb anything already on screen.
      if (App.active || (body.dataset.screen === 'conversation' && current?.id !== contact.id)) return;
      await App.start({ roomId: message.roomId, token: message.token, kind: 'chat', conversationId, peerName: contact.username });
      if (current) updateHeader();
      render(); return;
    }
    ringing = { ...message, contact, conversationId };
    say('incoming-avatar', initial(contact.username)); say('incoming-title', contact.username);
    say('incoming-kind', message.kind === 'video' ? 'Incoming video call' : 'Incoming voice call');
    $('incoming').hidden = false; $('incoming-accept').focus();
  }
  function hideRing() { $('incoming').hidden = true; }
  $('incoming-accept').onclick = async () => {
    const ring = ringing; ringing = null; hideRing();
    if (!ring) return;
    if (App.active) App.leave();
    current = ring.contact; body.dataset.screen = 'conversation'; updateHeader();
    await App.start({ roomId: ring.roomId, token: ring.token, kind: ring.kind, conversationId: ring.conversationId, peerName: ring.contact.username });
  };
  $('incoming-decline').onclick = async () => {
    const ring = ringing; ringing = null; hideRing();
    if (ring) { try { await api(`/api/conversations/${ring.contact.username}/decline`, 'POST', { roomId: ring.roomId }); } catch {} }
  };

  App.onInvite = invite => { if (!me) { $('register-invite').value = invite; $('register-panel').open = true; $('register-username').focus(); } };
  App.onEnd = () => { if (me) { if (current) updateHeader(); render(); } };
  App.onQueued = () => { if (current && contactById(current.id)?.online && !App.active) startChat(current); };

  // ---------- Start ----------
  (async () => {
    if (window.pendingAccountInvite) App.onInvite(window.pendingAccountInvite);
    try { signedIn((await api('/api/me')).user); }
    catch (error) { body.dataset.auth = error.status === 404 ? 'off' : 'out'; if (body.dataset.auth === 'out' && !App.roomId) $('invitation-panel').open = false; }
  })();
})();
