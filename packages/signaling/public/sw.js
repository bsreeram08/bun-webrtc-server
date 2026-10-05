'use strict';
const CACHE = 'private-conversations-shell-v5';
const ASSETS = ['/', '/app.js', '/account.js', '/alerts.js', '/vendor/simplewebauthn-browser.js', '/chat-store.js', '/verify.js', '/style.css', '/install.js', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS)));
  // Do not take over an active call. New code activates after old tabs close.
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(names => Promise.all(names.filter(name => name.startsWith('private-conversations-shell-') && name !== CACHE).map(name => caches.delete(name)))));
});
self.addEventListener('fetch', event => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.search || request.headers.has('authorization') || !ASSETS.includes(url.pathname)) return;
  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const response = await fetch(request);
      if (response.ok && response.type === 'basic' && !response.redirected) await cache.put(url.pathname, response.clone());
      return response;
    } catch (error) {
      const cached = await cache.match(url.pathname);
      if (cached) return cached;
      throw error;
    }
  })());
});

// Push payloads carry only { type, from, kind?, roomId? }; message text never travels by push.
const USER = /^[a-z0-9_]{3,20}$/, ROOM = /^[A-Za-z0-9_-]{43}$/;
function notification(data) {
  const from = typeof data?.from === 'string' && USER.test(data.from) ? data.from : null;
  const kind = data?.kind === 'video' ? 'video' : 'voice';
  const base = { icon: '/icon-192.png', badge: '/icon-192.png' };
  // Every push must show something (browsers penalise silent pushes), so unknown data gets a generic note.
  if (!from || !['message', 'call', 'missed'].includes(data.type)) return ['Private conversations', { ...base, body: 'Open the app to see what is new.', tag: 'generic' }];
  if (data.type === 'message') return [`New message from ${from}`, { ...base, body: 'Open the app to read it on this device.', tag: `message-${from}`, data: { open: from } }];
  if (data.type === 'missed') return [`Missed ${kind} call from ${from}`, { ...base, tag: `call-${from}`, data: { open: from } }];
  return [`Incoming ${kind} call from ${from}`, {
    ...base, body: 'Open the app to answer', tag: `call-${from}`, renotify: true, requireInteraction: true, vibrate: [400, 200, 400, 200, 400],
    // 'Open' only shows the ringing call in the app; answering always takes a tap on Accept there.
    actions: [{ action: 'open', title: 'Open' }, { action: 'decline', title: 'Decline' }],
    data: { open: from, call: kind, roomId: ROOM.test(data.roomId || '') ? data.roomId : null },
  }];
}
self.addEventListener('push', event => {
  let data = null;
  try { data = event.data?.json(); } catch {}
  const [title, options] = notification(data);
  event.waitUntil(self.registration.showNotification(title, options));
});
self.addEventListener('notificationclick', event => {
  const note = event.notification; note.close();
  const { open, call, roomId } = note.data || {};
  if (!USER.test(open || '')) return;
  if (event.action === 'decline') {
    if (roomId) event.waitUntil(fetch(`/api/conversations/${open}/decline`, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ roomId }) }).catch(() => {}));
    return;
  }
  // Only the contact's username travels in the URL; call credentials arrive over the app's own session.
  const params = new URLSearchParams({ open });
  if (call) params.set('call', call);
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const client = windows.find(value => new URL(value.url).origin === self.location.origin);
    if (client) { client.postMessage({ type: 'open', user: open, call: call || null }); return client.focus(); }
    return self.clients.openWindow(`/#${params}`);
  })());
});
