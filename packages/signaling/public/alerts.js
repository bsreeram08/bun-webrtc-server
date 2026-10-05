'use strict';
// Ringtones and push notifications. Tones are synthesized with Web Audio (no audio files);
// push subscriptions go to this server, and pushes carry only the event type and a username.
(() => {
  const $ = id => document.getElementById(id);
  const store = { get: key => { try { return localStorage.getItem(key); } catch { return null; } }, set: (key, value) => { try { if (value === null) localStorage.removeItem(key); else localStorage.setItem(key, value); } catch {} } };
  const SILENT = 'ring-silent-v1', OFF = 'notify-off-v1', DISMISSED = 'notify-banner-dismissed-v1';

  // ---------- Ringtones ----------
  let audio = null, mode = null, loop, nodes = [];
  function context() {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) return null;
    if (!audio) audio = new Context();
    // Browsers start audio only after a user gesture; resume() is a no-op once allowed.
    if (audio.state === 'suspended') audio.resume().catch(() => {});
    return audio;
  }
  function tone(frequencies, start, duration, level) {
    for (const frequency of frequencies) {
      const oscillator = audio.createOscillator(), gain = audio.createGain();
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0, start);
      gain.gain.linearRampToValueAtTime(level, start + 0.02);
      gain.gain.setValueAtTime(level, start + duration - 0.03);
      gain.gain.linearRampToValueAtTime(0, start + duration);
      oscillator.connect(gain).connect(audio.destination);
      oscillator.start(start); oscillator.stop(start + duration);
      nodes.push(oscillator);
      oscillator.onended = () => { nodes = nodes.filter(node => node !== oscillator); };
    }
  }
  const patterns = {
    // Two short two-tone bursts every 3 s, like a phone ringing.
    incoming: { every: 3000, play: at => { tone([440, 480], at, 0.4, 0.12); tone([440, 480], at + 0.6, 0.4, 0.12); }, vibrate: [400, 200, 400] },
    // Quieter single burst every 4 s while the other phone rings.
    outgoing: { every: 4000, play: at => tone([440, 480], at, 1.6, 0.05) },
  };
  function start(kind) {
    stop();
    if (Ring.silent) return;
    mode = kind;
    const pattern = patterns[kind];
    const tick = () => {
      if (mode !== kind) return;
      if (context()) pattern.play(audio.currentTime + 0.05);
      if (pattern.vibrate) navigator.vibrate?.(pattern.vibrate);
      loop = setTimeout(tick, pattern.every);
    };
    tick();
  }
  function stop() {
    mode = null; clearTimeout(loop);
    for (const node of nodes) { try { node.stop(); } catch {} }
    nodes = [];
    try { navigator.vibrate?.(0); } catch {}
  }
  const Ring = {
    incoming: () => start('incoming'), outgoing: () => start('outgoing'), stop,
    /** Call from a user gesture so later rings are allowed to play. */
    unlock: () => { if (!Ring.silent) context(); },
    get silent() { return store.get(SILENT) === '1'; },
    set silent(value) { store.set(SILENT, value ? '1' : null); if (value) stop(); },
    get state() { return { mode, audio: audio ? audio.state : 'none' }; },
  };
  document.addEventListener('pointerdown', () => Ring.unlock(), { once: true, capture: true });

  // ---------- Push notifications ----------
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const standalone = navigator.standalone === true || window.matchMedia?.('(display-mode: standalone)').matches;
  const supported = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  let signedIn = false;
  const say = text => { if ($('notify-status')) $('notify-status').textContent = text; };
  async function api(path, method, payload) {
    const response = await fetch(path, { method, cache: 'no-store', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Notifications are unavailable right now.');
    return data;
  }
  const keyBytes = base64 => Uint8Array.from(atob(base64.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(base64.length / 4) * 4, '=')), character => character.charCodeAt(0));
  async function subscribe() {
    const { publicKey } = await api('/api/push/key', 'GET');
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription() || await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(publicKey) });
    await api('/api/push/subscribe', 'POST', { subscription: subscription.toJSON() });
  }
  async function enable() {
    store.set(OFF, null); store.set(DISMISSED, '1');
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') { render(); say('Notifications are blocked. Allow them in your browser settings to turn them on.'); return; }
    try { await subscribe(); say('Notifications are on for this device.'); } catch (error) { say(error.message || 'Could not turn on notifications.'); }
    render();
  }
  async function disable() {
    store.set(OFF, '1');
    try {
      const subscription = await (await navigator.serviceWorker.ready).pushManager.getSubscription();
      if (subscription) { await api('/api/push/subscribe', 'DELETE', { endpoint: subscription.endpoint }).catch(() => {}); await subscription.unsubscribe(); }
      say('Notifications are off for this device.');
    } catch { say('Could not turn off notifications.'); }
    render();
  }
  function render() {
    const banner = $('notify-banner'), toggle = $('notify-toggle');
    if (!banner || !toggle) return;
    const permission = supported ? Notification.permission : 'unsupported';
    const needsHomeScreen = ios && !standalone;
    toggle.checked = permission === 'granted' && store.get(OFF) !== '1';
    toggle.disabled = !supported || permission === 'denied';
    $('ring-silent').checked = Ring.silent;
    if (needsHomeScreen) say('On iPhone, notifications work after you add this app to your Home Screen (Share → Add to Home Screen) and open it from there.');
    else if (!supported) say('This browser cannot show notifications.');
    else if (permission === 'denied') say('Notifications are blocked in your browser settings.');
    const showBanner = signedIn && store.get(DISMISSED) !== '1' && store.get(OFF) !== '1' && (needsHomeScreen || (supported && permission === 'default'));
    banner.hidden = !showBanner;
    $('notify-banner-text').textContent = needsHomeScreen
      ? 'To get message and call notifications on iPhone, tap Share → Add to Home Screen, then open the app from there.'
      : 'Get notified about messages and calls, even when this app is closed.';
    $('notify-enable').hidden = needsHomeScreen;
  }
  $('notify-enable').onclick = () => enable();
  $('notify-dismiss').onclick = () => { store.set(DISMISSED, '1'); render(); };
  $('notify-toggle').onchange = () => { if ($('notify-toggle').checked) enable(); else disable(); };
  $('ring-silent').onchange = () => { Ring.silent = $('ring-silent').checked; };

  // The service worker forwards notification taps to an already-open app.
  navigator.serviceWorker?.addEventListener('message', event => {
    const data = event.data;
    if (data?.type === 'open' && typeof data.user === 'string') Alerts.onOpen?.({ user: data.user, call: Boolean(data.call) });
  });

  const Alerts = {
    Ring,
    signedIn() {
      signedIn = true; render();
      // Re-register this device after each sign-in (sign-out removes it on the server).
      if (supported && Notification.permission === 'granted' && store.get(OFF) !== '1') subscribe().catch(() => {});
    },
    signedOut() { signedIn = false; render(); },
    onOpen: null,
  };
  window.Ring = Ring; window.Alerts = Alerts;
  render();
})();
