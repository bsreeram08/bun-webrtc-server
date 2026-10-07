'use strict';
// The page's handle on the WebAssembly messaging core (core-worker.js), shaped like signal.js's box so
// account.js can use either. Enabled per browser with localStorage['core-backend'] = 'wasm' (or ?core=wasm).
//
// One writer per account: tabs of the same account elect a leader with the Web Locks API. The leader runs
// the worker; other tabs send their calls to it over a BroadcastChannel. When the leader tab closes, the
// lock passes to another tab, which starts its own worker from what was saved.
(() => {
  const TIMEOUT = 15000;
  const tab = crypto.randomUUID();
  const accounts = new Map();
  const failure = result => Object.assign(new Error(result.error || 'Messaging core failed'), result.code ? { code: result.code } : {});

  function account(userId) {
    if (accounts.has(userId)) return accounts.get(userId);
    const channel = new BroadcastChannel(`chatcore:${userId}`);
    const waiting = new Map();
    let worker = null, nextId = 0, leader = false, opened = null;
    const state = { leader: () => leader };

    function settle(id, result) { const entry = waiting.get(id); if (entry) { waiting.delete(id); clearTimeout(entry.timer); entry.resolve(result); } }
    function pending(id) {
      return new Promise(resolve => {
        const timer = setTimeout(() => { waiting.delete(id); resolve({ error: 'Messaging core did not answer', code: null }); }, TIMEOUT);
        waiting.set(id, { resolve, timer });
      });
    }
    function toWorker(message) {
      const id = `${tab}:${++nextId}`;
      const answer = pending(id);
      worker.postMessage({ ...message, id });
      return answer;
    }
    function becomeLeader() {
      leader = true;
      worker = new Worker('/core-worker.js', { type: 'module' });
      worker.onmessage = event => settle(event.data.id, event.data.result);
      opened = toWorker({ op: 'open', userId });
    }
    // Followers' calls arrive here; only the leader answers.
    channel.onmessage = async event => {
      const message = event.data || {};
      if (message.type === 'request' && leader) {
        await opened;
        const result = await toWorker({ op: 'call', command: message.command });
        channel.postMessage({ type: 'response', id: message.id, to: message.from, result });
      } else if (message.type === 'response' && message.to === tab) settle(message.id, message.result);
    };
    // Decide before the first call: take the lock if it's free, otherwise follow and queue to take over. The
    // lock is held until this page goes away (the promise never settles); then the next waiting tab takes it.
    // (A tab's own BroadcastChannel never hears its own messages, so a call must not go out before this.)
    const lockName = `chatcore:${userId}`, hold = () => new Promise(() => {});
    const decided = !navigator.locks ? (becomeLeader(), Promise.resolve()) : new Promise(resolve => {
      navigator.locks.request(lockName, { ifAvailable: true }, lock => {
        if (lock) { becomeLeader(); resolve(); return hold(); }
        resolve();
        navigator.locks.request(lockName, () => { becomeLeader(); return hold(); });
      });
    });

    state.call = async command => {
      await decided;
      if (leader) {
        const open = await opened;
        if (open?.error) { opened = toWorker({ op: 'open', userId }); throw failure(open); }
        return toWorker({ op: 'call', command });
      }
      const id = `${tab}:${++nextId}`;
      const answer = pending(id);
      channel.postMessage({ type: 'request', id, from: tab, command });
      return answer;
    };
    accounts.set(userId, state);
    return state;
  }

  /** A signal.js-compatible box backed by the WebAssembly core. */
  function box(userId, hooks = {}) {
    const state = account(userId);
    const run = async command => { const result = await state.call(command); if ('error' in result) throw failure(result); return result.ok; };
    const same = (a, b) => a && b && a.dh === b.dh && a.sign === b.sign;
    const changedFrom = async (contactId, before) => {
      if (!before) return;
      const after = await run({ cmd: 'peer', contact: contactId });
      if (after && !same(before.identity, after.identity)) hooks.identityChanged?.(contactId, after);
    };
    return {
      backend: 'wasm',
      isLeader: () => state.leader(),
      identity: async () => ({ pub: await run({ cmd: 'identity' }) }),
      prekeys: (now = Date.now(), maxAge) => run({ cmd: 'prekeys', now, ...(maxAge ? { maxAge } : {}) }),
      oneTimePreKeys: count => run({ cmd: 'opks', count }),
      async encryptTo(contactId, payload, fetchBundle) {
        const plaintext = JSON.stringify(payload), before = await run({ cmd: 'peer', contact: contactId });
        try {
          let result = await run({ cmd: 'encrypt', contact: contactId, plaintext });
          if (result.needsBundle) result = await run({ cmd: 'encrypt', contact: contactId, plaintext, bundle: await fetchBundle() });
          return result.envelope;
        } finally { await changedFrom(contactId, before).catch(() => {}); }
      },
      // Two-phase, like signal.js: decrypt, let the caller store it, then commit (or abort if storing failed).
      async decryptFrom(contactId, envelope, handle) {
        const decrypted = await run({ cmd: 'decrypt', contact: contactId, envelope, commit: false });
        let outcome;
        try { outcome = await handle(JSON.parse(decrypted.plaintext), { identityChanged: decrypted.identityChanged, firstContact: decrypted.firstContact, identity: decrypted.identity }); }
        catch (error) { await run({ cmd: 'abort', pendingId: decrypted.pendingId }).catch(() => {}); throw error; }
        const recorded = await run({ cmd: 'commit', pendingId: decrypted.pendingId, rotate: outcome?.rotate === true });
        if (recorded === true) hooks.identityChanged?.(contactId, await run({ cmd: 'peer', contact: contactId }));
      },
      async notePeer(contactId, identity) {
        const before = await run({ cmd: 'peer', contact: contactId });
        const record = await run({ cmd: 'notePeer', contact: contactId, identity });
        if (before && !same(before.identity, record.identity)) hooks.identityChanged?.(contactId, record);
        return record;
      },
      safety: (me, contactId, them) => run({ cmd: 'safety', me, contact: contactId, them }),
      setVerified: (contactId, verified) => run({ cmd: 'setVerified', contact: contactId, verified }),
      acceptChange: contactId => run({ cmd: 'acceptChange', contact: contactId }),
      peer: contactId => run({ cmd: 'peer', contact: contactId }),
      forget: contactId => run({ cmd: 'forget', contact: contactId }),
      rotate: contactId => run({ cmd: 'rotate', contact: contactId }),
      sessionInfo: contactId => run({ cmd: 'sessionInfo', contact: contactId }),
      resetIdentity: () => run({ cmd: 'resetIdentity' }),
    };
  }

  const supported = () => typeof WebAssembly === 'object' && typeof Worker === 'function' && typeof BroadcastChannel === 'function' && Boolean(globalThis.indexedDB && crypto?.subtle);
  function enabled() {
    try { if (new URLSearchParams(location.search).get('core') === 'wasm') return true; } catch {}
    try { return localStorage.getItem('core-backend') === 'wasm'; } catch { return false; }
  }
  window.Core = Object.freeze({ box, supported, enabled });
})();
