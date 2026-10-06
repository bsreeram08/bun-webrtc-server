'use strict';
// End-to-end message encryption: X3DH key agreement and the Double Ratchet, after Signal's
// published specifications (signal.org/docs/specifications/x3dh and /doubleratchet), on WebCrypto.
// Deviations (documented in docs/security.md): separate Ed25519 signing and X25519 DH identity keys
// instead of XEdDSA; AES-256-GCM (key and nonce from HKDF over the message key) instead of
// AES-CBC + HMAC; headers are authenticated, not encrypted. The server only relays opaque envelopes.
(() => {
  const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
  const MAX_SKIP = 1000, MAX_STORED_SKIPPED = 2000, MAX_SESSIONS = 4, PREKEY_BATCH = 100, MAX_CLAIMS_PER_CONTACT = 20;
  const B64 = /^[A-Za-z0-9_-]+$/, KEY_B64 = /^[A-Za-z0-9_-]{43}$/, SIG_B64 = /^[A-Za-z0-9_-]{86}$/;
  const subtle = () => globalThis.crypto.subtle;
  // Codes mark permanent, deterministic outcomes; callers may discard those. Anything uncoded is
  // treated as transient and retried.
  const coded = (code, text) => Object.assign(new Error(text), { code });

  // ---------- Encoding ----------
  function b64(bytes) {
    let binary = ''; const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let offset = 0; offset < view.length; offset += 8192) binary += String.fromCharCode(...view.subarray(offset, offset + 8192));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64(text, length) {
    if (typeof text !== 'string' || !B64.test(text)) throw new Error('Invalid encoding');
    const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
    if (length !== undefined && bytes.length !== length) throw new Error('Invalid key length');
    if (b64(bytes) !== text) throw new Error('Invalid encoding');
    return bytes;
  }
  const concat = (...parts) => { const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out; };
  const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

  // ---------- Primitives ----------
  async function supported() {
    try {
      const pair = await subtle().generateKey({ name: 'X25519' }, false, ['deriveBits']);
      await subtle().generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      await subtle().deriveBits({ name: 'X25519', public: pair.publicKey }, pair.privateKey, 256);
      return true;
    } catch { return false; }
  }
  // Private keys stay non-extractable CryptoKeys; only public halves are exported.
  // X25519 private keys are stored wrapped (AES-256-GCM) under a non-extractable wrapping key, not as
  // CryptoKey objects: Safari/WebKit stores X25519 CryptoKeys in IndexedDB as empty objects, so every reload
  // silently produced new keys. Wrapping keeps the private bytes out of plain storage; they are unwrapped
  // into non-extractable keys when used (cached per public key). Older pairs ({keyPair} from before, or
  // {priv} plain PKCS#8 from the first Safari fix) are still read.
  const privateKeys = new Map();
  let wrapping;
  function wrappingKey() {
    return wrapping ||= (async () => {
      const make = () => subtle().generateKey({ name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
      if (!globalThis.indexedDB) return make(); // Tests and non-browser hosts: an in-memory key for this process.
      const db = await new Promise((resolve, reject) => {
        const request = indexedDB.open('webrtc-bun-wrap-v1', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('kv');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(coded('storage', 'Could not open key storage'));
      });
      const read = () => new Promise((resolve, reject) => { const r = db.transaction('kv').objectStore('kv').get('key'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(coded('storage', 'Could not read key storage')); });
      let key = await read();
      if (!(key instanceof CryptoKey)) {
        const fresh = await make();
        // add() rather than put(): two tabs racing must agree on one key, so the loser re-reads the winner's.
        await new Promise(resolve => { const tx = db.transaction('kv', 'readwrite'); tx.objectStore('kv').add(fresh, 'key'); tx.oncomplete = tx.onerror = tx.onabort = () => resolve(); });
        key = await read();
        if (!(key instanceof CryptoKey)) throw coded('storage', 'This browser cannot keep encryption keys');
      }
      return key;
    })().catch(error => { wrapping = undefined; throw error; });
  }
  async function dhPair() {
    const keyPair = await subtle().generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await subtle().wrapKey('pkcs8', keyPair.privateKey, await wrappingKey(), { name: 'AES-GCM', iv }));
    return { wrapped, iv, pub: new Uint8Array(await subtle().exportKey('raw', keyPair.publicKey)) };
  }
  async function privateKeyOf(pair) {
    if (pair.keyPair?.privateKey) return pair.keyPair.privateKey;
    const id = b64(pair.pub);
    if (!privateKeys.has(id)) {
      let key;
      if (ArrayBuffer.isView(pair.wrapped) && ArrayBuffer.isView(pair.iv)) key = await subtle().unwrapKey('pkcs8', pair.wrapped, await wrappingKey(), { name: 'AES-GCM', iv: pair.iv }, { name: 'X25519' }, false, ['deriveBits']).catch(() => { throw coded('storage', 'Encryption key could not be unlocked in this browser'); });
      else if (ArrayBuffer.isView(pair.priv)) key = await subtle().importKey('pkcs8', pair.priv, { name: 'X25519' }, false, ['deriveBits']);
      else throw coded('storage', 'Encryption key is missing from this browser’s storage');
      if (privateKeys.size > 256) privateKeys.clear();
      privateKeys.set(id, key);
    }
    return privateKeys.get(id);
  }
  async function dh(pair, publicBytes) {
    const key = await subtle().importKey('raw', publicBytes, { name: 'X25519' }, false, []);
    return new Uint8Array(await subtle().deriveBits({ name: 'X25519', public: key }, await privateKeyOf(pair), 256));
  }
  async function hkdf(ikm, salt, info, length) {
    const key = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) }, key, length * 8));
  }
  async function hmac(keyBytes, data) {
    const key = await subtle().importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle().sign('HMAC', key, data));
  }
  const ZERO_SALT = new Uint8Array(32), F = new Uint8Array(32).fill(0xff);
  async function kdfRk(rk, dhOut) { const out = await hkdf(dhOut, rk, 'webrtc-bun-ratchet-v1', 64); return [out.slice(0, 32), out.slice(32)]; }
  async function kdfCk(ck) { return [await hmac(ck, new Uint8Array([0x02])), await hmac(ck, new Uint8Array([0x01]))]; } // [next chain key, message key]
  async function messageCipher(mk) {
    const out = await hkdf(mk, ZERO_SALT, 'webrtc-bun-message-v1', 44);
    return { key: await subtle().importKey('raw', out.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']), iv: out.slice(32) };
  }
  const spkMessage = pub => concat(encoder.encode('webrtc-bun-spk-v1'), pub);

  // ---------- Keys ----------
  async function generateIdentity() {
    const sign = await subtle().generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    const dhKey = await dhPair();
    return { sign, dh: dhKey, pub: { dh: b64(dhKey.pub), sign: b64(new Uint8Array(await subtle().exportKey('raw', sign.publicKey))) } };
  }
  async function generateSignedPreKey(identity, id, now = Date.now()) {
    const pair = await dhPair();
    const signature = new Uint8Array(await subtle().sign('Ed25519', identity.sign.privateKey, spkMessage(pair.pub)));
    return { id, pair, pub: b64(pair.pub), signature: b64(signature), createdAt: now };
  }
  async function verifySignedPreKey(identityPub, spk) {
    const key = await subtle().importKey('raw', unb64(identityPub.sign, 32), { name: 'Ed25519' }, false, ['verify']);
    if (!await subtle().verify('Ed25519', key, unb64(spk.signature, 64), spkMessage(unb64(spk.key, 32)))) throw new Error('Signed prekey signature is invalid');
  }
  const identityBytes = pub => concat(unb64(pub.dh, 32), unb64(pub.sign, 32));

  // ---------- Double Ratchet ----------
  const copy = state => ({ ...state, skipped: { ...state.skipped }, oldDhr: [...(state.oldDhr || [])] });
  // Only for keys provably used up (n below the chain position, or an earlier chain): such a message could never decrypt.
  const replayed = () => coded('replay', 'Replayed or duplicate message');
  async function ratchetStep(state, remote) {
    // Remember recent receiving chains so a late duplicate from one is recognised, not mistaken for a new chain.
    if (state.dhr) state.oldDhr = [...state.oldDhr, b64(state.dhr)].slice(-16);
    state.pn = state.ns; state.ns = 0; state.nr = 0; state.dhr = remote;
    [state.rk, state.ckr] = await kdfRk(state.rk, await dh(state.dhs, remote));
    state.dhs = await dhPair();
    [state.rk, state.cks] = await kdfRk(state.rk, await dh(state.dhs, remote));
  }
  async function skipUntil(state, until) {
    if (!state.ckr) return;
    if (until - state.nr > MAX_SKIP) throw coded('skip-limit', 'Too many skipped messages');
    while (state.nr < until) {
      let mk; [state.ckr, mk] = await kdfCk(state.ckr);
      state.skipped[`${b64(state.dhr)}:${state.nr}`] = mk; state.nr++;
    }
    const keys = Object.keys(state.skipped);
    for (const key of keys.slice(0, Math.max(0, keys.length - MAX_STORED_SKIPPED))) delete state.skipped[key];
  }
  // The exact bytes both sides authenticate: session associated data plus the canonical header.
  function canonical(packet) {
    const header = { v: 1, sid: packet.sid, h: { dh: packet.h.dh, pn: packet.h.pn, n: packet.h.n } };
    if (packet.x) header.x = { ik: { dh: packet.x.ik.dh, sign: packet.x.ik.sign }, ek: packet.x.ek, spk: packet.x.spk, opk: packet.x.opk };
    return header;
  }
  function parseEnvelope(envelope) {
    if (typeof envelope !== 'string' || envelope.length > 90000) throw coded('malformed', 'Invalid envelope');
    let packet;
    try { packet = JSON.parse(decoder.decode(unb64(envelope))); } catch { throw coded('malformed', 'Invalid envelope'); }
    const integer = value => Number.isSafeInteger(value) && value >= 0;
    if (!packet || packet.v !== 1 || !KEY_B64.test(packet.sid || '') || !packet.h || !KEY_B64.test(packet.h.dh || '') || !integer(packet.h.pn) || !integer(packet.h.n) || typeof packet.c !== 'string' || !B64.test(packet.c)) throw coded('malformed', 'Invalid envelope');
    if (packet.x !== undefined && (!packet.x || !KEY_B64.test(packet.x.ik?.dh || '') || !KEY_B64.test(packet.x.ik?.sign || '') || packet.x.ek !== packet.sid || !integer(packet.x.spk) || !(packet.x.opk === null || integer(packet.x.opk)))) throw coded('malformed', 'Invalid envelope');
    try { return { header: canonical(packet), ciphertext: unb64(packet.c) }; } catch { throw coded('malformed', 'Invalid envelope'); }
  }
  async function encrypt(session, plaintext) {
    if (!session.cks) throw new Error('Session cannot send yet');
    const state = copy(session);
    let mk; [state.cks, mk] = await kdfCk(state.cks);
    const header = canonical({ sid: state.sid, h: { dh: b64(state.dhs.pub), pn: state.pn, n: state.ns }, x: state.init || undefined });
    state.ns++;
    const { key, iv } = await messageCipher(mk);
    const ciphertext = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: concat(state.ad, encoder.encode(JSON.stringify(header))), tagLength: 128 }, key, plaintext));
    return { session: state, envelope: b64(encoder.encode(JSON.stringify({ ...header, c: b64(ciphertext) }))) };
  }
  async function decrypt(session, parsed) {
    const state = copy(session), { header, ciphertext } = parsed;
    const remote = unb64(header.h.dh, 32), skippedKey = `${header.h.dh}:${header.h.n}`;
    let mk = state.skipped[skippedKey];
    if (mk) delete state.skipped[skippedKey]; // Each message key is usable once.
    else {
      if (state.dhr && equal(remote, state.dhr)) { if (header.h.n < state.nr) throw replayed(); }
      else if (state.oldDhr.includes(header.h.dh)) throw replayed(); // An old chain whose key was already used.
      else { await skipUntil(state, header.h.pn); await ratchetStep(state, remote); }
      await skipUntil(state, header.h.n);
      [state.ckr, mk] = await kdfCk(state.ckr); state.nr++;
    }
    const { key, iv } = await messageCipher(mk);
    let plaintext;
    try { plaintext = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: concat(state.ad, encoder.encode(JSON.stringify(header))), tagLength: 128 }, key, ciphertext)); }
    catch { throw coded('auth', 'Message authentication failed'); }
    state.init = null; // The peer has this session now; stop resending the X3DH header.
    return { session: state, plaintext };
  }

  // ---------- X3DH ----------
  async function initiate(identity, bundle) {
    await verifySignedPreKey(bundle.identity, bundle.signedPreKey);
    const ek = await dhPair(), spk = unb64(bundle.signedPreKey.key, 32);
    const parts = [F, await dh(identity.dh, spk), await dh(ek, unb64(bundle.identity.dh, 32)), await dh(ek, spk)];
    if (bundle.oneTimePreKey) parts.push(await dh(ek, unb64(bundle.oneTimePreKey.key, 32)));
    const sk = await hkdf(concat(...parts), ZERO_SALT, 'webrtc-bun-x3dh-v1', 32);
    const dhs = await dhPair(); const [rk, cks] = await kdfRk(sk, await dh(dhs, spk));
    return {
      sid: b64(ek.pub), ad: concat(identityBytes(identity.pub), identityBytes(bundle.identity)), peer: bundle.identity,
      dhs, dhr: spk, rk, cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {},
      init: { ik: identity.pub, ek: b64(ek.pub), spk: bundle.signedPreKey.id, opk: bundle.oneTimePreKey ? bundle.oneTimePreKey.id : null },
    };
  }
  async function respond(identity, spk, opk, header) {
    const x = header.x, ek = unb64(x.ek, 32);
    const parts = [F, await dh(spk.pair, unb64(x.ik.dh, 32)), await dh(identity.dh, ek), await dh(spk.pair, ek)];
    if (opk) parts.push(await dh(opk.pair, ek));
    const sk = await hkdf(concat(...parts), ZERO_SALT, 'webrtc-bun-x3dh-v1', 32);
    return {
      sid: x.ek, ad: concat(identityBytes(x.ik), identityBytes(identity.pub)), peer: { dh: x.ik.dh, sign: x.ik.sign },
      dhs: spk.pair, dhr: null, rk: sk, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, init: null,
    };
  }

  // ---------- Safety numbers ----------
  async function fingerprint(username, identity) {
    let digest = concat(encoder.encode(`webrtc-bun-safety-v1:${username}:`), identityBytes(identity));
    for (let round = 0; round < 1024; round++) digest = new Uint8Array(await subtle().digest('SHA-512', concat(digest, identityBytes(identity))));
    let digits = '';
    for (let chunk = 0; chunk < 6; chunk++) {
      const value = digest.slice(chunk * 5, chunk * 5 + 5).reduce((sum, byte) => sum * 256 + byte, 0);
      digits += String(value % 100000).padStart(5, '0');
    }
    return digits;
  }
  async function safetyNumber(a, b) {
    const [first, second] = [a, b].sort((x, y) => x.username < y.username ? -1 : 1);
    const digits = await fingerprint(first.username, first.identity) + await fingerprint(second.username, second.identity);
    return digits.match(/.{5}/g).join(' ');
  }

  // ---------- Persistent box ----------
  /**
   * Account-level messaging on top of a key/value backend: get, put, delete, deletePrefix and
   * batch([{ put | delete }]) — the batch must be atomic (one IndexedDB transaction).
   * All work for one contact is serialized so concurrent messages cannot fork or roll back a ratchet.
   * A decrypted state is persisted only after the caller has stored the plaintext.
   */
  function box(rawBackend, hooks = {}) {
    // Any storage failure is transient ('storage'): the envelope stays on the server and is retried.
    const backend = Object.fromEntries(['get', 'put', 'delete', 'deletePrefix', 'batch'].map(name => [name, async (...args) => {
      try { return await rawBackend[name](...args); } catch (error) { throw Object.assign(new Error(`Key storage failed: ${error?.message || error}`), { code: 'storage' }); }
    }]));
    const locks = new Map();
    // An identity reset holds this barrier: every queued task waits, so nothing writes keys of the old identity
    // after (or while) they are erased.
    let barrier = Promise.resolve();
    // `inner` marks a lock taken by a task that is already running (decryptFrom's x3dh claim/commit): it must
    // not wait on the barrier, or a reset waiting for that task would deadlock with it.
    function serial(key, task, inner = false) {
      const previous = locks.get(key) || Promise.resolve(), gate = inner ? null : barrier;
      const next = Promise.all([previous.catch(() => {}), gate]).then(task);
      locks.set(key, next.catch(() => {}));
      return next;
    }
    async function identity() {
      let value = await backend.get('identity');
      if (!value) {
        value = await generateIdentity(); await backend.put('identity', value);
        // Read it back: a browser that cannot keep these keys must fail loudly, not mint new keys on every call.
        const kept = await backend.get('identity');
        if (!kept?.sign?.privateKey || !ArrayBuffer.isView(kept.dh?.wrapped) || kept.pub?.dh !== value.pub.dh) throw coded('storage', 'This browser cannot keep encryption keys');
      }
      return value;
    }
    /** Current signed prekey, rotated weekly. Replay records under a retired prekey are pruned with it. */
    async function prekeys(now = Date.now(), maxAge = 7 * 86400000) {
      return serial('prekeys', async () => {
        const me = await identity();
        let spks = await backend.get('spk') || { current: null, previous: null };
        let rotated = false;
        if (!spks.current || now - spks.current.createdAt > maxAge) {
          const retired = spks.previous;
          spks = { current: await generateSignedPreKey(me, (spks.current?.id ?? 0) + 1, now), previous: spks.current };
          await backend.put('spk', spks); rotated = true;
          // Initial messages under a retired signed prekey are rejected anyway, so its replay records can go.
          if (retired) { await backend.deletePrefix(`claim:${retired.id}:`); await backend.deletePrefix(`claims:${retired.id}:`); }
        }
        return { identity: me.pub, rotated, signedPreKey: { id: spks.current.id, key: spks.current.pub, signature: spks.current.signature } };
      });
    }
    async function oneTimePreKeys(count = PREKEY_BATCH) {
      return serial('prekeys', async () => {
        let next = await backend.get('opk-next') || 1;
        const out = [];
        for (let index = 0; index < count; index++, next++) {
          const pair = await dhPair();
          await backend.put(`opk:${next}`, { id: next, pair }); out.push({ id: next, key: b64(pair.pub) });
        }
        await backend.put('opk-next', next);
        return out;
      });
    }
    const sameIdentity = (a, b) => a.dh === b.dh && a.sign === b.sign;
    /**
     * Trust on first use. A different identity (either half) is recorded as a change: verification is
     * cleared and sending is blocked until the user accepts the new security code (acceptChange).
     */
    async function notePeer(contactId, pub) {
      const known = await backend.get(`peer:${contactId}`);
      if (known && sameIdentity(known.identity, pub)) return known;
      // Any change blocks sending until the user accepts it: a server that swaps in its own key must
      // never receive a message encrypted to that key before the user has seen the new code.
      const record = { identity: { dh: pub.dh, sign: pub.sign }, verified: false, changed: Boolean(known), blocked: Boolean(known) };
      await backend.put(`peer:${contactId}`, record);
      if (known) { await backend.delete(`sessions:${contactId}`); hooks.identityChanged?.(contactId, record); }
      return record;
    }
    async function assertSendable(contactId) {
      const peer = await backend.get(`peer:${contactId}`);
      if (peer?.blocked) throw Object.assign(new Error('Security code changed. Review it before sending.'), { code: 'identity-blocked' });
    }
    async function sessions(contactId) { return await backend.get(`sessions:${contactId}`) || { active: null, list: {}, order: [] }; }
    function remember(record, state, makeActive) {
      record = { ...record, list: { ...record.list, [state.sid]: state }, order: [...record.order.filter(sid => sid !== state.sid), state.sid] };
      while (record.order.length > MAX_SESSIONS) delete record.list[record.order.shift()];
      // While a rotation is pending nothing old may become active again: the next send must open a new session.
      if (makeActive || (!record.rotating && (!record.active || !record.list[record.active]))) record.active = state.sid;
      return record;
    }
    function encryptTo(contactId, plaintext, fetchBundle) {
      return serial(`contact:${contactId}`, async () => {
        await assertSendable(contactId);
        let record = await sessions(contactId);
        let state = record.active && record.list[record.active];
        if (record.rotating || !state || !state.cks) {
          const bundle = await fetchBundle();
          await notePeer(contactId, bundle.identity);
          await assertSendable(contactId);
          record = await sessions(contactId);
          state = { ...await initiate(await identity(), bundle), startedAt: Date.now() };
          // A manual or scheduled rotation: older sessions stay (bounded) so messages already in flight
          // still decrypt, and are dropped once the peer answers on this new one.
          if (record.rotating) record = { ...record, rotating: false, rotatedTo: state.sid };
        }
        const result = await encrypt(state, encoder.encode(JSON.stringify(plaintext)));
        await backend.put(`sessions:${contactId}`, remember(record, result.session, true));
        return result.envelope;
      });
    }
    /**
     * Decrypts, awaits handle(plaintext, info) to store it, and only then advances and persists the ratchet.
     * info.identityChanged marks a message that opened a session under a different identity than the one
     * recorded for this contact: the caller shows it alongside a security-code warning. handle() must be
     * idempotent by message id: a pending initial message may be processed again after a failure.
     *
     * Initial (X3DH) messages are claimed once per ephemeral key, under one global lock and only after they
     * authenticate: the server picks the sender, so one envelope must never open sessions for two contacts.
     * Each claim is its own key. It stays pending until the session, the completed claim and the one-time
     * prekey deletion are written in one atomic batch; from then on the same envelope is a replay forever
     * (until its signed prekey retires, after which it is rejected as unknown).
     *
     * Each contact may open at most MAX_CLAIMS_PER_CONTACT sessions per signed prekey; past that, only that
     * contact's initial messages are refused, so storage stays bounded (contacts × cap × two prekeys) and one
     * contact cannot stop others from reaching this device. Availability against a malicious server is out of
     * scope: it can always drop messages.
     */
    function claim(spkId, ek, contactId) {
      return serial('x3dh', async () => {
        const key = `claim:${spkId}:${ek}`, existing = await backend.get(key);
        if (existing && (existing.contact !== contactId || existing.done)) throw coded('replay', 'Replayed or duplicate message');
        if (existing) return;
        const counter = `claims:${spkId}:${contactId}`, count = await backend.get(counter) || 0;
        if (count >= MAX_CLAIMS_PER_CONTACT) throw coded('claim-limit', 'Too many new sessions from this contact');
        await backend.batch([{ put: key, value: { contact: contactId, done: false } }, { put: counter, value: count + 1 }]);
      }, true);
    }
    function decryptFrom(contactId, envelope, handle) {
      return serial(`contact:${contactId}`, async () => {
        const parsed = parseEnvelope(envelope), x = parsed.header.x;
        let record = await sessions(contactId), state = record.list[parsed.header.sid], fresh = false, spk = null;
        if (!state) {
          if (!x) throw coded('unknown-session', 'Unknown session');
          const me = await identity(), spks = await backend.get('spk');
          spk = [spks?.current, spks?.previous].find(value => value && value.id === x.spk);
          if (!spk) throw coded('unknown-spk', 'Unknown signed prekey');
          let opk = null;
          if (x.opk !== null) {
            opk = await backend.get(`opk:${x.opk}`);
            // A consumed one-time prekey is gone only after a completed claim, so this is a replay.
            if (!opk) throw coded('replay', 'One-time prekey already used');
          }
          state = { ...await respond(me, spk, opk, parsed.header), startedAt: Date.now() }; fresh = true;
        }
        const result = await decrypt(state, parsed); // Authenticate before claiming anything.
        if (fresh) await claim(spk.id, x.ek, contactId);
        const known = fresh ? await backend.get(`peer:${contactId}`) : null;
        const identityChanged = Boolean(fresh && known && !sameIdentity(known.identity, x.ik));
        let payload;
        try { payload = JSON.parse(decoder.decode(result.plaintext)); } catch { throw coded('invalid', 'Invalid message content'); }
        // handle() may answer { rotate: true } for a peer's session reset; the box applies it below, in the same
        // write as the ratchet, so no other code mutates this contact's sessions while the queue is held.
        const outcome = await handle(payload, { identityChanged, firstContact: Boolean(fresh && !known), identity: fresh ? { dh: x.ik.dh, sign: x.ik.sign } : null });
        // Record a new or changed identity only once a message under it authenticated.
        if (fresh) { await notePeer(contactId, x.ik); record = await sessions(contactId); }
        // A late message on an old session must not undo a rotation in progress. A fresh session from the
        // peer is itself new keys, so it simply becomes the one in use.
        const keepRotation = !fresh && (record.rotating || (record.rotatedTo && record.rotatedTo !== parsed.header.sid));
        let next = remember(fresh ? { ...record, rotating: false, rotatedTo: null } : record, result.session, !keepRotation);
        // The peer answered on the session we rotated to: the old chains are no longer needed.
        if (!fresh && record.rotatedTo === parsed.header.sid) next = { ...only(next, parsed.header.sid), rotatedTo: null };
        // The peer reset the session: keep only the new one it opened. A reset arriving on an older session is
        // ignored, so it can never make an old chain the survivor.
        if (outcome?.rotate === true && (fresh || record.rotatedTo === parsed.header.sid)) next = { ...only(next, parsed.header.sid), rotating: false, rotatedTo: null };
        const writes = [{ put: `sessions:${contactId}`, value: next }];
        if (fresh) {
          writes.push({ put: `claim:${spk.id}:${x.ek}`, value: { contact: contactId, done: true } });
          if (x.opk !== null) writes.push({ delete: `opk:${x.opk}` });
        }
        // The claim's x3dh lock keeps a concurrent claim for this ek from interleaving with completion.
        await (fresh ? serial('x3dh', () => backend.batch(writes), true) : backend.batch(writes));
      });
    }
    const only = (record, sid) => ({ active: sid, list: { [sid]: record.list[sid] }, order: [sid] });
    /** Starts a fresh session (new X3DH) with the next message; older sessions stay until the peer answers. */
    function rotate(contactId) {
      return serial(`contact:${contactId}`, async () => {
        const record = await sessions(contactId);
        await backend.put(`sessions:${contactId}`, { ...record, active: null, rotating: true, rotatedTo: null });
      });
    }
    /** When the active session started; sessions from before this was recorded count from first use here. */
    function sessionInfo(contactId) {
      return serial(`contact:${contactId}`, async () => {
        const record = await sessions(contactId), state = record.active && record.list[record.active];
        if (!state) return null;
        if (!state.startedAt) await backend.put(`sessions:${contactId}`, { ...record, list: { ...record.list, [state.sid]: { ...state, startedAt: Date.now() } } });
        return { sid: state.sid, startedAt: state.startedAt || Date.now() };
      });
    }
    /**
     * A new identity for this device: every session, prekey and replay record goes with the old one.
     * Pinned contact identities (peer:*) stay. Explicit only — contacts see a security-code change, and
     * changing it on a timer would teach people to ignore those warnings.
     */
    function resetIdentity() {
      // Close the gate first (synchronously), then wait for everything already queued on any key, so no
      // in-flight encrypt/decrypt can write a session of the old identity after the erase.
      const inFlight = [...locks.values()], prior = barrier;
      let release;
      barrier = new Promise(resolve => { release = resolve; });
      return (async () => {
        try {
          await prior; await Promise.all(inFlight.map(task => task.catch(() => {})));
          for (const prefix of ['sessions:', 'opk:', 'claim:', 'claims:']) await backend.deletePrefix(prefix);
          await backend.batch([{ delete: 'identity' }, { delete: 'spk' }, { delete: 'opk-next' }]);
        } finally { release(); }
      })();
    }
    async function safety(myUsername, contactId, theirUsername) {
      const me = await identity(), peer = await backend.get(`peer:${contactId}`);
      if (!peer) return null;
      return { number: await safetyNumber({ username: myUsername, identity: me.pub }, { username: theirUsername, identity: peer.identity }), verified: peer.verified, changed: peer.changed, blocked: Boolean(peer.blocked) };
    }
    async function setVerified(contactId, verified) {
      const peer = await backend.get(`peer:${contactId}`);
      if (peer) await backend.put(`peer:${contactId}`, { ...peer, verified, changed: verified ? false : peer.changed, blocked: false });
    }
    /** The user reviewed a changed security code and chose to keep messaging (without marking it verified). */
    async function acceptChange(contactId) {
      const peer = await backend.get(`peer:${contactId}`);
      if (peer) await backend.put(`peer:${contactId}`, { ...peer, changed: false, blocked: false });
    }
    return { identity, prekeys, oneTimePreKeys, encryptTo, decryptFrom, notePeer, safety, setVerified, acceptChange, rotate, sessionInfo, resetIdentity, peer: contactId => backend.get(`peer:${contactId}`), forget: contactId => backend.delete(`sessions:${contactId}`) };
  }

  // IndexedDB backend: CryptoKeys are stored by structured clone and never exported.
  function indexedDbBackend(name = 'webrtc-bun-signal-v1') {
    let opened;
    const db = () => opened ||= new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('kv');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => { opened = undefined; reject(new Error('Could not open encryption key storage.')); };
    });
    const run = async (mode, work) => {
      const database = await db();
      return new Promise((resolve, reject) => {
        const tx = database.transaction('kv', mode), request = work(tx.objectStore('kv'));
        tx.oncomplete = () => resolve(request.result); tx.onabort = tx.onerror = () => reject(tx.error || new Error('Key storage failed'));
      });
    };
    return {
      get: key => run('readonly', store => store.get(key)),
      put: (key, value) => run('readwrite', store => store.put(value, key)),
      delete: key => run('readwrite', store => store.delete(key)),
      deletePrefix: prefix => run('readwrite', store => store.delete(IDBKeyRange.bound(prefix, `${prefix}\uffff`))),
      batch: writes => run('readwrite', store => { let last; for (const write of writes) last = 'put' in write ? store.put(write.value, write.put) : store.delete(write.delete); return last; }),
      clear: () => run('readwrite', store => store.clear()),
    };
  }

  // Chat key rotation schedule: each side picks one; a conversation uses the shorter non-off interval.
  const DAY = 86400000, ROTATION_CHOICES = Object.freeze([0, DAY, 7 * DAY, 30 * DAY]);
  function rotationInterval(mine, theirs) {
    const set = [mine, theirs].filter(value => ROTATION_CHOICES.includes(value) && value > 0);
    return set.length ? Math.min(...set) : 0;
  }
  const api = { ROTATION_CHOICES, rotationInterval, MAX_CLAIMS_PER_CONTACT, supported, generateIdentity, generateSignedPreKey, verifySignedPreKey, initiate, respond, encrypt, decrypt, parseEnvelope, safetyNumber, box, indexedDbBackend, b64, unb64, MAX_SKIP };
  (typeof window !== 'undefined' ? window : globalThis).Signal = Object.freeze(api);
})();
