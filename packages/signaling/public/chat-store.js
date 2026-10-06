'use strict';
(() => {
  const MAX_MESSAGES = 2000, MAX_PER_CONVERSATION = 500, CLOCK_SKEW = 300000, MAX_FILE = 10 * 1024 * 1024, MAX_AGE = 30 * 86400000;
  const ITERATIONS = 600000, encoder = new TextEncoder();
  const FIELDS = ['id', 'conversationId', 'direction', 'text', 'createdAt', 'status', 'expiresAt'];
  // Optional rich content. `text` is always a readable fallback, so anything that cannot show the rich
  // form still shows the message. kind 'action' is a /me line; kind 'poll' carries {question, options}
  // and local tallies in `votes` ({me, peer}: option index or null) — 1:1 chats have two voters.
  const OPTIONAL = ['kind', 'poll', 'votes'], MAX_OPTIONS = 10, MAX_OPTION = 200;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const ROOM = /^[A-Za-z0-9_-]{43}$/;
  const FORMAT = 'webrtc-bun-chat-backup';
  const aad = encoder.encode(`${FORMAT}:1:PBKDF2-SHA256:${ITERATIONS}:AES-256-GCM`);
  let database;

  function exactObject(value, fields) {
    return value && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
  }
  const shortText = (value, max) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
  /** A poll's question and 2–10 options, each at most 200 characters; returns a clean copy or throws. */
  function cleanPoll(poll) {
    if (!exactObject(poll, ['question', 'options']) || !shortText(poll.question, MAX_OPTION) || !Array.isArray(poll.options) ||
        poll.options.length < 2 || poll.options.length > MAX_OPTIONS || !poll.options.every(option => shortText(option, MAX_OPTION))) throw new Error('Invalid poll.');
    return { question: poll.question, options: [...poll.options] };
  }
  const voteOk = (value, count) => value === null || Number.isSafeInteger(value) && value >= 0 && value < count;
  function cleanRich(message) {
    const extra = Object.keys(message).filter(key => !FIELDS.includes(key));
    if (extra.some(key => !OPTIONAL.includes(key))) throw new Error('Invalid chat message.');
    const out = {};
    if (message.kind === undefined) { if (message.poll !== undefined || message.votes !== undefined) throw new Error('Invalid chat message.'); return out; }
    if (message.direction === 'system' || !['action', 'poll'].includes(message.kind)) throw new Error('Invalid chat message.');
    out.kind = message.kind;
    if (message.kind === 'action') { if (message.poll !== undefined || message.votes !== undefined) throw new Error('Invalid chat message.'); return out; }
    out.poll = cleanPoll(message.poll);
    if (message.votes !== undefined) {
      const votes = message.votes;
      if (!votes || typeof votes !== 'object' || Array.isArray(votes) || Object.keys(votes).some(key => !['me', 'peer'].includes(key)) ||
          !Object.values(votes).every(value => voteOk(value, out.poll.options.length))) throw new Error('Invalid poll votes.');
      out.votes = { ...votes };
    }
    return out;
  }
  // 'system' rows (local notices such as a session reset) exist only on this device: only note() writes them
  // and stored records are read back with them allowed; put() and backup import never accept them.
  function validate(message, allowSystem = false) {
    if (!message || typeof message !== 'object' || Array.isArray(message) || !FIELDS.every(key => Object.hasOwn(message, key)) || typeof message.id !== 'string' || !UUID.test(message.id) ||
        typeof message.conversationId !== 'string' || !ROOM.test(message.conversationId) ||
        !(['incoming', 'outgoing'].includes(message.direction) || allowSystem && message.direction === 'system') || typeof message.text !== 'string' ||
        message.text.length === 0 || encoder.encode(message.text).byteLength > 4096 ||
        !Number.isSafeInteger(message.createdAt) || message.createdAt < 0 || message.createdAt > 8640000000000000 ||
        !['queued', 'sent', 'delivered', 'uncertain'].includes(message.status) ||
        !(message.expiresAt === null || Number.isSafeInteger(message.expiresAt) &&
          message.expiresAt > message.createdAt && message.expiresAt <= Math.min(8640000000000000, message.createdAt + MAX_AGE))) {
      throw new Error('Invalid chat message. Only message content and delivery metadata are allowed.');
    }
    const rich = cleanRich(message);
    // Explicitly construct the stored record: never serialize invitation tokens, keys or UI state.
    return { ...Object.fromEntries(FIELDS.map(key => [key, key === 'id' ? message.id.toLowerCase() : message[key]])), ...rich };
  }
  const expired = (message, now = Date.now()) => message.expiresAt !== null && message.expiresAt <= now;
  const key = message => `${message.conversationId}:${message.id.toLowerCase()}`;
  const sorted = messages => messages.sort((a, b) => a.createdAt - b.createdAt || key(a).localeCompare(key(b)));
  // Same message: identical fields, kind and poll (votes are local tallies and never conflict).
  const sameContent = (a, b) => FIELDS.every(field => field === 'status' || a[field] === b[field]) && a.kind === b.kind && JSON.stringify(a.poll) === JSON.stringify(b.poll);
  function combine(previous, next) {
    if (previous && !sameContent(previous, next)) {
      throw new Error('A duplicate message has conflicting content or expiration. Nothing was imported.');
    }
    const merged = previous?.votes ? { ...next, votes: previous.votes } : next;
    return previous?.status === 'delivered' ? { ...merged, status: 'delivered' } : merged;
  }
  function openDatabase() {
    if (!database) database = new Promise((resolve, reject) => {
      if (!globalThis.indexedDB) { reject(new Error('Device chat storage is unavailable in this browser.')); return; }
      const request = indexedDB.open('webrtc-bun-chat-v1', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('messages', { keyPath: ['conversationId', 'id'] });
      request.onerror = () => reject(new Error('Could not open device chat storage.'));
      request.onblocked = () => reject(new Error('Close other app windows and try device storage again.'));
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => { db.close(); database = undefined; };
        resolve(db);
      };
    }).catch(error => { database = undefined; throw error; });
    return database;
  }
  async function transaction(change) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite'), store = tx.objectStore('messages');
      let result, failure;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(failure || new Error('Could not save chats on this device. Storage may be full or unavailable.'));
      tx.onerror = () => { /* The abort event reports a single consistent storage error. */ };
      const request = store.getAll();
      request.onsuccess = () => {
        try {
          const active = new Map(), now = Date.now();
          for (const value of request.result) {
            const message = validate(value, true);
            if (expired(message, now)) store.delete([message.conversationId, message.id]);
            else active.set(key(message), message);
          }
          if (active.size > MAX_MESSAGES) throw new Error('Device chat storage exceeds the 2,000-message limit.');
          const update = change(active, now);
          if (update.clear) store.clear();
          for (const message of update.writes || []) store.put(message);
          result = update.result;
        } catch (error) { failure = error; tx.abort(); }
      };
    });
  }
  async function put(value) {
    const message = validate(value);
    if (expired(message)) throw new Error('This disappearing message has expired.');
    return transaction((active, now) => {
      if (expired(message, now)) throw new Error('This disappearing message has expired.');
      const previous = active.get(key(message));
      if (!previous && active.size >= MAX_MESSAGES) throw new Error('This device holds 2,000 messages. Clear chat history before adding more.');
      const next = combine(previous, message);
      return { writes: [next], result: next };
    });
  }
  const coded = (code, text) => Object.assign(new Error(text), { code });
  /**
   * Stores one decrypted incoming message, idempotent by id, using the same validation as every stored
   * record. Deterministic rejections carry a code so the caller acknowledges and discards the envelope
   * instead of retrying forever: 'invalid', 'conflict' (an id reused with other content),
   * 'conversation-full' (500 incoming messages from this conversation: only this sender is refused, so one
   * contact cannot crowd out the others) and 'full' (the 2,000-message device cap). Nothing is evicted.
   * Resolves to 'stored', 'duplicate' or 'expired'.
   */
  async function receive(conversationId, payload) {
    let message, createdAt = payload?.createdAt, expiresAt = payload?.expiresAt;
    // A sender whose clock runs ahead must not lose messages (nor pin them to the end of every list):
    // date them on arrival and keep their disappearing lifetime.
    const now = Date.now();
    if (Number.isSafeInteger(createdAt) && createdAt > now + CLOCK_SKEW) {
      if (Number.isSafeInteger(expiresAt)) expiresAt -= createdAt - now;
      createdAt = now;
    }
    const rich = payload?.kind === undefined ? {} : payload.kind === 'poll' ? { kind: 'poll', poll: payload.poll } : { kind: payload.kind };
    try { message = validate({ id: payload?.id, conversationId, direction: 'incoming', text: payload?.text, createdAt, status: 'delivered', expiresAt, ...rich }); }
    catch { throw coded('invalid', 'Invalid incoming message.'); }
    if (expired(message)) return 'expired';
    return transaction((active, now) => {
      if (expired(message, now)) return { result: 'expired' };
      const previous = active.get(key(message));
      if (previous) {
        if (!sameContent(previous, message)) throw coded('conflict', 'A message identifier was reused with different content.');
        return { result: 'duplicate' };
      }
      if (fromPeer(active, conversationId) >= MAX_PER_CONVERSATION) throw coded('conversation-full', 'This conversation holds 500 incoming messages.');
      if (active.size >= MAX_MESSAGES) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
      return { writes: [message], result: 'stored' };
    });
  }
  /**
   * Shape of a decrypted contact payload; message content itself is validated by receive().
   * 'rotate' asks the peer to drop old sessions; 'policy' carries the sender's rotation interval in ms
   * (only known choices take effect, see Signal.rotationInterval). Returns the payload type.
   */
  function checkPayload(payload) {
    const bad = () => coded('invalid', 'Invalid message');
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || payload.v !== 1 || typeof payload.id !== 'string' || !UUID.test(payload.id)) throw bad();
    const size = Object.keys(payload).length;
    switch (payload.type) {
      case 'receipt': case 'burn': if (size === 3) return payload.type; break;
      // Plain (6 keys), a /me action (+kind) or a poll (+kind, +poll); content is validated by receive().
      case 'message': if (size === 6 && !('kind' in payload) || size === 7 && payload.kind === 'action' || size === 8 && payload.kind === 'poll' && 'poll' in payload) return payload.type; break;
      case 'vote': if (size === 5 && typeof payload.poll === 'string' && UUID.test(payload.poll) && (payload.option === null || Number.isSafeInteger(payload.option) && payload.option >= 0 && payload.option < MAX_OPTIONS)) return payload.type; break;
      case 'rotate': if (size === 4 && ['manual', 'scheduled'].includes(payload.reason)) return payload.type; break;
      case 'policy': if (size === 4 && Number.isSafeInteger(payload.rotateEveryMs) && payload.rotateEveryMs >= 0) return payload.type; break;
    }
    throw bad();
  }
  /**
   * A local, never-sent system line (e.g. "secure session reset"), stored once per id. Peer-triggered lines
   * count toward the same caps as incoming messages, and one written within a minute of the previous
   * system line in that conversation replaces it instead of adding a row, so a contact cannot flood them.
   */
  async function note(conversationId, id, text) {
    const message = validate({ id, conversationId, direction: 'system', text, createdAt: Date.now(), status: 'delivered', expiresAt: null }, true);
    return transaction((active, now) => {
      if (active.has(key(message))) return { result: false };
      const recent = [...active.values()].filter(value => value.conversationId === conversationId && value.direction === 'system' && now - value.createdAt < 60000).at(-1);
      if (recent) return { writes: [{ ...recent, text: message.text, createdAt: Math.max(recent.createdAt, message.createdAt) }], result: false };
      if (fromPeer(active, conversationId) >= MAX_PER_CONVERSATION) throw coded('conversation-full', 'This conversation holds 500 incoming messages.');
      if (active.size >= MAX_MESSAGES) throw coded('full', 'This device holds 2,000 messages. Clear chat history to receive more.');
      return { writes: [message], result: true };
    });
  }
  /**
   * Records one voter's choice on a poll in this conversation (null clears it). One vote per voter,
   * changeable; a vote for an unknown poll or option is ignored. Updates in place, so votes add no rows.
   */
  async function vote(conversationId, pollId, voter, option) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof pollId !== 'string' || !UUID.test(pollId) || !['me', 'peer'].includes(voter)) throw coded('invalid', 'Invalid vote.');
    return transaction(active => {
      const poll = active.get(`${conversationId}:${pollId.toLowerCase()}`);
      if (poll?.kind !== 'poll' || !voteOk(option, poll.poll.options.length)) return { result: false };
      if ((poll.votes?.[voter] ?? null) === option) return { result: true };
      return { writes: [{ ...poll, votes: { ...poll.votes, [voter]: option } }], result: true };
    });
  }
  /** Rows a contact can cause on this device: their messages and the system lines their payloads add. */
  function fromPeer(active, conversationId) {
    let count = 0;
    for (const value of active.values()) if (value.conversationId === conversationId && value.direction !== 'outgoing') count++;
    return count;
  }
  /**
   * What to do with a mailbox envelope after trying to process it: acknowledge (the server deletes it)
   * or leave it for redelivery. Fails closed: only known permanent outcomes are acknowledged at once.
   * Storage errors and anything uncoded or unknown are retried, and acknowledged with a notice only
   * after `limit` attempts. Every discard except a true replay is reported.
   */
  const PERMANENT = { replay: null, full: 'storage-full', 'conversation-full': 'conversation-full', invalid: 'invalid', conflict: 'conflict', mismatch: 'mismatch', malformed: 'undecryptable', auth: 'undecryptable', 'skip-limit': 'undecryptable', 'unknown-session': 'undecryptable', 'unknown-spk': 'undecryptable', 'claim-limit': 'undecryptable' };
  function inboundDisposition(error, attempts, limit = 3) {
    if (!error) return { ack: true, notice: null };
    if (typeof error.code === 'string' && Object.hasOwn(PERMANENT, error.code)) return { ack: true, notice: PERMANENT[error.code] };
    return attempts >= limit ? { ack: true, notice: 'gave-up' } : { ack: false, notice: 'retrying' };
  }
  const list = () => transaction(active => ({ result: sorted([...active.values()]) }));
  async function setStatus(conversationId, id, status) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId) || typeof id !== 'string' || !UUID.test(id) ||
        !['queued', 'sent', 'delivered', 'uncertain'].includes(status)) throw new Error('Invalid message delivery update.');
    return transaction(active => {
      const previous = active.get(`${conversationId}:${id.toLowerCase()}`);
      // A late ACK or send completion must never recreate cleared or expired content.
      if (!previous) return { result: false };
      // Nor may an old send completion turn freshly restored history back into an outbound queue.
      if (previous.status === 'uncertain' && ['queued', 'sent'].includes(status)) return { result: false };
      return { writes: [{ ...previous, status: previous.status === 'delivered' ? 'delivered' : status }], result: true };
    });
  }
  // Burning one conversation deletes only its records, keyed by the room identifier.
  async function removeConversation(conversationId) {
    if (typeof conversationId !== 'string' || !ROOM.test(conversationId)) throw new Error('Invalid conversation.');
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new Error('Could not delete this conversation.'));
      tx.objectStore('messages').delete(IDBKeyRange.bound([conversationId], [conversationId, []]));
    });
  }
  // Clearing must also work if an older or corrupted record cannot be validated.
  async function clear() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('messages', 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new Error('Could not clear device chat storage.'));
      tx.objectStore('messages').clear();
    });
  }
  function passwordBytes(password) {
    if (typeof password !== 'string' || password.length < 12 || encoder.encode(password).byteLength > 1024) {
      throw new Error('Use a backup password of at least 12 characters and at most 1,024 UTF-8 bytes.');
    }
    return encoder.encode(password);
  }
  async function derive(password, salt) {
    if (!globalThis.crypto?.subtle) throw new Error('Encrypted backups require a browser with Web Crypto over HTTPS.');
    const material = await crypto.subtle.importKey('raw', passwordBytes(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  function base64(bytes) {
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    return btoa(binary);
  }
  function fromBase64(text, min, max) {
    if (typeof text !== 'string' || text.length % 4 !== 0 || text.length > Math.ceil(max / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
      throw new Error('Invalid encrypted backup encoding.');
    }
    const bytes = Uint8Array.from(atob(text), character => character.charCodeAt(0));
    if (bytes.length < min || bytes.length > max || base64(bytes) !== text) throw new Error('Invalid encrypted backup encoding.');
    return bytes;
  }
  async function exportBackup(password) {
    passwordBytes(password);
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptionKey = await derive(password, salt);
    const messages = (await list()).filter(message => message.direction !== 'system'); // Local notices stay local.
    const plaintext = encoder.encode(JSON.stringify({ version: 1, messages }));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, plaintext));
    const envelope = { format: FORMAT, version: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, cipher: 'AES-256-GCM', salt: base64(salt), iv: base64(iv), ciphertext: base64(ciphertext) };
    const blob = new Blob([JSON.stringify(envelope)], { type: 'application/json' });
    if (blob.size > MAX_FILE) throw new Error('Encrypted backup exceeds the 10 MiB file limit. Reduce local history before exporting.');
    return blob;
  }
  async function importBackup(file, password) {
    passwordBytes(password);
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > MAX_FILE || typeof file.text !== 'function') throw new Error('Choose an encrypted backup file no larger than 10 MiB.');
    const raw = await file.text();
    if (encoder.encode(raw).byteLength > MAX_FILE) throw new Error('Encrypted backup exceeds the 10 MiB file limit.');
    let envelope;
    try { envelope = JSON.parse(raw); } catch { throw new Error('Invalid encrypted backup file.'); }
    if (!exactObject(envelope, ['format', 'version', 'kdf', 'iterations', 'cipher', 'salt', 'iv', 'ciphertext']) ||
        envelope.format !== FORMAT || envelope.version !== 1 || envelope.kdf !== 'PBKDF2-SHA256' || envelope.iterations !== ITERATIONS || envelope.cipher !== 'AES-256-GCM') {
      throw new Error('Unsupported or invalid encrypted backup format.');
    }
    const salt = fromBase64(envelope.salt, 16, 16), iv = fromBase64(envelope.iv, 12, 12), ciphertext = fromBase64(envelope.ciphertext, 16, MAX_FILE);
    const encryptionKey = await derive(password, salt);
    let plaintext;
    try { plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, encryptionKey, ciphertext); }
    catch { throw new Error('Incorrect backup password or corrupted backup file. Nothing was imported.'); }
    let payload;
    try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
    catch { throw new Error('Invalid decrypted backup content. Nothing was imported.'); }
    if (!exactObject(payload, ['version', 'messages']) || payload.version !== 1 || !Array.isArray(payload.messages) || payload.messages.length > MAX_MESSAGES) {
      throw new Error('Backup must contain at most 2,000 valid messages. Nothing was imported.');
    }
    // Validate every record before opening the write transaction, including expired records.
    const incoming = payload.messages.map(message => validate(message)); // Never system rows.
    return transaction((active, now) => {
      const writes = new Map(); let count = 0;
      for (const message of incoming) {
        if (expired(message, now)) continue;
        const identity = key(message), previous = active.get(identity);
        combine(previous, message); // Reject conflicting immutable fields before accepting a duplicate.
        // Restored history is never an outbound queue. Existing live records win over old backups.
        if (previous) continue;
        const next = message.direction === 'outgoing' && message.status !== 'delivered' ? { ...message, status: 'uncertain' } : message;
        count++; active.set(identity, next);
        writes.set(identity, next);
      }
      if (active.size > MAX_MESSAGES) throw new Error('Import would exceed 2,000 device messages. Nothing was imported.');
      return { writes: [...writes.values()], result: count };
    });
  }
  window.ChatStore = Object.freeze({ put, list, clear, removeConversation, setStatus, exportBackup, importBackup, receive, note, vote, checkPayload, inboundDisposition, MAX_OPTIONS, isMessageId: id => typeof id === 'string' && UUID.test(id) });
})();
