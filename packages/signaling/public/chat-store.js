'use strict';
(() => {
  const MAX_MESSAGES = 2000, MAX_FILE = 10 * 1024 * 1024, MAX_AGE = 30 * 86400000;
  const ITERATIONS = 600000, encoder = new TextEncoder();
  const FIELDS = ['id', 'conversationId', 'direction', 'text', 'createdAt', 'status', 'expiresAt'];
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const ROOM = /^[A-Za-z0-9_-]{43}$/;
  const FORMAT = 'webrtc-bun-chat-backup';
  const aad = encoder.encode(`${FORMAT}:1:PBKDF2-SHA256:${ITERATIONS}:AES-256-GCM`);
  let database;

  function exactObject(value, fields) {
    return value && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
  }
  function validate(message) {
    if (!exactObject(message, FIELDS) || typeof message.id !== 'string' || !UUID.test(message.id) ||
        typeof message.conversationId !== 'string' || !ROOM.test(message.conversationId) ||
        !['incoming', 'outgoing'].includes(message.direction) || typeof message.text !== 'string' ||
        message.text.length === 0 || encoder.encode(message.text).byteLength > 4096 ||
        !Number.isSafeInteger(message.createdAt) || message.createdAt < 0 || message.createdAt > 8640000000000000 ||
        !['queued', 'sent', 'delivered', 'uncertain'].includes(message.status) ||
        !(message.expiresAt === null || Number.isSafeInteger(message.expiresAt) &&
          message.expiresAt > message.createdAt && message.expiresAt <= Math.min(8640000000000000, message.createdAt + MAX_AGE))) {
      throw new Error('Invalid chat message. Only message content and delivery metadata are allowed.');
    }
    // Explicitly construct the stored record: never serialize invitation tokens, keys or UI state.
    return Object.fromEntries(FIELDS.map(key => [key, key === 'id' ? message.id.toLowerCase() : message[key]]));
  }
  const expired = (message, now = Date.now()) => message.expiresAt !== null && message.expiresAt <= now;
  const key = message => `${message.conversationId}:${message.id.toLowerCase()}`;
  const sorted = messages => messages.sort((a, b) => a.createdAt - b.createdAt || key(a).localeCompare(key(b)));
  function combine(previous, next) {
    if (previous && FIELDS.some(field => field !== 'status' && previous[field] !== next[field])) {
      throw new Error('A duplicate message has conflicting content or expiration. Nothing was imported.');
    }
    return previous?.status === 'delivered' ? { ...next, status: 'delivered' } : next;
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
            const message = validate(value);
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
    const messages = await list();
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
    const incoming = payload.messages.map(validate);
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
  window.ChatStore = Object.freeze({ put, list, clear, setStatus, exportBackup, importBackup });
})();
