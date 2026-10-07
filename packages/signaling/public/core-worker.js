// Runs the WebAssembly messaging core (crates/chatcore-wasm) for one account, off the page's main thread.
// Only the leader tab of an account starts this worker (see core.js), so there is exactly one writer.
//
// Storage: IndexedDB `webrtc-bun-core-v1-<userId>`, object store `kv`. Every value is sealed with AES-256-GCM
// under a non-extractable AES key kept in its own database (`webrtc-bun-core-key-v1`), with associated data
// binding it to the account and row (`core1|<userId>|<row key>`), so rows can't be read, edited or moved.
// No CryptoKey from the core is ever stored: WebKit stores X25519 CryptoKeys in IndexedDB as empty objects
// (the reason signal.js wraps its keys), so the core keeps raw key bytes and they only exist sealed on disk.
//
// Each call: the core runs synchronously in memory and returns the writes it made; they are sealed and
// applied in ONE IndexedDB transaction before the page gets the answer. If that fails the core is dropped
// and reloaded from disk on the next call, so memory never runs ahead of storage.
const KEY_DB = 'webrtc-bun-core-key-v1', MARKER = '__marker';
const encoder = new TextEncoder(), decoder = new TextDecoder();
let userId = null, ChatCore = null, core = null, sealKey = null, queue = Promise.resolve();

const coded = (code, message) => Object.assign(new Error(message), { code });
function request(req) {
  return new Promise((resolve, reject) => { req.onsuccess = () => resolve(req.result); req.onerror = () => reject(req.error); });
}
function openDb(name) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(coded('storage', 'Could not open key storage'));
  });
}
async function loadModule() {
  if (ChatCore) return;
  const manifest = await (await fetch('/core/manifest.json', { cache: 'no-cache' })).json();
  const module = await import(`/core/${manifest.js}`);
  await module.default({ module_or_path: `/core/${manifest.wasm}` });
  ChatCore = module.ChatCore;
}
/** The sealing key: one non-extractable AES key per browser profile, created once with add() so two tabs agree. */
async function sealingKey() {
  if (sealKey) return sealKey;
  const db = await openDb(KEY_DB);
  const read = () => request(db.transaction('kv').objectStore('kv').get('aes'));
  let key = await read();
  if (!(key instanceof CryptoKey)) {
    const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await new Promise(resolve => { const tx = db.transaction('kv', 'readwrite'); tx.objectStore('kv').add(fresh, 'aes'); tx.oncomplete = tx.onerror = tx.onabort = () => resolve(); });
    key = await read();
    if (!(key instanceof CryptoKey)) throw coded('storage', 'This browser cannot keep encryption keys');
  }
  return (sealKey = key);
}
const aad = row => encoder.encode(`core1|${userId}|${row}`);
async function seal(row, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return { iv, ct: new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(row) }, await sealingKey(), encoder.encode(text))) };
}
async function unseal(row, value) {
  if (!value || !ArrayBuffer.isView(value.iv) || !ArrayBuffer.isView(value.ct)) throw coded('storage', 'Key storage holds an unsealed row');
  try { return decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: value.iv, additionalData: aad(row) }, await sealingKey(), value.ct)); }
  catch { throw coded('storage', 'Key storage could not be unlocked'); }
}
/** Opens the account's core from disk. Fails closed: any row that doesn't authenticate refuses the whole store. */
async function open() {
  await loadModule();
  const db = await openDb(`webrtc-bun-core-v1-${userId}`);
  const tx = db.transaction('kv'), store = tx.objectStore('kv');
  const [keys, values] = await Promise.all([request(store.getAllKeys()), request(store.getAll())]);
  const rows = {};
  let marker = false;
  for (let index = 0; index < keys.length; index++) {
    const text = await unseal(keys[index], values[index]);
    if (keys[index] === MARKER) { marker = text === '{"v":1}'; continue; }
    rows[keys[index]] = JSON.parse(text);
  }
  // Rows without the marker were not written by this code (or the marker was deleted): refuse, never start over.
  if (keys.length && !marker) throw coded('storage', 'Key storage is missing its marker');
  core = { db, chat: new ChatCore(JSON.stringify(rows), marker), marker };
}
async function persist(writes) {
  if (!writes.length) return;
  // Seal first: an IndexedDB transaction would auto-commit across the awaits of WebCrypto.
  const sealed = [];
  if (!core.marker) sealed.push([MARKER, await seal(MARKER, '{"v":1}')]);
  for (const write of writes) sealed.push('put' in write ? [write.put, await seal(write.put, JSON.stringify(write.value))] : [write.delete, null]);
  await new Promise((resolve, reject) => {
    const tx = core.db.transaction('kv', 'readwrite'), store = tx.objectStore('kv');
    for (const [row, value] of sealed) value ? store.put(value, row) : store.delete(row);
    tx.oncomplete = resolve; tx.onerror = tx.onabort = () => reject(tx.error || new Error('write failed'));
  });
  core.marker = true;
}
async function call(command) {
  if (!core) await open();
  const result = JSON.parse(core.chat.call(JSON.stringify(command)));
  try { await persist(result.writes || []); }
  catch {
    // Disk and memory may now differ: drop the core; the next call reloads what was really saved.
    core = null;
    return { error: 'Key storage failed: could not save', code: 'storage' };
  }
  delete result.writes;
  return result;
}
self.onmessage = event => {
  const { id, op } = event.data || {};
  queue = queue.then(async () => {
    try {
      if (op === 'open') { if (userId && userId !== event.data.userId) throw new Error('worker serves another account'); userId = event.data.userId; if (!core) await open(); return { ok: true }; }
      if (op === 'call') return await call(event.data.command);
      throw new Error('unknown op');
    } catch (error) {
      if (op === 'call' || op === 'open') core = error.code === 'storage' ? null : core;
      return { error: error.message || String(error), code: error.code ?? null };
    }
  }).then(result => self.postMessage({ id, result }));
};
