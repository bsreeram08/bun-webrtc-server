import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { IDBFactory } from 'fake-indexeddb';

const source = readFileSync(new URL('../../packages/signaling/public/chat-store.js', import.meta.url), 'utf8');
const PASSWORD = 'correct horse battery staple';
const NOW = 1800000000000;
const ROOM = 'r'.repeat(43);
type Message = { id: string; conversationId: string; direction: 'incoming' | 'outgoing'; text: string; createdAt: number; status: 'queued' | 'sent' | 'delivered' | 'uncertain'; expiresAt: number | null };
type Store = { put(message: unknown): Promise<Message>; list(): Promise<Message[]>; clear(): Promise<void>; setStatus(conversationId: string, id: string, status: string): Promise<boolean>; exportBackup(password: string): Promise<Blob>; importBackup(file: Blob, password: string): Promise<number> };
function fixture() {
  let now = NOW;
  class Clock extends Date { static override now() { return now; } }
  const indexedDB = new IDBFactory();
  const context: Record<string, any> = { indexedDB, crypto, Blob, TextEncoder, TextDecoder, Uint8Array, Date: Clock, atob, btoa };
  context.window = context;
  runInNewContext(source, context);
  return { store: context.ChatStore as Store, indexedDB, advance(ms: number) { now += ms; } };
}
function message(values: Partial<Message> = {}): Message {
  return { id: crypto.randomUUID(), conversationId: ROOM, direction: 'outgoing', text: 'Private hello 🌱', createdAt: NOW, status: 'queued', expiresAt: null, ...values };
}
const encoder = new TextEncoder();
const AAD = encoder.encode('webrtc-bun-chat-backup:1:PBKDF2-SHA256:600000:AES-256-GCM');
async function envelopeFor(payload: unknown, password = PASSWORD) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 }, key, encoder.encode(JSON.stringify(payload)));
  return new Blob([JSON.stringify({ format: 'webrtc-bun-chat-backup', version: 1, kdf: 'PBKDF2-SHA256', iterations: 600000, cipher: 'AES-256-GCM', salt: Buffer.from(salt).toString('base64'), iv: Buffer.from(iv).toString('base64'), ciphertext: Buffer.from(encrypted).toString('base64') })]);
}

describe('device-only chat storage', () => {
  test('late delivery updates cannot resurrect cleared or expired history', async () => {
    const f = fixture(), item = message();
    expect(await f.store.setStatus(item.conversationId, item.id, 'sent')).toBe(false);
    await f.store.put(item);
    expect(await f.store.setStatus(item.conversationId, item.id, 'delivered')).toBe(true);
    expect(await f.store.setStatus(item.conversationId, item.id, 'sent')).toBe(true);
    expect((await f.store.list())[0]!.status).toBe('delivered');
    await f.store.clear();
    expect(await f.store.setStatus(item.conversationId, item.id, 'delivered')).toBe(false);
    expect(await f.store.list()).toEqual([]);
    const expiring = message({ expiresAt: NOW + 1000 });
    await f.store.put(expiring); f.advance(1001);
    expect(await f.store.setStatus(expiring.conversationId, expiring.id, 'sent')).toBe(false);
    expect(await f.store.list()).toEqual([]);
    await expect(f.store.setStatus('bad-room', item.id, 'sent')).rejects.toThrow();
  });
  test('put/list persist, deduplicate, update status and preserve immutable expiry', async () => {
    const { store } = fixture();
    const item = message({ expiresAt: NOW + 3600000 });
    await store.put(item);
    await store.put({ ...item, status: 'delivered' });
    await store.put({ ...item, status: 'sent' });
    expect(await store.list()).toEqual([{ ...item, status: 'delivered' }]);
    await expect(store.put({ ...item, expiresAt: NOW + 7200000 })).rejects.toThrow('conflicting');
    await expect(store.put({ ...item, text: 'changed' })).rejects.toThrow('conflicting');
    await store.put({ ...item, conversationId: 's'.repeat(43) });
    expect((await store.list()).length).toBe(2);
    await store.clear();
    expect(await store.list()).toEqual([]);
  });

  test('invalid fields, oversized UTF-8 text, invalid expiry and secrets are rejected before persistence', async () => {
    const { store } = fixture();
    for (const item of [message({ text: '🧪'.repeat(1025) }), message({ id: 'not-a-uuid' }), message({ conversationId: 'bad' }), message({ createdAt: NaN }), message({ expiresAt: NOW }), message({ expiresAt: NOW + 31 * 86400000 }), { ...message(), token: 'secret-invitation' }, { ...message(), adminToken: 'secret-admin' }, { ...message(), turnSecret: 'secret-turn' }]) {
      await expect(store.put(item)).rejects.toThrow();
    }
    expect(await store.list()).toEqual([]);
  });

  test('expiry removes stored data and expired messages cannot be put again', async () => {
    const f = fixture(), item = message({ expiresAt: NOW + 1000 });
    await f.store.put(item); f.advance(1001);
    expect(await f.store.list()).toEqual([]);
    await expect(f.store.put(item)).rejects.toThrow('expired');
    const database = await new Promise<any>((resolve, reject) => { const r = f.indexedDB.open('webrtc-bun-chat-v1', 1); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const count = await new Promise<number>((resolve, reject) => { const r = database.transaction('messages').objectStore('messages').count(); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    expect(count).toBe(0); database.close();
  });

  test('capacity overflow and conflicting import are atomic', async () => {
    const { store } = fixture();
    const items = Array.from({ length: 2000 }, (_, index) => message({ text: `Message ${index}` }));
    expect(await store.importBackup(await envelopeFor({ version: 1, messages: items }), PASSWORD)).toBe(2000);
    await expect(store.put(message())).rejects.toThrow('2,000');
    const incoming = [message(), { ...items[0], text: 'conflicting text' }];
    await expect(store.importBackup(await envelopeFor({ version: 1, messages: incoming }), PASSWORD)).rejects.toThrow('conflicting');
    expect(await store.list()).toHaveLength(2000);
    expect((await store.list()).find(item => item.id === items[0]!.id)?.text).toBe('Message 0');
    await expect(store.importBackup(await envelopeFor({ version: 1, messages: [message()] }), PASSWORD)).rejects.toThrow('2,000');
    expect(await store.list()).toHaveLength(2000);
  }, 15000);
});

describe('encrypted portable backups', () => {
  test('restored outgoing history cannot replay and an old backup cannot alter live delivery state', async () => {
    const from = fixture().store, to = fixture().store;
    const queued = message(), sent = message({ status: 'sent' }), delivered = message({ status: 'delivered' });
    for (const item of [queued, sent, delivered]) await from.put(item);
    const backup = await from.exportBackup(PASSWORD);
    await to.put({ ...queued, status: 'delivered' });
    expect(await to.importBackup(backup, PASSWORD)).toBe(2);
    const restored = await to.list();
    expect(restored.find(item => item.id === queued.id)?.status).toBe('delivered');
    expect(restored.find(item => item.id === sent.id)?.status).toBe('uncertain');
    expect(restored.find(item => item.id === delivered.id)?.status).toBe('delivered');
    const fresh = fixture().store;
    await fresh.importBackup(backup, PASSWORD);
    expect((await fresh.list()).find(item => item.id === queued.id)?.status).toBe('uncertain');
    expect(await fresh.setStatus(queued.conversationId, queued.id, 'sent')).toBe(false);
    expect((await fresh.list()).find(item => item.id === queued.id)?.status).toBe('uncertain');
  }, 15000);
  test('real AES-GCM round-trip into a different device database and deduplication', async () => {
    const from = fixture().store, to = fixture().store;
    const items = [message({ status: 'delivered' }), message({ direction: 'incoming', expiresAt: NOW + 86400000 })];
    for (const item of items) await from.put(item);
    const backup = await from.exportBackup(PASSWORD), raw = await backup.text(), envelope = JSON.parse(raw);
    expect(raw).not.toContain('Private hello');
    expect(raw).not.toContain(items[0]!.id);
    expect(Object.keys(envelope).sort()).toEqual(['cipher', 'ciphertext', 'format', 'iterations', 'iv', 'kdf', 'salt', 'version']);
    expect(envelope.iterations).toBe(600000);
    expect(Buffer.from(envelope.iv, 'base64')).toHaveLength(12);
    expect(Buffer.from(envelope.salt, 'base64')).toHaveLength(16);
    expect(await to.importBackup(backup, PASSWORD)).toBe(2);
    expect(await to.importBackup(backup, PASSWORD)).toBe(0);
    expect((await to.list()).map(item => item.id).sort()).toEqual(items.map(item => item.id).sort());
    const second = JSON.parse(await (await from.exportBackup(PASSWORD)).text());
    expect(second.salt).not.toBe(envelope.salt);
    expect(second.iv).not.toBe(envelope.iv);
    expect(second.ciphertext).not.toBe(envelope.ciphertext);
  }, 15000);

  test('wrong password and tampering leave existing device data untouched', async () => {
    const { store } = fixture(); const item = message(); await store.put(item);
    const backup = await store.exportBackup(PASSWORD);
    await expect(store.importBackup(backup, 'incorrect password')).rejects.toThrow('Incorrect backup password or corrupted');
    const envelope = JSON.parse(await backup.text());
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64'); ciphertext[0] = ciphertext[0]! ^ 1;
    envelope.ciphertext = ciphertext.toString('base64');
    await expect(store.importBackup(new Blob([JSON.stringify(envelope)]), PASSWORD)).rejects.toThrow('Incorrect backup password or corrupted');
    expect(await store.list()).toEqual([item]);
  }, 15000);

  test('expired backup records never resurrect and exports omit expired messages', async () => {
    const f = fixture(), to = fixture();
    await f.store.put(message({ expiresAt: NOW + 1000 }));
    const backup = await f.store.exportBackup(PASSWORD);
    f.advance(1001); to.advance(1001);
    expect(await to.store.importBackup(backup, PASSWORD)).toBe(0);
    expect(await to.store.list()).toEqual([]);
    const empty = await f.store.exportBackup(PASSWORD);
    expect(await fixture().store.importBackup(empty, PASSWORD)).toBe(0);
  }, 15000);

  test('strict envelope limits reject malicious iterations, extra fields and malformed encodings', async () => {
    const { store } = fixture();
    await expect(store.exportBackup('too short')).rejects.toThrow('12 characters');
    await expect(store.exportBackup('x'.repeat(1025))).rejects.toThrow('1,024');
    await expect(store.importBackup(new Blob(['bad json']), PASSWORD)).rejects.toThrow('Invalid');
    await expect(store.importBackup(new Blob([new Uint8Array(10 * 1024 * 1024 + 1)]), PASSWORD)).rejects.toThrow('10 MiB');
    const envelope = JSON.parse(await (await store.exportBackup(PASSWORD)).text());
    for (const changed of [{ ...envelope, version: 2 }, { ...envelope, iterations: 1 }, { ...envelope, iterations: 1000000000 }, { ...envelope, token: 'secret' }, { ...envelope, iv: 'bad!' }, { ...envelope, salt: 'YQ==' }]) {
      await expect(store.importBackup(new Blob([JSON.stringify(changed)]), PASSWORD)).rejects.toThrow();
    }
  }, 15000);

  test('authenticated malformed payload is rejected wholly before any import transaction', async () => {
    const { store } = fixture(); const original = message(); await store.put(original);
    for (const payload of [{ version: 1, messages: [message(), { ...message(), token: 'never-store' }] }, { version: 1, messages: [], adminToken: 'never-store' }, { version: 1, messages: Array.from({ length: 2001 }, () => message()) }]) {
      await expect(store.importBackup(await envelopeFor(payload), PASSWORD)).rejects.toThrow();
      expect(await store.list()).toEqual([original]);
    }
  }, 15000);
});
