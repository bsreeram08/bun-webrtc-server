import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { openDatabase } from '../../packages/signaling/accounts';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
let dataDir: string, app: ReturnType<typeof startSignaling>;
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'mailbox-'));
    app = startSignaling({ adminToken: 'mailbox-test-admin-secret-00000000000000000', origin, port: 0, dataDir });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });

const request = (path: string, method: string, cookie: string, body?: unknown) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(method !== 'GET' ? { Origin: origin } : {}) }, body: body === undefined ? undefined : JSON.stringify(body),
});
function user(name: string) { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; }
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    expect((await request('/api/contacts', 'POST', a.cookie, { username: b.username })).status).toBe(202);
    expect((await request(`/api/contacts/${a.username}/accept`, 'POST', b.cookie, {})).status).toBe(200);
}
const key = () => randomBytes(32).toString('base64url');
const keys = (count = 3, start = 1) => ({ identity: { dh: key(), sign: key() }, signedPreKey: { id: 1, key: key(), signature: randomBytes(64).toString('base64url') }, oneTimePreKeys: Array.from({ length: count }, (_, index) => ({ id: start + index, key: key() })) });
const envelope = (bytes = 64) => randomBytes(bytes).toString('base64url');
function events(cookie: string) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers: { Origin: origin, Cookie: cookie } } as any);
    const inbox: any[] = []; const waiters: ((value: any) => void)[] = [];
    socket.onmessage = event => { const message = JSON.parse(String(event.data)); const waiter = waiters.shift(); if (waiter) waiter(message); else inbox.push(message); };
    const raw = () => inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((resolve, reject) => { const timer = setTimeout(() => reject(new Error('timeout')), 2000); waiters.push(value => { clearTimeout(timer); resolve(value); }); });
    const next = async (type: string) => { for (;;) { const message = await raw(); if (message.type === type) return message; } };
    return { socket, next, opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })), closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })) };
}

describe('prekey directory', () => {
    test('uploads are validated and bundles go only to mutual contacts, consuming one one-time prekey each', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        expect((await request('/api/keys', 'PUT', bob.cookie, { identity: { dh: 'short', sign: key() } })).status).toBe(400);
        expect((await request('/api/keys', 'PUT', bob.cookie, { identity: { dh: key(), sign: key() } })).status).toBe(400); // first upload needs a signed prekey
        const uploaded = keys(2);
        expect((await request('/api/keys', 'PUT', bob.cookie, uploaded)).status).toBe(200);
        expect((await request('/api/keys/bob', 'GET', carol.cookie)).status).toBe(403);
        expect(await (await request('/api/keys/bob/identity', 'GET', alice.cookie)).json()).toEqual({ userId: bob.id, identity: uploaded.identity });
        expect(((await (await request('/api/keys/count', 'GET', bob.cookie)).json()) as any).oneTimePreKeys).toBe(2); // identity lookups consume nothing
        const first = await (await request('/api/keys/bob', 'GET', alice.cookie)).json() as any;
        expect(first.signedPreKey).toEqual(uploaded.signedPreKey);
        expect(first.oneTimePreKey).toEqual(uploaded.oneTimePreKeys[0]);
        expect(((await (await request('/api/keys/bob', 'GET', alice.cookie)).json()) as any).oneTimePreKey).toEqual(uploaded.oneTimePreKeys[1]);
        expect(((await (await request('/api/keys/bob', 'GET', alice.cookie)).json()) as any).oneTimePreKey).toBeNull();
        expect(((await (await request('/api/keys/count', 'GET', bob.cookie)).json()) as any).oneTimePreKeys).toBe(0);
        expect((await request('/api/keys/bob', 'GET', alice.cookie)).status).toBe(429); // a contact cannot drain prekeys quickly
    });
    test('the number of waiting one-time prekeys is capped', async () => {
        const bob = user('bob'), upload = keys(100);
        expect((await request('/api/keys', 'PUT', bob.cookie, upload)).status).toBe(200);
        expect((await request('/api/keys', 'PUT', bob.cookie, { identity: upload.identity, oneTimePreKeys: keys(100, 101).oneTimePreKeys })).status).toBe(200);
        expect((await request('/api/keys', 'PUT', bob.cookie, { identity: upload.identity, oneTimePreKeys: keys(1, 201).oneTimePreKeys })).status).toBe(400);
    });
    test('a new identity voids old prekeys and tells contacts to re-check the security code', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await request('/api/keys', 'PUT', bob.cookie, keys(3));
        const watch = events(alice.cookie); await watch.opened; await watch.next('hello');
        const replaced = keys(1, 50);
        expect(((await (await request('/api/keys', 'PUT', bob.cookie, replaced)).json()) as any).changed).toBe(true);
        expect(await watch.next('keys')).toEqual({ type: 'keys', id: bob.id });
        expect(((await (await request('/api/keys/count', 'GET', bob.cookie)).json()) as any).oneTimePreKeys).toBe(1);
        watch.socket.close();
    });
    test('the username "count" is reserved for the prekey count route', async () => {
        const response = await request('/api/register/options', 'POST', '', { invite: 'A'.repeat(22), username: 'count' });
        expect(response.status).toBe(400);
    });
});

describe('encrypted mailbox', () => {
    test('only mutual contacts can send, and envelopes are size checked', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        expect((await request('/api/messages', 'POST', carol.cookie, { to: 'bob', envelope: envelope() })).status).toBe(403);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'ghost', envelope: envelope() })).status).toBe(403);
        for (const bad of ['', 'not base64!', 'abc=', envelope(65537)]) expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: bad })).status).toBe(400);
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope(65536) })).status).toBe(201);
    });
    test('an online recipient gets envelopes at once; acknowledged ones are deleted, others are redelivered', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const inbox = events(bob.cookie); await inbox.opened;
        const sealed = envelope();
        const { id } = await (await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: sealed })).json() as any;
        const delivered = await inbox.next('envelope');
        expect(delivered).toMatchObject({ id, from: { id: alice.id, username: 'alice' }, envelope: sealed });
        const second = await (await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).json() as any;
        await inbox.next('envelope');
        inbox.socket.send(JSON.stringify({ type: 'ack', id }));
        await Bun.sleep(50);
        inbox.socket.close(); await inbox.closed;
        const again = events(bob.cookie); await again.opened;
        expect((await again.next('envelope')).id).toBe(second.id); // unacknowledged → redelivered; acknowledged → gone
        again.socket.close();
    });
    test('envelopes wait for an offline recipient, arrive in order on connect and trigger a push hook', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const pushes: any[] = [];
        app.accounts!.pushNotify = (userId, event) => { pushes.push([userId, event]); };
        const ids: string[] = [];
        for (let index = 0; index < 5; index++) { ids.push(((await (await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).json()) as any).id); await Bun.sleep(2); }
        expect(pushes).toHaveLength(5);
        expect(pushes[0]).toEqual([bob.id, { type: 'message', from: 'alice' }]);
        const inbox = events(bob.cookie); await inbox.opened;
        const got = []; for (let index = 0; index < 5; index++) got.push((await inbox.next('envelope')).id);
        expect(got).toEqual(ids);
        inbox.socket.close();
    });
    test('a user can acknowledge only their own envelopes', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob); await befriend(carol, alice);
        const { id } = await (await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).json() as any;
        const intruder = events(carol.cookie); await intruder.opened;
        intruder.socket.send(JSON.stringify({ type: 'ack', id }));
        await Bun.sleep(50);
        const inbox = events(bob.cookie); await inbox.opened;
        expect((await inbox.next('envelope')).id).toBe(id);
        intruder.socket.close(); inbox.socket.close();
    });
    test('any other client message closes the stream', async () => {
        const bob = user('bob');
        const inbox = events(bob.cookie); await inbox.opened;
        inbox.socket.send(JSON.stringify({ type: 'send', to: 'alice' }));
        expect((await inbox.closed).code).toBe(1008);
    });
    test('one sender is rate limited, so a flood cannot fill a mailbox at once', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const statuses = await Promise.all(Array.from({ length: 25 }, () => request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() }).then(response => response.status)));
        expect(statuses).toContain(429);
        expect(statuses.filter(status => status === 201).length).toBeLessThanOrEqual(20);
    });
    test('one contact can hold only a share of a mailbox, so others can still reach the recipient', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob); await befriend(carol, bob);
        const db = openDatabase(dataDir);
        const insert = db.query('INSERT INTO mailbox (id, recipient_id, sender_id, envelope, created_at) VALUES (?, ?, ?, ?, ?)');
        db.transaction(() => { for (let index = 0; index < 200; index++) insert.run(`f${String(index).padStart(21, '0')}`, bob.id, alice.id, new Uint8Array(8), Date.now()); })();
        db.close();
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).status).toBe(429);
        expect((await request('/api/messages', 'POST', carol.cookie, { to: 'bob', envelope: envelope() })).status).toBe(201);
    });
    test('a full mailbox refuses new envelopes and expired envelopes are deleted', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const db = openDatabase(dataDir);
        const insert = db.query('INSERT INTO mailbox (id, recipient_id, sender_id, envelope, created_at) VALUES (?, ?, ?, ?, ?)');
        const old = Date.now() - 31 * 86400000;
        db.transaction(() => { for (let index = 0; index < 1000; index++) insert.run(`m${String(index).padStart(21, '0')}`, bob.id, alice.id, new Uint8Array(8), old); })();
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).status).toBe(507);
        app.accounts!.sweep();
        expect((db.query('SELECT COUNT(*) AS count FROM mailbox').get() as any).count).toBe(0);
        db.close();
        expect((await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() })).status).toBe(201);
    });
    test('removing a contact discards envelopes between them', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await request('/api/messages', 'POST', alice.cookie, { to: 'bob', envelope: envelope() });
        expect((await request('/api/contacts/alice', 'DELETE', bob.cookie)).status).toBe(200);
        const db = openDatabase(dataDir);
        expect((db.query('SELECT COUNT(*) AS count FROM mailbox').get() as any).count).toBe(0);
        db.close();
    });
});
