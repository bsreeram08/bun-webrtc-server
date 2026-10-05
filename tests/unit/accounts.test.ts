import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInvite, openDatabase } from '../../packages/signaling/accounts';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
const adminToken = 'accounts-test-admin-secret-000000000000000';
let dataDir: string, app: ReturnType<typeof startSignaling>;
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'accounts-'));
    app = startSignaling({ adminToken, origin, port: 0, dataDir });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });

const api = (path: string, init: RequestInit & { cookie?: string } = {}) => fetch(new URL(path, app.server.url), {
    ...init, headers: { 'Content-Type': 'application/json', ...(init.method && init.method !== 'GET' ? { Origin: origin } : {}), ...(init.cookie ? { Cookie: init.cookie } : {}), ...init.headers as any },
});
const post = (path: string, body: unknown, cookie?: string) => api(path, { method: 'POST', body: JSON.stringify(body), cookie });
function user(name: string) { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; }
function events(cookie: string) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers: { Origin: origin, Cookie: cookie } } as any);
    const inbox: any[] = []; let waiter: ((value: any) => void) | undefined;
    socket.onmessage = event => { const message = JSON.parse(String(event.data)); if (waiter) { const resolve = waiter; waiter = undefined; resolve(message); } else inbox.push(message); };
    const next = (type?: string): Promise<any> => {
        const index = inbox.findIndex(message => !type || message.type === type);
        if (index >= 0) return Promise.resolve(inbox.splice(index, 1)[0]);
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`No ${type ?? 'event'}`)), 2000);
            waiter = message => { clearTimeout(timer); if (!type || message.type === type) resolve(message); else { inbox.push(message); next(type).then(resolve, reject); } };
        });
    };
    return { socket, next, opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })), closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })) };
}
function roomSocket(roomId: string, token: string) {
    const url = new URL(`/rooms/${roomId}/socket`, app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { protocols: ['webrtc', token], headers: { Origin: origin } } as any);
    const first = new Promise<any>(resolve => socket.addEventListener('message', event => resolve(JSON.parse(String(event.data))), { once: true }));
    return { socket, first, closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })) };
}
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    expect((await post('/api/contacts', { username: b.username }, a.cookie)).status).toBe(202);
    expect((await post(`/api/contacts/${a.username}/accept`, {}, b.cookie)).status).toBe(200);
}

describe('account storage', () => {
    test('database directory and file are private to the service account', async () => {
        expect((await stat(dataDir)).mode & 0o777).toBe(0o700);
        expect((await stat(join(dataDir, 'accounts.sqlite'))).mode & 0o777).toBe(0o600);
    });
    test('accounts are disabled without a data directory', async () => {
        const plain = startSignaling({ adminToken, origin, port: 0 });
        try { expect((await fetch(new URL('/api/me', plain.server.url))).status).toBe(404); } finally { await plain.stop(); }
    });
});

describe('invites and passkey registration', () => {
    test('registration requires a valid, unused, unexpired invite and a free well-formed username', async () => {
        const db = openDatabase(dataDir);
        const { code } = createInvite(db, null);
        const expired = createInvite(db, null, Date.now() - 8 * 86400000).code;
        const used = createInvite(db, null).code;
        user('taken');
        const usedBy = db.query<{ id: string }, []>('SELECT id FROM users LIMIT 1').get()!.id;
        db.query('UPDATE invites SET used_by = ? WHERE code_hash = (SELECT code_hash FROM invites ORDER BY rowid DESC LIMIT 1)').run(usedBy);
        db.close();
        expect((await post('/api/register/options', { invite: 'x'.repeat(22), username: 'alice' })).status).toBe(400);
        expect((await post('/api/register/options', { invite: expired, username: 'alice' })).status).toBe(400);
        expect((await post('/api/register/options', { invite: used, username: 'alice' })).status).toBe(400);
        expect((await post('/api/register/options', { invite: code, username: 'A!' })).status).toBe(400);
        expect((await post('/api/register/options', { invite: code, username: 'taken' })).status).toBe(409);
        const response = await post('/api/register/options', { invite: code, username: 'Alice' });
        expect(response.status).toBe(200);
        const { flowId, options } = await response.json() as any;
        expect(flowId).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect(options.rp.id).toBe('localhost');
        expect(options.user.name).toBe('alice');
        expect(options.authenticatorSelection.residentKey).toBe('required');
        expect(options.attestation).toBe('none');
    });
    test('forged registration responses are rejected and each challenge is single-use', async () => {
        const db = openDatabase(dataDir); const { code } = createInvite(db, null); db.close();
        const { flowId } = await (await post('/api/register/options', { invite: code, username: 'alice' })).json() as any;
        const forged = { id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { clientDataJSON: 'e30', attestationObject: 'oA' }, clientExtensionResults: {} };
        const first = await post('/api/register/verify', { flowId, response: forged });
        expect(first.status).toBe(400);
        expect(first.headers.get('set-cookie')).toBeNull();
        expect(((await (await post('/api/register/verify', { flowId, response: forged })).json()) as any).error).toContain('expired');
        // The invite was not consumed by the failed attempt.
        expect((await post('/api/register/options', { invite: code, username: 'alice' })).status).toBe(200);
    });
    test('state changes require this origin', async () => {
        const response = await api('/api/register/options', { method: 'POST', body: '{}', headers: { Origin: 'https://evil.example' } });
        expect(response.status).toBe(403);
        const missing = await fetch(new URL('/api/login/options', app.server.url), { method: 'POST' });
        expect(missing.status).toBe(403);
    });
    test('usernameless sign-in options reveal no accounts and unknown credentials fail generically', async () => {
        user('alice');
        const { flowId, options } = await (await post('/api/login/options', {})).json() as any;
        expect(options.allowCredentials ?? []).toEqual([]);
        const response = await post('/api/login/verify', { flowId, response: { id: 'unknown', rawId: 'unknown', type: 'public-key', response: {}, clientExtensionResults: {} } });
        expect(response.status).toBe(400);
        expect(((await response.json()) as any).error).toBe('Sign-in failed.');
    });
    test('one source cannot exhaust pending sign-in challenges', async () => {
        const statuses = [];
        for (let index = 0; index < 6; index++) statuses.push((await post('/api/login/options', {})).status);
        expect(statuses).toEqual([200, 200, 200, 200, 200, 503]);
    });
    test('authentication endpoints are rate limited per source', async () => {
        const statuses = await Promise.all(Array.from({ length: 14 }, () => post('/api/login/options', {}).then(response => response.status)));
        expect(statuses).toContain(429);
    });
});

describe('sessions', () => {
    test('cookie sessions authenticate, expire and end at sign-out', async () => {
        const alice = user('alice');
        expect((await api('/api/me')).status).toBe(401);
        expect((await api('/api/me', { cookie: `session=${'x'.repeat(43)}` })).status).toBe(401);
        const me = await api('/api/me', { cookie: alice.cookie });
        expect(((await me.json()) as any).user).toEqual({ id: alice.id, username: 'alice' });
        const out = await post('/api/logout', {}, alice.cookie);
        expect(out.headers.get('set-cookie')).toContain('Max-Age=0');
        expect((await api('/api/me', { cookie: alice.cookie })).status).toBe(401);
        const bob = user('bob');
        const db = openDatabase(dataDir); db.query('UPDATE sessions SET expires_at = 0').run(); db.close();
        expect((await api('/api/me', { cookie: bob.cookie })).status).toBe(401);
    });
    test('session cookies are HttpOnly and SameSite=Strict and invite codes are created once per request', async () => {
        const alice = user('alice');
        const invite = await post('/api/invites', {}, alice.cookie);
        expect(invite.status).toBe(201);
        const { code } = await invite.json() as any;
        expect(code).toMatch(/^[A-Za-z0-9_-]{22}$/);
        const db = openDatabase(dataDir);
        expect(db.query('SELECT COUNT(*) AS n FROM invites WHERE code_hash = ?').get(code) as any).toEqual({ n: 0 });
        db.close();
        expect(app.accounts!.testing.cookie(alice.id)).toStartWith('session=');
    });
});

describe('contacts and conversations', () => {
    test('contact requests become mutual only after acceptance', async () => {
        const alice = user('alice'), bob = user('bob');
        expect((await post('/api/contacts', { username: 'alice' }, alice.cookie)).status).toBe(400);
        expect((await post('/api/contacts', { username: 'BOB' }, alice.cookie)).status).toBe(202);
        expect(((await (await api('/api/contacts', { cookie: bob.cookie })).json()) as any).contacts).toEqual([{ id: alice.id, username: 'alice', state: 'incoming', online: false }]);
        expect(((await (await api('/api/contacts', { cookie: alice.cookie })).json()) as any).contacts).toEqual([{ id: null, username: 'bob', state: 'outgoing', online: false }]);
        expect((await post('/api/conversations/bob/session', { kind: 'chat' }, alice.cookie)).status).toBe(403);
        expect((await post('/api/contacts/carol/accept', {}, bob.cookie)).status).toBe(404);
        expect((await post('/api/contacts/alice/accept', {}, bob.cookie)).status).toBe(200);
        expect(((await (await api('/api/contacts', { cookie: alice.cookie })).json()) as any).contacts).toEqual([{ id: bob.id, username: 'bob', state: 'mutual', online: false }]);
        expect((await api('/api/contacts/bob', { method: 'DELETE', cookie: alice.cookie })).status).toBe(200);
        expect(((await (await api('/api/contacts', { cookie: bob.cookie })).json()) as any).contacts).toEqual([]);
        expect((await post('/api/conversations/alice/session', { kind: 'chat' }, bob.cookie)).status).toBe(403);
    });
    test('requesting a missing username looks exactly like requesting an existing one', async () => {
        const alice = user('alice'); user('bob');
        const real = await post('/api/contacts', { username: 'bob' }, alice.cookie);
        const ghost = await post('/api/contacts', { username: 'ghost' }, alice.cookie);
        expect(ghost.status).toBe(real.status);
        expect(await ghost.text()).toBe(await real.text());
        const listed = ((await (await api('/api/contacts', { cookie: alice.cookie })).json()) as any).contacts;
        expect(listed).toEqual([{ id: null, username: 'bob', state: 'outgoing', online: false }, { id: null, username: 'ghost', state: 'outgoing', online: false }]);
    });
    test('registering a requested username reveals nothing about earlier requests and cannot accept them', async () => {
        const alice = user('alice');
        expect((await post('/api/contacts', { username: 'bob' }, alice.cookie)).status).toBe(202);
        await Bun.sleep(5);
        const squatter = user('bob');
        expect(((await (await api('/api/contacts', { cookie: squatter.cookie })).json()) as any).contacts).toEqual([]);
        expect((await post('/api/contacts/alice/accept', {}, squatter.cookie)).status).toBe(404);
        expect((await post('/api/contacts', { username: 'alice' }, squatter.cookie)).status).toBe(202);
        const listed = ((await (await api('/api/contacts', { cookie: alice.cookie })).json()) as any).contacts;
        expect(listed.find((contact: any) => contact.username === 'bob').state).not.toBe('mutual');
    });
    test('pending outgoing requests are capped', async () => {
        const alice = user('alice');
        for (let index = 0; index < 20; index++) expect((await post('/api/contacts', { username: `ghost${index}` }, alice.cookie)).status).toBe(202);
        expect((await post('/api/contacts', { username: 'ghost99' }, alice.cookie)).status).toBe(429);
        expect((await post('/api/contacts', { username: 'ghost3' }, alice.cookie)).status).toBe(202);
        expect((await api('/api/contacts/ghost3', { method: 'DELETE', cookie: alice.cookie })).status).toBe(200);
        expect((await post('/api/contacts', { username: 'ghost99' }, alice.cookie)).status).toBe(202);
    });
    test('removing a contact ends their live room and stops presence both ways', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const bobEvents = events(bob.cookie); await bobEvents.opened; await bobEvents.next('hello');
        const session = await (await post('/api/conversations/bob/session', { kind: 'chat' }, alice.cookie)).json() as any;
        const room = roomSocket(session.roomId, session.token); await room.first;
        await bobEvents.next('incoming');
        expect((await api('/api/contacts/bob', { method: 'DELETE', cookie: alice.cookie })).status).toBe(200);
        expect((await room.closed).code).toBe(1000);
        expect(await bobEvents.next('presence')).toEqual({ type: 'presence', id: alice.id, online: false });
        const aliceEvents = events(alice.cookie); await aliceEvents.opened;
        expect((await aliceEvents.next('hello')).online).toEqual([]);
        await expect(bobEvents.next('presence')).rejects.toThrow();
        bobEvents.socket.close(); aliceEvents.socket.close();
    });
    test('a contact who comes online receives a fresh credential for a room waiting for them', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const session = await (await post('/api/conversations/bob/session', { kind: 'chat' }, alice.cookie)).json() as any;
        expect(session.online).toBe(false);
        const room = roomSocket(session.roomId, session.token); await room.first;
        const bobEvents = events(bob.cookie); await bobEvents.opened;
        const incoming = await bobEvents.next('incoming');
        expect(incoming).toMatchObject({ kind: 'chat', roomId: session.roomId, from: { username: 'alice' } });
        expect((await roomSocket(session.roomId, incoming.token).first).type).toBe('welcome');
        bobEvents.socket.close(); room.socket.close();
    });
    test('only mutual contacts can open a session; the peer credential goes only to the peer event stream', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        expect((await post('/api/conversations/bob/session', { kind: 'chat' }, carol.cookie)).status).toBe(403);
        expect((await post('/api/conversations/bob/session', { kind: 'bogus' }, alice.cookie)).status).toBe(400);
        const bobEvents = events(bob.cookie); await bobEvents.opened; await bobEvents.next('hello');
        const response = await post('/api/conversations/bob/session', { kind: 'video' }, alice.cookie);
        const session = await response.json() as any;
        expect(session.online).toBe(true);
        expect(JSON.stringify(session)).not.toContain('peerToken');
        const incoming = await bobEvents.next('incoming');
        expect(incoming).toMatchObject({ from: { id: alice.id, username: 'alice' }, kind: 'video', roomId: session.roomId });
        expect(incoming.token).not.toBe(session.token);
        const a = roomSocket(session.roomId, session.token), b = roomSocket(session.roomId, incoming.token);
        expect((await a.first).type).toBe('welcome'); expect((await b.first).type).toBe('welcome');
        // A second request while connected is refused instead of stealing the slot.
        expect((await post('/api/conversations/bob/session', { kind: 'chat' }, alice.cookie)).status).toBe(409);
        // A new call replaces the pair's room: old sockets learn it was replaced, both users learn it ended.
        const replaced = await post('/api/conversations/alice/session', { kind: 'voice' }, bob.cookie);
        expect(replaced.status).toBe(200);
        expect((await a.closed).code).toBe(4001);
        expect((await bobEvents.next('ended')).roomId).toBe(session.roomId);
        bobEvents.socket.close();
    });
    test('declining a call closes the caller with a declined code', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        const session = await (await post('/api/conversations/bob/session', { kind: 'video' }, alice.cookie)).json() as any;
        const caller = roomSocket(session.roomId, session.token); await caller.first;
        expect((await post('/api/conversations/alice/decline', { roomId: 'x'.repeat(43) }, bob.cookie)).status).toBe(404);
        expect((await post('/api/conversations/alice/decline', { roomId: session.roomId }, bob.cookie)).status).toBe(200);
        expect((await caller.closed).code).toBe(4002);
    });
});

describe('session lifecycle', () => {
    test('signing out closes that session\'s event stream and only that session', async () => {
        const alice = user('alice');
        const other = app.accounts!.testing.cookie(alice.id);
        const first = events(alice.cookie), second = events(other);
        await first.opened; await second.opened;
        await post('/api/logout', {}, alice.cookie);
        expect((await first.closed).code).toBe(4401);
        expect(second.socket.readyState).toBe(WebSocket.OPEN);
        expect((await api('/api/me', { cookie: other })).status).toBe(200);
        second.socket.close();
    });
    test('sign out everywhere ends every session and stream of the account', async () => {
        const alice = user('alice'), bob = user('bob');
        const other = app.accounts!.testing.cookie(alice.id);
        const stream = events(other), bobStream = events(bob.cookie); await stream.opened; await bobStream.opened;
        expect((await post('/api/logout?all=1', {}, alice.cookie)).status).toBe(200);
        expect((await stream.closed).code).toBe(4401);
        expect((await api('/api/me', { cookie: other })).status).toBe(401);
        expect((await api('/api/me', { cookie: bob.cookie })).status).toBe(200);
        bobStream.socket.close();
    });
    test('an expired session\'s stream is closed by the sweep', async () => {
        const alice = user('alice');
        const stream = events(alice.cookie); await stream.opened;
        const db = openDatabase(dataDir); db.query('UPDATE sessions SET expires_at = 1').run(); db.close();
        expect((await stream.closed).code).toBe(4401);
    });
    test('sign-out without a cookie is rejected cleanly and every sign-in issues a new token', async () => {
        expect((await post('/api/logout', {})).status).toBe(401);
        const alice = user('alice');
        const a = app.accounts!.testing.cookie(alice.id), b = app.accounts!.testing.cookie(alice.id);
        expect(a).not.toBe(b);
    });
    test('invites created through the API are attributed to the signed-in user', async () => {
        const alice = user('alice');
        const { code } = await (await post('/api/invites', {}, alice.cookie)).json() as any;
        const db = openDatabase(dataDir);
        const row = db.query('SELECT created_by FROM invites WHERE code_hash = (SELECT code_hash FROM invites ORDER BY rowid DESC LIMIT 1)').get() as any;
        db.close();
        expect(row.created_by).toBe(alice.id);
        expect(code).toMatch(/^[A-Za-z0-9_-]{22}$/);
        expect((await post('/api/invites', {})).status).toBe(401);
    });
});

describe('presence stream', () => {
    test('requires a session cookie and this origin', async () => {
        const url = new URL('/api/events', app.server.url);
        expect((await fetch(url, { headers: { Origin: origin, Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==' } })).status).toBe(401);
        const alice = user('alice');
        expect((await fetch(url, { headers: { Origin: 'https://evil.example', Cookie: alice.cookie } })).status).toBe(403);
    });
    test('mutual contacts see each other come online and go offline; others do not', async () => {
        const alice = user('alice'), bob = user('bob'), carol = user('carol');
        await befriend(alice, bob);
        await post('/api/contacts', { username: 'alice' }, carol.cookie);
        const aliceEvents = events(alice.cookie); await aliceEvents.opened;
        expect((await aliceEvents.next('hello')).online).toEqual([]);
        const bobEvents = events(bob.cookie); await bobEvents.opened;
        expect((await bobEvents.next('hello')).online).toEqual([alice.id]);
        expect(await aliceEvents.next('presence')).toEqual({ type: 'presence', id: bob.id, online: true });
        const carolEvents = events(carol.cookie); await carolEvents.opened; await carolEvents.next('hello');
        bobEvents.socket.close();
        expect(await aliceEvents.next('presence')).toEqual({ type: 'presence', id: bob.id, online: false });
        await expect(aliceEvents.next('presence')).rejects.toThrow();
        aliceEvents.socket.close(); carolEvents.socket.close();
    });
});
