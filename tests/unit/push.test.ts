import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validSubscription, type PushSubscriptionRecord } from '../../packages/signaling/push';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
const adminToken = 'push-test-admin-secret-00000000000000000000';
type Sent = { subscription: PushSubscriptionRecord; payload: any; options: { TTL: number; urgency: string } };
let dataDir: string, app: ReturnType<typeof startSignaling>, sent: Sent[], status: number;
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'push-'));
    sent = []; status = 201;
    app = startSignaling({ adminToken, origin, port: 0, dataDir, ringAckMs: 50, pushSend: async (subscription, payload, options) => {
        sent.push({ subscription, payload: JSON.parse(payload), options }); return { statusCode: status };
    } });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });

const api = (path: string, init: RequestInit & { cookie?: string } = {}) => fetch(new URL(path, app.server.url), {
    ...init, headers: { 'Content-Type': 'application/json', ...(init.method && init.method !== 'GET' ? { Origin: origin } : {}), ...(init.cookie ? { Cookie: init.cookie } : {}) },
});
const post = (path: string, body: unknown, cookie?: string) => api(path, { method: 'POST', body: JSON.stringify(body), cookie });
function user(name: string) { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; }
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    await post('/api/contacts', { username: b.username }, a.cookie);
    expect((await post(`/api/contacts/${a.username}/accept`, {}, b.cookie)).status).toBe(200);
}
const key = Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 7)]).toString('base64url');
const auth = Buffer.alloc(16, 9).toString('base64url');
const subscription = (endpoint = 'https://fcm.googleapis.com/fcm/send/device-1') => ({ endpoint, keys: { p256dh: key, auth } });
function events(cookie: string) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers: { Origin: origin, Cookie: cookie } } as any);
    const inbox: any[] = [];
    socket.onmessage = event => inbox.push(JSON.parse(String(event.data)));
    const next = async (type: string) => {
        for (let i = 0; i < 100; i++) { const index = inbox.findIndex(message => message.type === type); if (index >= 0) return inbox.splice(index, 1)[0]; await Bun.sleep(10); }
        throw new Error(`No ${type}`);
    };
    return { socket, next, opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })) };
}
const settle = () => Bun.sleep(120);

describe('push subscriptions', () => {
    test('only well-formed subscriptions on known push services are accepted', () => {
        expect(validSubscription(subscription())).toBeTruthy();
        expect(validSubscription(subscription('https://web.push.apple.com/QGuQ'))).toBeTruthy();
        expect(validSubscription(subscription('https://wns2-par02p.notify.windows.com/w/?token=x'))).toBeTruthy();
        expect(validSubscription(subscription('https://updates.push.services.mozilla.com/wpush/v2/x'))).toBeTruthy();
        for (const endpoint of ['http://fcm.googleapis.com/fcm/send/x', 'https://evil.example/fcm/send/x', 'https://push.apple.com.evil.example/x', 'https://xpush.apple.com/x',
            'https://fcm.googleapis.com:8443/x', 'https://user:pw@fcm.googleapis.com/x', 'https://169.254.169.254/latest', 'not a url']) expect(validSubscription(subscription(endpoint))).toBeNull();
        expect(validSubscription({ endpoint: subscription().endpoint, keys: { p256dh: 'short', auth } })).toBeNull();
        expect(validSubscription({ endpoint: subscription().endpoint, keys: { p256dh: key, auth: Buffer.alloc(8).toString('base64url') } })).toBeNull();
        expect(validSubscription({ endpoint: subscription().endpoint })).toBeNull();
    });
    test('subscribing requires a session and this origin; the VAPID key is generated once and private', async () => {
        expect((await post('/api/push/subscribe', { subscription: subscription() })).status).toBe(401);
        const alice = user('alice');
        expect((await api('/api/push/subscribe', { method: 'POST', body: JSON.stringify({ subscription: subscription() }), cookie: alice.cookie, headers: {} } as any)).status).toBe(201);
        expect((await fetch(new URL('/api/push/subscribe', app.server.url), { method: 'POST', headers: { Cookie: alice.cookie, Origin: 'https://evil.example' }, body: '{}' })).status).toBe(403);
        expect((await post('/api/push/subscribe', { subscription: subscription('https://evil.example/x') }, alice.cookie)).status).toBe(400);
        const { publicKey } = await (await api('/api/push/key')).json() as any;
        expect(publicKey).toMatch(/^[A-Za-z0-9_-]{80,}$/);
        expect((await stat(join(dataDir, 'vapid.json'))).mode & 0o777).toBe(0o600);
    });
    test('message pushes carry only type and sender, and skip recipients whose app is open', async () => {
        const alice = user('alice'), bob = user('bob');
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        const sneaky = { type: 'message', from: 'alice', text: 'secret plans', token: 'x' } as any;
        expect(await app.accounts!.pushNotify(bob.id, sneaky)).toBe(1);
        expect(sent).toHaveLength(1);
        expect(sent[0]!.payload).toEqual({ type: 'message', from: 'alice' });
        expect(JSON.stringify(sent[0])).not.toContain('secret');
        expect(sent[0]!.options).toEqual({ TTL: 86400, urgency: 'normal' });
        const open = events(bob.cookie); await open.opened; await open.next('hello');
        expect(await app.accounts!.pushNotify(bob.id, { type: 'message', from: 'alice' })).toBe(0);
        expect(sent).toHaveLength(1);
        open.socket.close(); void alice;
    });
    test('subscriptions the push service reports gone are deleted', async () => {
        const bob = user('bob');
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        status = 410;
        expect(await app.accounts!.pushNotify(bob.id, { type: 'message', from: 'alice' })).toBe(1);
        status = 201;
        expect(await app.accounts!.pushNotify(bob.id, { type: 'message', from: 'alice' })).toBe(0);
        expect(sent).toHaveLength(1);
    });
    test('signing out removes that device subscription; unsubscribe removes it on request', async () => {
        const bob = user('bob'), other = app.accounts!.testing.cookie(bob.id);
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        await post('/api/push/subscribe', { subscription: subscription('https://fcm.googleapis.com/fcm/send/device-2') }, other);
        expect((await post('/api/logout', {}, bob.cookie)).status).toBe(200);
        expect(await app.accounts!.pushNotify(bob.id, { type: 'message', from: 'alice' })).toBe(1);
        expect(sent[0]!.subscription.endpoint).toBe('https://fcm.googleapis.com/fcm/send/device-2');
        expect((await api('/api/push/subscribe', { method: 'DELETE', body: JSON.stringify({ endpoint: 'https://fcm.googleapis.com/fcm/send/device-2' }), cookie: other })).status).toBe(200);
        expect(await app.accounts!.pushNotify(bob.id, { type: 'message', from: 'alice' })).toBe(0);
    });
});

describe('call pushes', () => {
    test('calling an offline contact pushes immediately with a short TTL and high urgency', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        const session = await (await post('/api/conversations/bob/session', { kind: 'video' }, alice.cookie)).json() as any;
        await settle();
        expect(sent.map(value => value.payload)).toEqual([{ type: 'call', from: 'alice', kind: 'video', roomId: session.roomId }]);
        expect(sent[0]!.options).toEqual({ TTL: 30, urgency: 'high' });
        expect(JSON.stringify(sent[0]!.payload)).not.toContain(session.token);
    });
    test('a chat session never pushes', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        await post('/api/conversations/bob/session', { kind: 'chat' }, alice.cookie);
        await settle();
        expect(sent).toHaveLength(0);
    });
    test('an open app that confirms ringing suppresses the push; one that does not gets it', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        const bobEvents = events(bob.cookie); await bobEvents.opened; await bobEvents.next('hello');
        const first = await (await post('/api/conversations/bob/session', { kind: 'voice' }, alice.cookie)).json() as any;
        const incoming = await bobEvents.next('incoming');
        bobEvents.socket.send(JSON.stringify({ type: 'ringing', roomId: incoming.roomId }));
        await settle();
        expect(sent).toHaveLength(0);
        await post('/api/conversations/bob/decline', { roomId: first.roomId }, bob.cookie);
        await post('/api/conversations/bob/session', { kind: 'voice' }, alice.cookie);
        await bobEvents.next('incoming');
        await settle();
        expect(sent.map(value => value.payload.type)).toEqual(['call']);
        bobEvents.socket.close();
    });
    test('an unanswered call that ends becomes a missed-call push; replaced or declined calls do not', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await post('/api/push/subscribe', { subscription: subscription() }, bob.cookie);
        await post('/api/conversations/bob/session', { kind: 'video' }, alice.cookie);
        const second = await (await post('/api/conversations/bob/session', { kind: 'voice' }, alice.cookie)).json() as any;
        await settle();
        expect(sent.map(value => value.payload.type)).toEqual(['call', 'call']);
        expect((await fetch(new URL(`/rooms/${second.roomId}`, app.server.url), { method: 'DELETE', headers: { Authorization: `Bearer ${second.token}` } })).status).toBe(200);
        await settle();
        expect(sent.map(value => value.payload)).toEqual([
            expect.objectContaining({ type: 'call', kind: 'video' }), expect.objectContaining({ type: 'call', kind: 'voice' }), { type: 'missed', from: 'alice', kind: 'voice' },
        ]);
        expect(sent[2]!.options).toEqual({ TTL: 86400, urgency: 'normal' });
    });
});
