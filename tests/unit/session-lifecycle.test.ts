import { expect, test } from 'bun:test';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
const adminToken = 'lifecycle-test-admin-secret-0000000000000';
function connect(base: URL, roomId: string, token: string) {
    const url = new URL(`/rooms/${roomId}/socket`, base); url.protocol = 'ws:';
    const socket = new WebSocket(url, { protocols: ['webrtc', token], headers: { Origin: origin } });
    const inbox: any[] = [];
    let pending: { resolve: (message: any) => void; timer: ReturnType<typeof setTimeout> } | undefined;
    socket.onmessage = event => {
        const message = JSON.parse(String(event.data));
        if (pending) { clearTimeout(pending.timer); pending.resolve(message); pending = undefined; }
        else inbox.push(message);
    };
    const closed = new Promise<void>(resolve => socket.addEventListener('close', () => resolve(), { once: true }));
    const next = () => inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((resolve, reject) => {
        pending = { resolve, timer: setTimeout(() => { pending = undefined; reject(new Error('Message timed out')); }, 2000) };
    });
    return { socket, next, closed, send: (value: unknown) => socket.send(JSON.stringify(value)) };
}

test('an old pairing cannot deliver delayed ICE to a participant that has rejoined', async () => {
    const app = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0 });
    const clients: ReturnType<typeof connect>[] = [];
    try {
        const response = await fetch(new URL('/rooms', app.server.url), { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
        const room = await response.json() as { roomId: string; participants: { token: string }[] };
        const a = connect(app.server.url, room.roomId, room.participants[0].token); clients.push(a);
        expect((await a.next()).type).toBe('welcome');
        const b = connect(app.server.url, room.roomId, room.participants[1].token); clients.push(b);
        expect((await b.next()).type).toBe('welcome');
        const oldReady = await a.next(); expect(oldReady.type).toBe('ready');
        expect((await b.next()).type).toBe('ready');
        b.socket.close(); await b.closed;
        expect((await a.next()).type).toBe('peer-left');
        const rejoined = connect(app.server.url, room.roomId, room.participants[1].token); clients.push(rejoined);
        expect((await rejoined.next()).type).toBe('welcome');
        const freshReady = await rejoined.next(); expect(freshReady.type).toBe('ready');
        expect(freshReady.sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(freshReady.sessionId).not.toBe(oldReady.sessionId);
        expect((await a.next()).type).toBe('ready');

        // This simulates frames already queued for the previous pairing before its
        // disconnect notification was processed. WebSocket ordering alone cannot
        // order a survivor's inbound frames against the other socket's reconnect.
        const candidate = (generation: string) => ({ candidate: `candidate:${generation} 1 udp 1 192.0.2.1 5000 typ host`, sdpMid: '0', sdpMLineIndex: 0, usernameFragment: generation });
        a.send({ type: 'candidate', sessionId: oldReady.sessionId, candidate: candidate('old') });
        a.send({ type: 'candidate', sessionId: freshReady.sessionId, candidate: candidate('fresh') });
        expect(await a.next()).toEqual({ type: 'error', error: 'Stale session' });
        const delivered = await rejoined.next();
        expect(delivered.type).toBe('candidate');
        expect(delivered.sessionId).toBe(freshReady.sessionId);
        expect(delivered.candidate).toEqual(candidate('fresh'));
    } finally {
        for (const client of clients) client.socket.close();
        await app.stop();
    }
});

test('missing or forged sessions cannot forward SDP, and valid sessions still work afterwards', async () => {
    const app = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0 });
    const clients: ReturnType<typeof connect>[] = [];
    try {
        const response = await fetch(new URL('/rooms', app.server.url), { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
        const room = await response.json() as { roomId: string; participants: { token: string }[] };
        const a = connect(app.server.url, room.roomId, room.participants[0].token); clients.push(a); await a.next();
        const b = connect(app.server.url, room.roomId, room.participants[1].token); clients.push(b); await b.next();
        const ready = await a.next(); await b.next();
        for (const sessionId of [undefined, null, 'x'.repeat(43), 123]) {
            a.send({ type: 'description', sessionId, description: { type: 'offer', sdp: 'stale offer' } });
            expect(await a.next()).toEqual({ type: 'error', error: 'Stale session' });
        }
        const valid = { type: 'description', sessionId: ready.sessionId, description: { type: 'offer', sdp: 'fresh offer' } };
        a.send(valid);
        expect(await b.next()).toEqual(valid);
        expect(a.socket.readyState).toBe(WebSocket.OPEN);
    } finally {
        for (const client of clients) client.socket.close();
        await app.stop();
    }
});

test('a disconnected participant can end its room over HTTP without administrator access', async () => {
    const app = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0 });
    const clients: ReturnType<typeof connect>[] = [];
    const request = (path: string, method: string, bearer = '', requestOrigin?: string) => fetch(new URL(path, app.server.url), {
        method, headers: { Authorization: `Bearer ${bearer}`, ...(requestOrigin ? { Origin: requestOrigin } : {}) },
    });
    try {
        const room = await (await request('/rooms', 'POST', adminToken)).json() as { roomId: string; participants: { token: string }[] };
        const other = await (await request('/rooms', 'POST', adminToken)).json() as typeof room;
        const path = `/rooms/${room.roomId}`;
        for (const bearer of ['', 'invalid', adminToken, other.participants[0].token]) {
            expect((await request(path, 'DELETE', bearer)).status).toBe(401);
        }
        expect((await request(path, 'DELETE', room.participants[0].token, 'https://evil.example')).status).toBe(403);
        const a = connect(app.server.url, room.roomId, room.participants[0].token); clients.push(a); await a.next();
        const b = connect(app.server.url, room.roomId, room.participants[1].token); clients.push(b); await b.next();
        await a.next(); await b.next();
        a.socket.close(); await a.closed;
        expect((await b.next()).type).toBe('peer-left');
        const ended = await request(path, 'DELETE', room.participants[0].token, origin);
        expect(ended.status).toBe(200);
        expect(ended.headers.get('cache-control')).toBe('no-store');
        expect(await ended.json()).toEqual({ status: 'ended' });
        await b.closed;
        for (const participant of room.participants) {
            expect((await request(`${path}/ice`, 'GET', participant.token)).status).toBe(401);
            expect((await request(path, 'DELETE', participant.token)).status).toBe(401);
        }
        // Either participant may end an unconnected room, and unrelated rooms survive.
        expect((await request(`/rooms/${other.roomId}/ice`, 'GET', other.participants[1].token)).status).toBe(200);
        expect((await request(`/rooms/${other.roomId}`, 'DELETE', other.participants[1].token)).status).toBe(200);
    } finally {
        for (const client of clients) client.socket.close();
        await app.stop();
    }
});

test('expired participant credentials cannot invoke room deletion', async () => {
    let now = 0;
    const app = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0, now: () => now, roomLifetimeMs: 10 });
    try {
        const response = await fetch(new URL('/rooms', app.server.url), { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
        const room = await response.json() as { roomId: string; participants: { token: string }[] };
        now = 10;
        const deleted = await fetch(new URL(`/rooms/${room.roomId}`, app.server.url), { method: 'DELETE', headers: { Authorization: `Bearer ${room.participants[0].token}` } });
        expect(deleted.status).toBe(401);
    } finally { await app.stop(); }
});
