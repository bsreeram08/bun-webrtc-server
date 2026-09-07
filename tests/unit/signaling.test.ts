import { afterEach, describe, expect, test } from 'bun:test';
import { createHmac } from 'node:crypto';
import { startSignaling } from '../../packages/signaling/server';

const adminToken = 'test-admin-secret-with-at-least-32-characters';
const origin = 'http://localhost:3000';
type Invitation = { roomId: string; expiresAt: number; participants: { token: string; polite: boolean }[] };
const apps: ReturnType<typeof startSignaling>[] = [];
const sockets: WebSocket[] = [];
afterEach(async () => {
    for (const socket of sockets.splice(0)) socket.close();
    for (const app of apps.splice(0)) await app.stop();
});
function app(extra: Partial<Parameters<typeof startSignaling>[0]> = {}) {
    const instance = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0, ...extra });
    apps.push(instance);
    const base = instance.server.url;
    const request = (path: string, init?: RequestInit) => fetch(new URL(path, base), init);
    async function room(): Promise<Invitation> {
        const response = await request('/rooms', { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
        expect(response.status).toBe(201);
        return response.json() as Promise<Invitation>;
    }
    return { ...instance, request, room, base };
}
function connect(base: URL, invitation: Invitation, participant = 0) {
    const url = new URL(`/rooms/${invitation.roomId}/socket`, base);
    url.protocol = 'ws:';
    const socket = new WebSocket(url, { protocols: ['webrtc', invitation.participants[participant].token], headers: { Origin: origin } });
    sockets.push(socket);
    let sessionId: string | undefined;
    const messages: any[] = [];
    const pending: { resolve: (value: any) => void; reject: (reason: Error) => void; timer: ReturnType<typeof setTimeout> }[] = [];
    socket.addEventListener('message', event => {
        const value = JSON.parse(event.data as string);
        if (value.type === 'ready') sessionId = value.sessionId;
        if (value.type === 'peer-left') sessionId = undefined;
        const waiter = pending.shift();
        if (waiter) { clearTimeout(waiter.timer); waiter.resolve(value); } else messages.push(value);
    });
    const closed = new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve, { once: true }));
    function next(): Promise<any> {
        if (messages.length) return Promise.resolve(messages.shift());
        return new Promise((resolve, reject) => {
            const waiter = { resolve, reject, timer: setTimeout(() => {
                pending.splice(pending.indexOf(waiter), 1);
                reject(new Error('Signaling message timed out'));
            }, 2000) };
            pending.push(waiter);
        });
    }
    return { socket, next, closed, messages, get sessionId() { return sessionId; }, send: (value: object) => socket.send(JSON.stringify({ sessionId, ...value })) };
}
async function pair(instance: ReturnType<typeof app>, invitation?: Invitation) {
    const room = invitation ?? await instance.room();
    const a = connect(instance.base, room);
    expect(await a.next()).toEqual({ type: 'welcome', polite: false });
    const b = connect(instance.base, room, 1);
    expect(await b.next()).toEqual({ type: 'welcome', polite: true });
    expect(await a.next()).toEqual({ type: 'ready', sessionId: expect.any(String) });
    expect(await b.next()).toEqual({ type: 'ready', sessionId: a.sessionId });
    return { a, b, room };
}
function upgradeHeaders(token: string, requestOrigin: string | null = origin) {
    return {
        Upgrade: 'websocket', Connection: 'Upgrade', 'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==', 'Sec-WebSocket-Protocol': `webrtc, ${token}`,
        ...(requestOrigin === null ? {} : { Origin: requestOrigin }),
    };
}

describe('self-hosted signaling over real HTTP and WebSocket sockets', () => {
    test('requires an exact secure public origin and a strong admin secret', () => {
        expect(() => app({ adminToken: 'weak' })).toThrow('32');
        expect(() => app({ origin: 'http://example.com' })).toThrow('HTTPS');
        expect(() => app({ origin: 'https://example.com/path' })).toThrow('exact');
    });
    test('room creation requires admin authorization and rejects foreign origins', async () => {
        const instance = app();
        for (const Authorization of ['', 'Basic invalid', 'Bearer wrong']) {
            expect((await instance.request('/rooms', { method: 'POST', headers: { Authorization } })).status).toBe(401);
        }
        expect((await instance.request('/rooms', { method: 'POST', headers: { Authorization: `Bearer ${adminToken}`, Origin: 'https://evil.example' } })).status).toBe(403);
        const room = await instance.room();
        expect(room.participants[0].token).not.toBe(room.participants[1].token);
        expect(room.participants.every(participant => /^[A-Za-z0-9_-]{43}$/.test(participant.token))).toBe(true);
        const health = await instance.request('/health');
        expect(health.headers.get('cache-control')).toBe('no-store');
    });
    test('HTTP source floods cannot starve another proxied client or health checks', async () => {
        const instance = app({ trustProxy: true });
        const sourceA = { 'X-Real-IP': '192.0.2.1' };
        const statuses = await Promise.all(Array.from({ length: 80 }, async () => {
            return (await instance.request('/unknown', { headers: sourceA })).status;
        }));
        expect(statuses.filter(status => status === 404)).toHaveLength(60);
        expect(statuses.filter(status => status === 429)).toHaveLength(20);
        expect((await instance.request('/health', { headers: sourceA })).status).toBe(200);
        expect((await instance.request('/rooms', { method: 'POST', headers: { 'X-Real-IP': '192.0.2.2', Authorization: `Bearer ${adminToken}` } })).status).toBe(201);
    });
    test('untrusted forwarded headers cannot bypass real HTTP source limits', async () => {
        const instance = app();
        const statuses = await Promise.all(Array.from({ length: 80 }, async (_, i) => {
            return (await instance.request('/unknown', { headers: { 'X-Real-IP': `192.0.2.${i + 1}` } })).status;
        }));
        expect(statuses.filter(status => status === 404)).toHaveLength(60);
        expect(statuses.filter(status => status === 429)).toHaveLength(20);
    });
    test('socket authentication binds the invitation to its room and requires Origin', async () => {
        const instance = app();
        const first = await instance.room(); const second = await instance.room();
        const path = `/rooms/${first.roomId}/socket`;
        expect((await instance.request(path, { headers: upgradeHeaders(second.participants[0].token) })).status).toBe(401);
        expect((await instance.request(path, { headers: upgradeHeaders(first.participants[0].token, null) })).status).toBe(403);
        expect((await instance.request(path, { headers: upgradeHeaders(first.participants[0].token, 'https://evil.example') })).status).toBe(403);
    });
    test('TURN configuration rejects missing secrets, missing relay and invalid URLs', () => {
        expect(() => app({ turnUrls: ['turn:relay.example:3478'] })).toThrow('TURN_SECRET');
        expect(() => app({ turnSecret: 'x'.repeat(32) })).toThrow('TURN_URLS');
        expect(() => app({ relayOnly: true })).toThrow('requires TURN');
        expect(() => app({ turnSecret: 'x'.repeat(32), turnUrls: ['https://relay.example'] })).toThrow('Invalid TURN URL');
    });
    test('ICE credentials require a room participant and expire with the room', async () => {
        let now = 100000;
        const turnSecret = 'turn-shared-secret-for-tests-only-123456';
        const turnUrls = ['turn:relay.example:3478?transport=udp', 'turns:relay.example:5349?transport=tcp'];
        const instance = app({ now: () => now, roomLifetimeMs: 10000, turnSecret, turnUrls, relayOnly: true });
        const room = await instance.room(); const otherRoom = await instance.room();
        const path = `/rooms/${room.roomId}/ice`;
        for (const bearer of ['', 'wrong', adminToken, otherRoom.participants[0].token]) {
            expect((await instance.request(path, { headers: { Authorization: `Bearer ${bearer}` } })).status).toBe(401);
        }
        for (const participant of room.participants) {
            const response = await instance.request(path, { headers: { Authorization: `Bearer ${participant.token}` } });
            expect(response.status).toBe(200);
            expect(response.headers.get('cache-control')).toBe('no-store');
            const raw = await response.text();
            expect(raw).not.toContain(turnSecret);
            expect(raw).not.toContain(participant.token);
            const username = `110:${room.roomId}`;
            expect(JSON.parse(raw)).toEqual({
                iceTransportPolicy: 'relay',
                iceServers: [{ urls: turnUrls, username, credential: createHmac('sha1', turnSecret).update(username).digest('base64') }],
            });
        }
        expect((await instance.request(path, { headers: { Authorization: `Bearer ${room.participants[0].token}`, Origin: 'https://evil.example' } })).status).toBe(403);
        now = 110000;
        expect((await instance.request(path, { headers: { Authorization: `Bearer ${room.participants[0].token}` } })).status).toBe(401);
    });
    test('local ICE mode requires authentication and exposes no invented relay', async () => {
        const instance = app(); const room = await instance.room();
        const response = await instance.request(`/rooms/${room.roomId}/ice`, { headers: { Authorization: `Bearer ${room.participants[0].token}` } });
        expect(await response.json()).toEqual({ iceServers: [], iceTransportPolicy: 'all' });
    });
    test('static files carry restrictive browser policies and unknown paths are not exposed', async () => {
        const instance = app();
        for (const path of ['/', '/app.js', '/style.css']) {
            const response = await instance.request(path);
            expect(response.status).toBe(200);
            const csp = response.headers.get('content-security-policy')!;
            expect(csp).toContain("default-src 'none'");
            expect(csp).toContain("script-src 'self'");
            expect(csp).toContain("frame-ancestors 'none'");
            expect(csp).not.toContain('unsafe-inline');
            expect(csp).not.toContain('unsafe-eval');
            expect(response.headers.get('referrer-policy')).toBe('no-referrer');
            expect(response.headers.get('x-content-type-options')).toBe('nosniff');
            expect(response.headers.get('permissions-policy')).toContain('camera=(self), microphone=(self)');
            expect(await response.text()).not.toBe('');
        }
        for (const path of ['/server.ts', '/.env', '/%2e%2e/server.ts']) expect((await instance.request(path)).status).toBe(404);
    });
    test('forwards offers, answers and ICE only to the paired peer and strips spoofed fields', async () => {
        const instance = app();
        const { a, b } = await pair(instance);
        const other = await pair(instance);
        a.send({ type: 'description', roomId: other.room.roomId, to: other.room.participants[0].token, description: { type: 'offer', sdp: 'test offer', admin: true } });
        expect(await b.next()).toEqual({ type: 'description', sessionId: a.sessionId, description: { type: 'offer', sdp: 'test offer' } });
        b.send({ type: 'description', description: { type: 'answer', sdp: 'test answer' } });
        expect(await a.next()).toEqual({ type: 'description', sessionId: a.sessionId, description: { type: 'answer', sdp: 'test answer' } });
        const candidate = { candidate: 'candidate:1 1 UDP 1 192.0.2.1 5000 typ host', sdpMid: '0', sdpMLineIndex: 0 };
        a.send({ type: 'candidate', candidate: { ...candidate, injected: 'evil' } });
        expect(await b.next()).toEqual({ type: 'candidate', sessionId: a.sessionId, candidate });
        b.send({ type: 'candidate', candidate: null });
        expect(await a.next()).toEqual({ type: 'candidate', sessionId: a.sessionId, candidate: null });
        expect(other.a.messages).toEqual([]); expect(other.b.messages).toEqual([]);
    });
    test('rejects duplicate participation without evicting the original socket', async () => {
        const instance = app(); const { a, b, room } = await pair(instance);
        const response = await instance.request(`/rooms/${room.roomId}/socket`, { headers: upgradeHeaders(room.participants[0].token) });
        expect(response.status).toBe(409);
        a.send({ type: 'candidate', candidate: null });
        expect(await b.next()).toEqual({ type: 'candidate', sessionId: a.sessionId, candidate: null });
    });
    test('preserves optional ICE username fragments without forwarding unrelated fields', async () => {
        const instance = app(); const { a, b } = await pair(instance);
        for (const usernameFragment of ['generation1', 'x'.repeat(256), null]) {
            const candidate = { candidate: 'candidate:1 1 udp 2122260223 192.0.2.1 5000 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment };
            a.send({ type: 'candidate', candidate: { ...candidate, unrelated: 'discard' } });
            expect(await b.next()).toEqual({ type: 'candidate', sessionId: a.sessionId, candidate });
        }
    });
    test('notifies disconnects and allows the same participant to reconnect', async () => {
        const instance = app(); const { a, b, room } = await pair(instance);
        a.socket.close(); await a.closed;
        expect(await b.next()).toEqual({ type: 'peer-left' });
        b.send({ type: 'candidate', candidate: null });
        expect(await b.next()).toEqual({ type: 'error', error: 'Peer unavailable' });
        const reconnected = connect(instance.base, room);
        expect(await reconnected.next()).toEqual({ type: 'welcome', polite: false });
        expect(await reconnected.next()).toEqual({ type: 'ready', sessionId: expect.any(String) });
        expect(await b.next()).toEqual({ type: 'ready', sessionId: reconnected.sessionId });
    });
    test('hangup ends the room and revokes both invitations', async () => {
        const instance = app(); const { a, b, room } = await pair(instance);
        a.send({ type: 'hangup' });
        expect((await a.closed).code).toBe(1000); expect((await b.closed).code).toBe(1000);
        for (const participant of room.participants) {
            expect((await instance.request(`/rooms/${room.roomId}/socket`, { headers: upgradeHeaders(participant.token) })).status).toBe(401);
        }
    });
    test('expired rooms reject messages, reconnects, and release capacity', async () => {
        let now = 1000; const instance = app({ now: () => now, roomLifetimeMs: 10, maxRooms: 1 });
        const { a, b, room } = await pair(instance);
        expect((await instance.request('/rooms', { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } })).status).toBe(503);
        now = 1011;
        a.send({ type: 'candidate', candidate: null });
        expect((await a.closed).code).toBe(1008);
        expect((await instance.request(`/rooms/${room.roomId}/socket`, { headers: upgradeHeaders(room.participants[0].token) })).status).toBe(401);
        await instance.room();
        expect((await b.closed).code).toBe(1000);
    });
    test('expiration sweep disconnects idle peers without further requests', async () => {
        let now = 0; const instance = app({ now: () => now, roomLifetimeMs: 10 });
        const { a, b } = await pair(instance);
        now = 11;
        expect((await a.closed).code).toBe(1000);
        expect((await b.closed).code).toBe(1000);
    });
    test('message floods close the sender and preserve the peer', async () => {
        const instance = app(); const { a, b } = await pair(instance);
        const sessionId = a.sessionId;
        for (let i = 0; i < 110; i++) a.send({ type: 'candidate', candidate: null });
        expect((await a.closed).code).toBe(1008);
        let forwarded = 0;
        for (;;) {
            const message = await b.next();
            if (message.type === 'peer-left') break;
            expect(message).toEqual({ type: 'candidate', sessionId, candidate: null });
            forwarded++;
        }
        expect(forwarded).toBe(100);
        expect(b.socket.readyState).toBe(WebSocket.OPEN);
    });
    test('oversized WebSocket payloads close without forwarding', async () => {
        const instance = app(); const { a, b } = await pair(instance);
        a.socket.send('x'.repeat(65537));
        // Bun may terminate at its transport payload limit before sending a close frame.
        expect([1006, 1009]).toContain((await a.closed).code);
        expect(await b.next()).toEqual({ type: 'peer-left' });
    });
    for (const [label, payload] of [
        ['invalid JSON', '{'], ['array', '[]'], ['null', 'null'], ['unknown type', '{"type":"admin"}'],
        ['invalid description', '{"type":"description","description":{"type":"rollback","sdp":""}}'],
        ['invalid ICE index', '{"type":"candidate","candidate":{"candidate":"x","sdpMid":"0","sdpMLineIndex":-1}}'],
        ['oversized ICE username fragment', JSON.stringify({ type: 'candidate', candidate: { candidate: 'x', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 'x'.repeat(257) } })],
        ['invalid ICE username fragment', JSON.stringify({ type: 'candidate', candidate: { candidate: 'x', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 42 } })],
        ['binary', new Uint8Array([1, 2, 3])],
    ] as const) {
        test(`closes ${label} without forwarding it`, async () => {
            const instance = app(); const { a, b } = await pair(instance);
            a.socket.send(payload);
            expect((await a.closed).code).toBe(1008);
            expect(await b.next()).toEqual({ type: 'peer-left' });
            expect(b.messages).toEqual([]);
        });
    }
});
