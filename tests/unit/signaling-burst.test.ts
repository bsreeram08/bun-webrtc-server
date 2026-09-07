import { expect, test } from 'bun:test';
import { startSignaling } from '../../packages/signaling/server';

const adminToken = 'burst-test-administrator-token-0000000000000';
const origin = 'http://localhost:3000';

function client(base: URL, roomId: string, token: string) {
    const url = new URL(`/rooms/${roomId}/socket`, base); url.protocol = 'ws:';
    const socket = new WebSocket(url, { protocols: ['webrtc', token], headers: { Origin: origin } });
    const messages: unknown[] = [];
    let pending: { count: number; resolve: () => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> } | undefined;
    socket.onmessage = event => {
        messages.push(JSON.parse(String(event.data)));
        if (pending && messages.length >= pending.count) { clearTimeout(pending.timer); pending.resolve(); pending = undefined; }
    };
    socket.onclose = event => {
        if (pending) { clearTimeout(pending.timer); pending.reject(new Error(`Socket closed ${event.code} after ${messages.length} messages`)); pending = undefined; }
    };
    function received(count: number) {
        if (messages.length >= count) return Promise.resolve();
        return new Promise<void>((resolve, reject) => {
            pending = { count, resolve, reject, timer: setTimeout(() => {
                pending = undefined; reject(new Error(`Expected ${count} messages, received ${messages.length}: ${JSON.stringify(messages)}`));
            }, 1500) };
        });
    }
    return { socket, received, messages };
}

test('Bun WebSocket forwards 30-candidate bidirectional bursts after SDP without loss or reordering', async () => {
    // Fresh servers avoid shared HTTP rate limits; iterations exercise transport scheduling.
    for (let iteration = 0; iteration < 40; iteration++) {
        const app = startSignaling({ adminToken, origin, hostname: '127.0.0.1', port: 0 });
        const clients: ReturnType<typeof client>[] = [];
        try {
            const response = await fetch(new URL('/rooms', app.server.url), { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
            expect(response.status).toBe(201);
            const room = await response.json() as { roomId: string; participants: { token: string }[] };
            const a = client(app.server.url, room.roomId, room.participants[0].token); clients.push(a);
            await a.received(1);
            const b = client(app.server.url, room.roomId, room.participants[1].token); clients.push(b);
            await Promise.all([a.received(2), b.received(2)]);
            const sessionId = (a.messages[1] as { sessionId: string }).sessionId;
            expect(a.messages).toEqual([{ type: 'welcome', polite: false }, { type: 'ready', sessionId: expect.any(String) }]);
            expect(b.messages).toEqual([{ type: 'welcome', polite: true }, { type: 'ready', sessionId }]);
            const bursts = [0, 1].map(side => [
                { type: 'description', description: { type: side === 0 ? 'offer' : 'answer', sdp: `v=0\r\na=ice-ufrag:${side}-${iteration}\r\n${'a=x:test\r\n'.repeat(iteration % 2 ? 5000 : 20)}` } },
                ...Array.from({ length: 30 }, (_, index) => ({ type: 'candidate', candidate: {
                    candidate: `candidate:${side}${index} 1 udp 2122260223 192.0.2.${side + 1} ${5000 + index} typ host generation 0 ufrag ${side}-${iteration}`,
                    sdpMid: String(index % 2), sdpMLineIndex: index % 2,
                } })),
                { type: 'candidate', candidate: null },
            ].map(message => ({ ...message, sessionId })));
            for (let index = 0; index < bursts[0].length; index++) {
                a.socket.send(JSON.stringify(bursts[0][index]));
                b.socket.send(JSON.stringify(bursts[1][index]));
            }
            await Promise.all([a.received(34), b.received(34)]);
            expect(a.messages.slice(2)).toEqual(bursts[1]);
            expect(b.messages.slice(2)).toEqual(bursts[0]);
        } finally {
            for (const value of clients) value.socket.close();
            await app.stop();
        }
    }
}, 15000);
