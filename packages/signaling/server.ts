import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { ServerWebSocket } from 'bun';
import { packetBudget } from '../stun-server/native/server';
import { requestLimiter, requestSource } from './rate-limit';
import { validateTurnUrl } from './config';

type Participant = { digest: string; socket?: ServerWebSocket<Connection> };
type Room = { id: string; expiresAt: number; participants: Participant[]; sessionId?: string };
type Connection = { room: Room; participant: Participant; allow: () => boolean };
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
const json = (value: unknown, status = 200) => Response.json(value, {
    status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' },
});

export type SignalingOptions = {
    adminToken: string;
    origin: string;
    hostname?: string;
    port?: number;
    roomLifetimeMs?: number;
    maxRooms?: number;
    now?: () => number;
    turnSecret?: string;
    turnUrls?: string[];
    relayOnly?: boolean;
    trustProxy?: boolean;
};

export function startSignaling(options: SignalingOptions) {
    if (options.adminToken.length < 32) throw new Error('ADMIN_TOKEN must contain at least 32 characters');
    const origin = new URL(options.origin);
    if (origin.origin !== options.origin || !['http:', 'https:'].includes(origin.protocol)) throw new Error('PUBLIC_ORIGIN must be an exact HTTP(S) origin');
    if (origin.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)) throw new Error('Public deployments require HTTPS');
    const rooms = new Map<string, Room>();
    const now = options.now ?? Date.now;
    const lifetime = options.roomLifetimeMs ?? 60 * 60 * 1000;
    const maxRooms = options.maxRooms ?? 1000;
    if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > 86400000) throw new Error('Invalid room lifetime');
    if (!Number.isSafeInteger(maxRooms) || maxRooms < 1) throw new Error('Invalid room limit');
    if (options.turnUrls?.length && (!options.turnSecret || options.turnSecret.length < 32)) throw new Error('TURN_SECRET must contain at least 32 characters');
    if (options.turnSecret && !options.turnUrls?.length) throw new Error('TURN_URLS required with TURN_SECRET');
    if (options.relayOnly && !options.turnUrls?.length) throw new Error('Relay-only mode requires TURN');
    for (const url of options.turnUrls ?? []) validateTurnUrl(url);
    const allowRequest = requestLimiter();
    const adminDigest = Buffer.from(digest(options.adminToken), 'hex');
    function remove(room: Room) {
        rooms.delete(room.id);
        room.sessionId = undefined;
        for (const participant of room.participants) participant.socket?.close(1000, 'Room ended');
    }
    function sweep() {
        for (const room of rooms.values()) if (room.expiresAt <= now()) remove(room);
    }
    const server = Bun.serve({
        hostname: options.hostname ?? '127.0.0.1', port: options.port ?? 3000,
        maxRequestBodySize: 1024,
        fetch(request, server) {
            const url = new URL(request.url);
            if (request.method === 'GET' && url.pathname === '/health') return json({ status: 'ok' });
            if (!allowRequest(requestSource(server.requestIP(request)?.address, request.headers, options.trustProxy))) return json({ error: 'Rate limited' }, 429);
            const requestOrigin = request.headers.get('origin');
            if (requestOrigin && requestOrigin !== options.origin) return json({ error: 'Origin denied' }, 403);
            if (request.method === 'GET' && ['/', '/app.js', '/style.css'].includes(url.pathname)) {
                const path = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
                return new Response(Bun.file(new URL(`./public/${path}`, import.meta.url)), { headers: {
                    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; media-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                    'Permissions-Policy': 'camera=(self), microphone=(self), display-capture=()',
                    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
                } });
            }
            const roomMatch = /^\/rooms\/([A-Za-z0-9_-]{43})(\/ice)?$/.exec(url.pathname);
            if (roomMatch && (roomMatch[2] && request.method === 'GET' || !roomMatch[2] && request.method === 'DELETE')) {
                const authorization = request.headers.get('authorization') ?? '';
                const room = rooms.get(roomMatch[1]);
                if (!authorization.startsWith('Bearer ') || !room || room.expiresAt <= now() || !room.participants.some(value => value.digest === digest(authorization.slice(7)))) return json({ error: 'Unauthorized' }, 401);
                if (request.method === 'DELETE') { remove(room); return json({ status: 'ended' }); }
                const iceServers: { urls: string[]; username?: string; credential?: string }[] = [];
                if (options.turnSecret && options.turnUrls?.length) {
                    // Coturn REST credentials expire with the room; the shared secret never reaches clients.
                    const username = `${Math.floor(room.expiresAt / 1000)}:${room.id}`;
                    iceServers.push({ urls: options.turnUrls, username, credential: createHmac('sha1', options.turnSecret).update(username).digest('base64') });
                }
                return json({ iceServers, iceTransportPolicy: options.relayOnly ? 'relay' : 'all' });
            }
            if (url.pathname === '/rooms' && request.method === 'POST') {
                const authorization = request.headers.get('authorization') ?? '';
                if (!authorization.startsWith('Bearer ') || !timingSafeEqual(Buffer.from(digest(authorization.slice(7)), 'hex'), adminDigest)) return json({ error: 'Unauthorized' }, 401);
                sweep();
                if (rooms.size >= maxRooms) return json({ error: 'Room capacity reached' }, 503);
                const tokens = [token(), token()];
                const room: Room = { id: token(), expiresAt: now() + lifetime, participants: tokens.map(value => ({ digest: digest(value) })) };
                rooms.set(room.id, room);
                return json({ roomId: room.id, expiresAt: room.expiresAt, participants: tokens.map((token, index) => ({ token, polite: index === 1 })) }, 201);
            }
            const match = /^\/rooms\/([A-Za-z0-9_-]{43})\/socket$/.exec(url.pathname);
            if (match && request.method === 'GET') {
                if (requestOrigin !== options.origin) return json({ error: 'Origin required' }, 403);
                const protocols = (request.headers.get('sec-websocket-protocol') ?? '').split(',').map(value => value.trim());
                const room = rooms.get(match[1]);
                if (protocols.length !== 2 || protocols[0] !== 'webrtc' || !/^[A-Za-z0-9_-]{43}$/.test(protocols[1])) return json({ error: 'Unauthorized' }, 401);
                const participant = room?.participants.find(value => value.digest === digest(protocols[1]));
                if (!room || !participant || room.expiresAt <= now()) return json({ error: 'Unauthorized' }, 401);
                if (participant.socket) return json({ error: 'Participant already connected' }, 409);
                if (server.upgrade(request, { data: { room, participant, allow: packetBudget(100) }, headers: { 'Sec-WebSocket-Protocol': 'webrtc' } })) return;
                return json({ error: 'WebSocket upgrade required' }, 400);
            }
            return json({ error: 'Not found' }, 404);
        },
        websocket: {
            data: {} as Connection,
            maxPayloadLength: 65536,
            backpressureLimit: 131072,
            closeOnBackpressureLimit: true,
            idleTimeout: 60,
            sendPings: true,
            perMessageDeflate: false,
            open(socket) {
                const { room, participant } = socket.data;
                // Repeat the check after upgrade to cover simultaneous uses of one token.
                if (participant.socket || room.expiresAt <= now() || !rooms.has(room.id)) { socket.close(1008, 'Participant unavailable'); return; }
                participant.socket = socket;
                socket.send(JSON.stringify({ type: 'welcome', polite: room.participants.indexOf(participant) === 1 }));
                if (room.participants.every(value => value.socket)) {
                    room.sessionId = token();
                    for (const member of room.participants) member.socket!.send(JSON.stringify({ type: 'ready', sessionId: room.sessionId }));
                }
            },
            message(socket, raw) {
                const { room, participant } = socket.data;
                if (participant.socket !== socket || room.expiresAt <= now() || !rooms.has(room.id)) { socket.close(1008, 'Room expired'); return; }
                if (!socket.data.allow()) { socket.close(1008, 'Rate limited'); return; }
                if (typeof raw !== 'string') { socket.close(1008, 'Text JSON required'); return; }
                let message: any;
                try { message = JSON.parse(raw); } catch { socket.close(1008, 'Invalid JSON'); return; }
                if (!message || typeof message !== 'object' || Array.isArray(message)) { socket.close(1008, 'Invalid message'); return; }
                let forwarded: object;
                if (message.type === 'description' && ['offer', 'answer'].includes(message.description?.type) && typeof message.description.sdp === 'string' && message.description.sdp.length <= 60000) {
                    forwarded = { type: 'description', description: { type: message.description.type, sdp: message.description.sdp } };
                } else if (message.type === 'candidate' && (message.candidate === null || (
                    typeof message.candidate === 'object' && typeof message.candidate.candidate === 'string' && message.candidate.candidate.length <= 4096 &&
                    (message.candidate.sdpMid === null || typeof message.candidate.sdpMid === 'string' && message.candidate.sdpMid.length <= 256) &&
                    (message.candidate.sdpMLineIndex === null || Number.isInteger(message.candidate.sdpMLineIndex) && message.candidate.sdpMLineIndex >= 0 && message.candidate.sdpMLineIndex <= 65535) &&
                    (message.candidate.usernameFragment === undefined || message.candidate.usernameFragment === null || typeof message.candidate.usernameFragment === 'string' && message.candidate.usernameFragment.length <= 256)
                ))) {
                    forwarded = { type: 'candidate', candidate: message.candidate === null ? null : {
                        candidate: message.candidate.candidate, sdpMid: message.candidate.sdpMid, sdpMLineIndex: message.candidate.sdpMLineIndex, usernameFragment: message.candidate.usernameFragment,
                    } };
                } else if (message.type === 'hangup') { remove(room); return; }
                else { socket.close(1008, 'Invalid signaling message'); return; }
                const peer = room.participants.find(value => value !== participant)?.socket;
                if (!peer) { socket.send(JSON.stringify({ type: 'error', error: 'Peer unavailable' })); return; }
                // A surviving socket may still have old SDP/ICE in flight when its peer
                // rejoins. Bind every frame to the current pairing before forwarding it.
                if (!room.sessionId || message.sessionId !== room.sessionId) { socket.send(JSON.stringify({ type: 'error', error: 'Stale session' })); return; }
                if (peer.send(JSON.stringify({ ...forwarded, sessionId: room.sessionId })) === 0) socket.send(JSON.stringify({ type: 'error', error: 'Delivery failed' }));
            },
            close(socket) {
                const { room, participant } = socket.data;
                if (participant.socket !== socket) return;
                participant.socket = undefined;
                room.sessionId = undefined;
                for (const peer of room.participants) peer.socket?.send(JSON.stringify({ type: 'peer-left' }));
            },
        },
    });
    const timer = setInterval(sweep, 1000);
    timer.unref();
    return { server, stop() { clearInterval(timer); rooms.clear(); return server.stop(true); } };
}

if (import.meta.main) {
    const rawPort = process.env.PORT ?? '3000';
    if (!/^\d+$/.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535) throw new Error('PORT must be 1–65535');
    const app = startSignaling({ adminToken: process.env.ADMIN_TOKEN ?? '', origin: process.env.PUBLIC_ORIGIN ?? 'http://localhost:3000', hostname: process.env.HOST ?? '127.0.0.1', port: Number(rawPort), turnSecret: process.env.TURN_SECRET, turnUrls: process.env.TURN_URLS?.split(',').map(value => value.trim()).filter(Boolean), relayOnly: process.env.RELAY_ONLY === 'true', trustProxy: process.env.TRUST_PROXY === 'true' });
    console.log(`Signaling listening on ${app.server.url}`);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, async () => { await app.stop(); process.exit(0); });
}
