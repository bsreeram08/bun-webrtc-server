import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync } from 'node:fs';
import type { ServerWebSocket } from 'bun';
import { packetBudget } from '../stun-server/native/server';
import { requestLimiter, requestSource } from './rate-limit';
import { validateTurnUrl } from './config';
import { createAccounts, openDatabase, type Accounts, type EventsConnection } from './accounts';
import { createPush, type PushSend } from './push';
import { nativeSenderFromEnv, type NativePlatform, type NativeSend } from './native-push';
import { createEmoji, type Emoji, type Fetcher, type Resolver } from './emoji';

type Participant = { digest: string; socket?: ServerWebSocket<Connection> };
type Room = { id: string; expiresAt: number; participants: Participant[]; sessionId?: string; pair?: string[]; kind?: string };
type Connection = { kind?: undefined; room: Room; participant: Participant; credential: string; allow: () => boolean };
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
// 'wasm-unsafe-eval' lets the worker instantiate the messaging core's WebAssembly; it does not allow eval().
const PAGE_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; media-src 'self' blob:; img-src 'self' blob:; manifest-src 'self'; worker-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const CORE_FILE = /^\/core\/(manifest\.json|chatcore(?:_bg)?\.[0-9a-f]{16}\.(?:js|wasm))$/;
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
    /** Enables passkey accounts, contacts and presence, stored in DATA_DIR. */
    dataDir?: string;
    /** Test hook replacing the Web Push sender. */
    pushSend?: PushSend;
    /** How long an online callee's app has to confirm it is ringing before devices get a push. */
    ringAckMs?: number;
    /** Native app identity: passkey origins and the files that associate this domain with the apps. */
    apps?: NativeApps;
    /** FCM/APNs transports for native apps (from the environment, or a test double). */
    nativePush?: { send: NativeSend; platforms: NativePlatform[] } | null;
    /** Custom emoji import: extra allowed hosts (EMOJI_IMPORT_HOSTS) and test hooks for the fetch and DNS. */
    emojiImportHosts?: string[];
    emojiFetcher?: Fetcher;
    emojiResolver?: Resolver;
};
export type NativeApps = { appleAppIds?: string[]; androidPackage?: string; androidCertSha256?: string[]; androidApkKeyHashes?: string[] };

const APPLE_APP_ID = /^[A-Z0-9]{10}\.[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/, ANDROID_PACKAGE = /^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/;
const CERT_SHA256 = /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/, APK_KEY_HASH = /^[A-Za-z0-9_-]{43}$/;
/** Validates app identifiers once at startup, so a typo fails loudly instead of silently breaking passkeys. */
export function nativeApps(env: Record<string, string | undefined> = process.env): NativeApps {
    const list = (value?: string) => (value ?? '').split(',').map(item => item.trim()).filter(Boolean);
    const apps: NativeApps = {
        appleAppIds: list(env.APPLE_APP_IDS), androidPackage: env.ANDROID_PACKAGE?.trim() || undefined,
        androidCertSha256: list(env.ANDROID_CERT_SHA256).map(value => value.toUpperCase()), androidApkKeyHashes: list(env.ANDROID_APK_KEY_HASHES),
    };
    if (apps.appleAppIds!.some(id => !APPLE_APP_ID.test(id))) throw new Error('APPLE_APP_IDS must look like TEAMID1234.com.example.app');
    if (apps.androidPackage && !ANDROID_PACKAGE.test(apps.androidPackage)) throw new Error('ANDROID_PACKAGE must be a Java package name');
    if (apps.androidCertSha256!.some(value => !CERT_SHA256.test(value))) throw new Error('ANDROID_CERT_SHA256 must be colon-separated SHA-256 fingerprints');
    if (apps.androidApkKeyHashes!.some(value => !APK_KEY_HASH.test(value))) throw new Error('ANDROID_APK_KEY_HASHES must be unpadded base64url SHA-256 hashes');
    return apps;
}
/** Origins Android's Credential Manager signs for this app: the key hash of each signing certificate. */
export function androidOrigins(apps: NativeApps = {}) {
    const hashes = new Set([...(apps.androidApkKeyHashes ?? []), ...(apps.androidCertSha256 ?? []).map(value => Buffer.from(value.replaceAll(':', ''), 'hex').toString('base64url'))]);
    return [...hashes].map(value => `android:apk-key-hash:${value}`);
}
/** /.well-known files tying this domain to the native apps (passkeys and links); null when unconfigured. */
export function wellKnown(apps: NativeApps = {}) {
    return {
        apple: apps.appleAppIds?.length ? { applinks: { details: [{ appIDs: apps.appleAppIds, components: [{ '/': '/*' }] }] }, webcredentials: { apps: apps.appleAppIds } } : null,
        android: apps.androidPackage && apps.androidCertSha256?.length ? [{
            relation: ['delegate_permission/common.get_login_creds', 'delegate_permission/common.handle_all_urls'],
            target: { namespace: 'android_app', package_name: apps.androidPackage, sha256_cert_fingerprints: apps.androidCertSha256 },
        }] : null,
    };
}

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
    const pairRooms = new Map<string, Room>();
    // 4001 tells clients their room was replaced (for example by a new call); 4002 that the call was declined.
    function remove(room: Room, code = 1000, reason = 'Room ended') {
        if (!rooms.delete(room.id)) return;
        room.sessionId = undefined;
        for (const participant of room.participants) participant.socket?.close(code, reason);
        if (room.pair) {
            if (pairRooms.get(room.pair.join(':')) === room) pairRooms.delete(room.pair.join(':'));
            accounts?.roomEnded(room.pair, room.id, code);
        }
    }
    function sweep() {
        for (const room of rooms.values()) if (room.expiresAt <= now()) remove(room);
        accounts?.sweep();
    }
    function issue(participant: Participant) { const next = token(); participant.digest = digest(next); return next; }
    let accounts: Accounts | undefined;
    const db = options.dataDir ? openDatabase(options.dataDir) : undefined;
    const push = db && options.dataDir ? createPush({ db, dataDir: options.dataDir, origin: options.origin, send: options.pushSend, now, native: options.nativePush }) : undefined;
    const associations = wellKnown(options.apps);
    if (db) accounts = createAccounts({ db, origin: options.origin, now, push, ringAckMs: options.ringAckMs, androidOrigins: androidOrigins(options.apps), calls: {
        pairRoom(users, requester, kind) {
            let room = pairRooms.get(users.join(':'));
            // A call always gets a fresh room; a chat reuses the live one.
            if (room && (kind !== 'chat' || room.expiresAt <= now())) { remove(room, 4001, 'Room replaced'); room = undefined; }
            if (!room) {
                sweep();
                if (rooms.size >= maxRooms) return 'full';
                room = { id: token(), expiresAt: now() + lifetime, participants: users.map(() => ({ digest: '' })), pair: users, kind };
                rooms.set(room.id, room); pairRooms.set(users.join(':'), room);
            }
            const mine = room.participants[users.indexOf(requester)]!, theirs = room.participants[1 - users.indexOf(requester)]!;
            if (mine.socket) return 'busy';
            return { roomId: room.id, token: issue(mine), peerToken: theirs.socket ? undefined : issue(theirs) };
        },
        declinePairRoom(users, roomId) {
            const room = pairRooms.get(users.join(':'));
            if (room?.id !== roomId) return false;
            remove(room, 4002, 'Call declined'); return true;
        },
        endPair(users) { const room = pairRooms.get(users.join(':')); if (room) remove(room); },
        ringingFor(userId, roomId) {
            const room = rooms.get(roomId), index = room?.pair?.indexOf(userId) ?? -1;
            return Boolean(room && index >= 0 && !room.participants[index]!.socket && room.expiresAt > now());
        },
        waitingFor(userId) {
            const waiting = [];
            for (const room of pairRooms.values()) {
                const index = room.pair!.indexOf(userId);
                if (index < 0 || room.expiresAt <= now() || room.participants[index]!.socket || !room.participants[1 - index]!.socket) continue;
                waiting.push({ roomId: room.id, peerId: room.pair![1 - index]!, kind: room.kind!, token: issue(room.participants[index]!) });
            }
            return waiting;
        },
    } });
    const emoji: Emoji | undefined = db && options.dataDir ? createEmoji({ db, dataDir: options.dataDir, origin: options.origin, now, adminToken: options.adminToken, fetcher: options.emojiFetcher, resolver: options.emojiResolver, importHosts: options.emojiImportHosts }) : undefined;
    const server = Bun.serve({
        hostname: options.hostname ?? '127.0.0.1', port: options.port ?? 3000,
        // Custom emoji uploads (512 KB images as base64) are the one larger body; everything else keeps 128 KiB.
        maxRequestBodySize: 786432,
        fetch(request, server) {
            const url = new URL(request.url);
            // Body limits are enforced on what is actually read: a body needs an exact Content-Length (no chunked
            // transfer, which could run past a declared length), at most 128 KiB everywhere except an emoji upload.
            if (request.method !== 'GET' && request.method !== 'HEAD' && (request.body || request.headers.has('transfer-encoding'))) {
                const declared = request.headers.get('content-length'), cap = url.pathname === '/api/emoji' ? 786432 : 131072;
                if (request.headers.has('transfer-encoding') || !declared || !/^\d{1,9}$/.test(declared)) return json({ error: 'Content-Length required' }, 411);
                if (Number(declared) > cap) return json({ error: 'Request too large' }, 413);
            }
            if (request.method === 'GET' && url.pathname === '/health') return json({ status: 'ok' });
            // Fetched by Apple's CDN and Google's verifier: exact JSON, no redirect, 404 until configured.
            if (request.method === 'GET' && (url.pathname === '/.well-known/apple-app-site-association' || url.pathname === '/.well-known/assetlinks.json')) {
                const file = url.pathname.endsWith('.json') ? associations.android : associations.apple;
                return file ? new Response(JSON.stringify(file), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' } }) : json({ error: 'Not found' }, 404);
            }
            const source = requestSource(server.requestIP(request)?.address, request.headers, options.trustProxy);
            const requestOrigin = request.headers.get('origin');
            if (requestOrigin && requestOrigin !== options.origin) return json({ error: 'Origin denied' }, 403);
            if (request.method === 'GET' && ['/', '/app.js', '/account.js', '/alerts.js', '/theme.js', '/commands.js', '/emoji.js', '/emoji-data.json', '/wallpaper-circuit.svg', '/chat-store.js', '/signal.js', '/verify.js', '/core.js', '/core-worker.js', '/vendor/simplewebauthn-browser.js', '/style.css', '/install.js', '/sw.js', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png'].includes(url.pathname)) {
                const path = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
                return new Response(Bun.file(new URL(`./public/${path}`, import.meta.url)), { headers: {
                    'Content-Security-Policy': PAGE_CSP,
                    'Permissions-Policy': 'camera=(self), microphone=(self), display-capture=()',
                    'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store',
                } });
            }
            // The WebAssembly messaging core (scripts/build-wasm.ts): content-hashed, so cached immutably; only the
            // manifest that names the current files is revalidated.
            const core = request.method === 'GET' && CORE_FILE.exec(url.pathname);
            if (core) {
                const location = new URL(`./public/core/${core[1]}`, import.meta.url);
                if (!existsSync(location)) return json({ error: 'Not found' }, 404);
                const file = Bun.file(location);
                const type = core[1].endsWith('.wasm') ? 'application/wasm' : core[1].endsWith('.js') ? 'text/javascript; charset=utf-8' : 'application/json';
                return new Response(file, { headers: {
                    'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': PAGE_CSP,
                    'Cache-Control': core[1] === 'manifest.json' ? 'no-cache' : 'public, max-age=31536000, immutable',
                } });
            }
            // Custom emoji images are public, content-addressed and immutable: served like the fixed files.
            if (request.method === 'GET' && url.pathname.startsWith('/emoji/')) return emoji?.serve(url) ?? json({ error: 'Not found' }, 404);
            // Fixed public files are not rate limited: two phones loading the app behind one home
            // router would otherwise spend the shared per-IP budget before their first API call.
            if (!allowRequest(source)) return json({ error: 'Rate limited' }, 429);
            if (emoji && accounts && /^\/api\/emoji(\/|$)/.test(url.pathname)) return emoji.handle(request, url, accounts.sessionUser(request), source);
            if (url.pathname.startsWith('/api/')) return accounts ? accounts.handle(request, url, server, source) : json({ error: 'Not found' }, 404);
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
                if (server.upgrade(request, { data: { room, participant, credential: participant.digest, allow: packetBudget(100) }, headers: { 'Sec-WebSocket-Protocol': 'webrtc' } })) return;
                return json({ error: 'WebSocket upgrade required' }, 400);
            }
            return json({ error: 'Not found' }, 404);
        },
        websocket: {
            data: {} as Connection | EventsConnection,
            maxPayloadLength: 65536,
            backpressureLimit: 131072,
            closeOnBackpressureLimit: true,
            idleTimeout: 60,
            sendPings: true,
            perMessageDeflate: false,
            open(socket) {
                if (socket.data.kind === 'events') { accounts!.events.open(socket as ServerWebSocket<EventsConnection>); return; }
                const { room, participant, credential } = socket.data;
                // Repeat the check after upgrade to cover simultaneous uses of one token,
                // including an upgrade that raced the rotation of that token.
                if (participant.socket || participant.digest !== credential || room.expiresAt <= now() || !rooms.has(room.id)) { socket.close(1008, 'Participant unavailable'); return; }
                participant.socket = socket as ServerWebSocket<Connection>;
                // Invitations are single-use: each accepted connection replaces the credential,
                // so a copied or leaked link cannot rejoin, fetch ICE or end the room later.
                socket.send(JSON.stringify({ type: 'welcome', polite: room.participants.indexOf(participant) === 1, token: issue(participant) }));
                if (room.participants.every(value => value.socket)) {
                    room.sessionId = token();
                    for (const member of room.participants) member.socket!.send(JSON.stringify({ type: 'ready', sessionId: room.sessionId }));
                }
            },
            message(socket, raw) {
                if (socket.data.kind === 'events') { accounts!.events.message(socket as ServerWebSocket<EventsConnection>, raw); return; }
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
            drain(socket) { if (socket.data.kind === 'events') accounts!.events.drain(socket as ServerWebSocket<EventsConnection>); },
            close(socket) {
                if (socket.data.kind === 'events') { accounts!.events.close(socket as ServerWebSocket<EventsConnection>); return; }
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
    return { server, accounts, stop() { clearInterval(timer); rooms.clear(); return server.stop(true); } };
}

if (import.meta.main) {
    const rawPort = process.env.PORT ?? '3000';
    if (!/^\d+$/.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535) throw new Error('PORT must be 1–65535');
    const app = startSignaling({ adminToken: process.env.ADMIN_TOKEN ?? '', origin: process.env.PUBLIC_ORIGIN ?? 'http://localhost:3000', hostname: process.env.HOST ?? '127.0.0.1', port: Number(rawPort), turnSecret: process.env.TURN_SECRET, turnUrls: process.env.TURN_URLS?.split(',').map(value => value.trim()).filter(Boolean), relayOnly: process.env.RELAY_ONLY === 'true', trustProxy: process.env.TRUST_PROXY === 'true', emojiImportHosts: process.env.EMOJI_IMPORT_HOSTS?.split(',').map(value => value.trim()).filter(Boolean), dataDir: process.env.ACCOUNTS === 'off' ? undefined : process.env.DATA_DIR || 'data', apps: nativeApps(), nativePush: nativeSenderFromEnv() });
    console.log(`Signaling listening on ${app.server.url}`);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, async () => { await app.stop(); process.exit(0); });
}
