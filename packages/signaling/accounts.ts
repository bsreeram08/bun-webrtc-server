import { Database } from 'bun:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { ServerWebSocket } from 'bun';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { packetBudget } from '../stun-server/native/server';
import { requestLimiter } from './rate-limit';

// Accounts identify people and introduce them; message content never reaches this module.
// The server learns usernames, the contact graph, presence and passkey public keys.
export type User = { id: string; username: string };
export type EventsConnection = { kind: 'events'; userId: string; session: string; allow: () => boolean; sent: Set<string> };
export type Calls = {
    /** Opens (or for calls, replaces) the pair's room and issues fresh participant credentials. */
    pairRoom(users: string[], requester: string, kind: 'chat' | 'voice' | 'video'): { roomId: string; token: string; peerToken?: string } | 'busy' | 'full';
    declinePairRoom(users: string[], roomId: string): boolean;
    /** Ends any live room for the pair (contact removed). */
    endPair(users: string[]): void;
    /** Rooms where the peer waits for this user, with a fresh credential for each. */
    waitingFor(userId: string): { roomId: string; peerId: string; kind: string; token: string }[];
};
const MAILBOX_TTL = 30 * 86400000, MAILBOX_MAX_COUNT = 1000, MAILBOX_MAX_BYTES = 50 * 1024 * 1024, SENDER_MAX_COUNT = 200, SENDER_MAX_BYTES = 10 * 1024 * 1024, ENVELOPE_MAX = 65536, MAX_PREKEYS = 200, INFLIGHT = 32;
const KEY = /^[A-Za-z0-9_-]{43}$/, SIGNATURE = /^[A-Za-z0-9_-]{86}$/, MESSAGE_ID = /^[A-Za-z0-9_-]{22}$/, RESERVED = new Set(['count']);
const DAY = 86400000, INVITE_LIFETIME = 7 * DAY, SESSION_LIFETIME = 30 * DAY, FLOW_LIFETIME = 5 * 60000, REQUEST_LIFETIME = 30 * DAY, MAX_PENDING_REQUESTS = 20;
const USERNAME = /^[a-z0-9_]{3,20}$/, INVITE = /^[A-Za-z0-9_-]{22}$/, FLOW = /^[A-Za-z0-9_-]{22}$/;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const random = (bytes: number) => randomBytes(bytes).toString('base64url');
const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
const json = (value: unknown, status = 200, extra: Record<string, string> = {}) => Response.json(value, { status, headers: { ...headers, ...extra } });
async function readBody(request: Request): Promise<Record<string, any> | null> {
    try { const value = await request.json(); return value && typeof value === 'object' && !Array.isArray(value) ? value : null; } catch { return null; }
}

export function openDatabase(dataDir: string) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    chmodSync(dataDir, 0o700);
    const path = join(dataDir, 'accounts.sqlite');
    const db = new Database(path, { create: true, strict: true });
    chmodSync(path, 0o600);
    db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 2000;');
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS invites (code_hash TEXT PRIMARY KEY, created_by TEXT REFERENCES users(id) ON DELETE SET NULL, expires_at INTEGER NOT NULL, used_by TEXT REFERENCES users(id) ON DELETE SET NULL);
        CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS contacts (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, contact_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, contact_id));
        -- Requests are addressed to a username whether or not it exists, so sending one reveals nothing.
        -- Public keys only. Private keys never leave devices.
        CREATE TABLE IF NOT EXISTS identity_keys (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, dh TEXT NOT NULL, sign TEXT NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS signed_prekeys (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL, key TEXT NOT NULL, signature TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS one_time_prekeys (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_id INTEGER NOT NULL, key TEXT NOT NULL, PRIMARY KEY (user_id, key_id));
        -- End-to-end encrypted envelopes waiting for their recipient; deleted on acknowledgement or after 30 days.
        CREATE TABLE IF NOT EXISTS mailbox (id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, envelope BLOB NOT NULL, created_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS mailbox_recipient ON mailbox (recipient_id, created_at);
        CREATE INDEX IF NOT EXISTS mailbox_age ON mailbox (created_at);
        CREATE TABLE IF NOT EXISTS contact_requests (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, username TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (user_id, username));
    `);
    return db;
}

/** Single-use invitation; only its hash is stored. */
export function createInvite(db: Database, createdBy: string | null, now = Date.now()) {
    const code = random(16);
    db.query('INSERT INTO invites (code_hash, created_by, expires_at) VALUES (?, ?, ?)').run(hash(code), createdBy, now + INVITE_LIFETIME);
    return { code, expiresAt: now + INVITE_LIFETIME };
}

export function createAccounts(options: { db: Database; origin: string; now: () => number; calls: Calls }) {
    const { db, now, calls } = options;
    const origin = new URL(options.origin), rpID = origin.hostname, secure = origin.protocol === 'https:';
    const cookieName = secure ? '__Host-session' : 'session';
    const flows = new Map<string, { kind: 'register' | 'login'; challenge: string; expiresAt: number; source: string; invite?: string; username?: string; userId?: string }>();
    const listeners = new Map<string, Set<ServerWebSocket<EventsConnection>>>();
    const allowAuth = requestLimiter({ perSource: 10, global: 100 });
    const allowSend = requestLimiter({ perSource: 20, global: 2000 }), allowBundle = requestLimiter({ perSource: 3, global: 500 });

    const userByName = (username: string) => db.query<User, [string]>('SELECT id, username FROM users WHERE username = ?').get(username);
    const inviteUsable = (code: string) => Boolean(db.query('SELECT 1 FROM invites WHERE code_hash = ? AND used_by IS NULL AND expires_at > ?').get(hash(code), now()));
    const mutual = (a: string, b: string) => Boolean(db.query('SELECT 1 FROM contacts x JOIN contacts y ON y.user_id = x.contact_id AND y.contact_id = x.user_id WHERE x.user_id = ? AND x.contact_id = ?').get(a, b));
    const mutualIds = (id: string) => db.query<{ id: string }, [string]>('SELECT x.contact_id AS id FROM contacts x JOIN contacts y ON y.user_id = x.contact_id AND y.contact_id = x.user_id WHERE x.user_id = ?').all(id).map(row => row.id);
    const online = (id: string) => (listeners.get(id)?.size ?? 0) > 0;
    function notify(userId: string, event: object) {
        const frame = JSON.stringify(event);
        for (const socket of listeners.get(userId) ?? []) socket.send(frame);
    }
    function announce(userId: string) {
        for (const contact of mutualIds(userId)) notify(contact, { type: 'presence', id: userId, online: online(userId) });
    }
    function startSession(userId: string) {
        const token = random(32);
        db.query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hash(token), userId, now() + SESSION_LIFETIME);
        return `${cookieName}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_LIFETIME / 1000}${secure ? '; Secure' : ''}`;
    }
    function cookieToken(request: Request) {
        for (const part of (request.headers.get('cookie') ?? '').split(';')) {
            const index = part.indexOf('=');
            if (index > 0 && part.slice(0, index).trim() === cookieName) return part.slice(index + 1).trim();
        }
    }
    function sessionUser(request: Request): (User & { session: string }) | null {
        const token = cookieToken(request);
        if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
        const session = hash(token);
        const user = db.query<User, [string, number]>('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?').get(session, now());
        return user && { ...user, session };
    }
    const sessionLive = (session: string) => Boolean(db.query('SELECT 1 FROM sessions WHERE token_hash = ? AND expires_at > ?').get(session, now()));
    /** Closes event streams whose session ended (sign-out, expiry or sign-out everywhere). */
    function closeDeadStreams(userId?: string) {
        for (const [id, set] of listeners) if (!userId || id === userId) for (const socket of set) if (!sessionLive(socket.data.session)) socket.close(4401, 'Signed out');
    }
    function takeFlow(id: unknown, kind: 'register' | 'login') {
        if (typeof id !== 'string' || !FLOW.test(id)) return null;
        const flow = flows.get(id); flows.delete(id); // Challenges are single-use even when verification fails.
        return flow && flow.kind === kind && flow.expiresAt > now() ? flow : null;
    }
    function addFlow(flow: Omit<NonNullable<ReturnType<typeof takeFlow>>, 'expiresAt'>) {
        for (const [id, value] of flows) if (value.expiresAt <= now()) flows.delete(id);
        // Per-source cap: one client cannot exhaust the pool and lock everyone out of signing in.
        let fromSource = 0;
        for (const value of flows.values()) if (value.source === flow.source) fromSource++;
        if (fromSource >= 5 || flows.size >= 10000) return null;
        const id = random(16);
        flows.set(id, { ...flow, expiresAt: now() + FLOW_LIFETIME });
        return id;
    }
    function contacts(me: User) {
        const live = now() - REQUEST_LIFETIME;
        const mutualRows = db.query<{ id: string; username: string }, [string]>('SELECT u.id, u.username FROM contacts c JOIN users u ON u.id = c.contact_id WHERE c.user_id = ?').all(me.id)
            .filter(row => mutual(me.id, row.id)).map(row => ({ id: row.id as string | null, username: row.username, state: 'mutual', online: online(row.id) }));
        // Outgoing requests show only the typed username: never whether that account exists.
        const outgoing = db.query<{ username: string }, [string, number]>('SELECT username FROM contact_requests WHERE user_id = ? AND created_at > ?').all(me.id, live)
            .map(row => ({ id: null, username: row.username, state: 'outgoing', online: false }));
        // Only requests sent after this account existed: whoever later registers a requested
        // username must not learn who asked for it, nor be able to accept on its behalf.
        const since = Math.max(live, db.query<{ created_at: number }, [string]>('SELECT created_at FROM users WHERE id = ?').get(me.id)!.created_at - 1);
        const incoming = db.query<{ id: string; username: string }, [string, number]>('SELECT u.id, u.username FROM contact_requests r JOIN users u ON u.id = r.user_id WHERE r.username = ? AND r.created_at > ?').all(me.username, since)
            .map(row => ({ id: row.id, username: row.username, state: 'incoming', online: false }));
        const seen = new Set(mutualRows.map(row => row.username));
        return [...mutualRows, ...incoming.filter(row => !seen.has(row.username)), ...outgoing.filter(row => !seen.has(row.username))].sort((a, b) => a.username.localeCompare(b.username));
    }
    /** A live request from `from` to `me`, sent after `me` registered (squatted usernames see nothing). */
    function requested(from: User, me: User) {
        const since = Math.max(now() - REQUEST_LIFETIME, db.query<{ created_at: number }, [string]>('SELECT created_at FROM users WHERE id = ?').get(me.id)!.created_at - 1);
        return Boolean(db.query('SELECT 1 FROM contact_requests WHERE user_id = ? AND username = ? AND created_at > ?').get(from.id, me.username, since));
    }
    function befriend(a: User, b: User) {
        db.transaction(() => {
            db.query('INSERT OR IGNORE INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, ?)').run(a.id, b.id, now());
            db.query('INSERT OR IGNORE INTO contacts (user_id, contact_id, created_at) VALUES (?, ?, ?)').run(b.id, a.id, now());
            db.query('DELETE FROM contact_requests WHERE (user_id = ?1 AND username = ?2) OR (user_id = ?3 AND username = ?4)').run(a.id, b.username, b.id, a.username);
        })();
        notify(a.id, { type: 'contacts' }); notify(b.id, { type: 'contacts' });
        notify(a.id, { type: 'presence', id: b.id, online: online(b.id) }); notify(b.id, { type: 'presence', id: a.id, online: online(a.id) });
    }

    const prekeyCount = (userId: string) => db.query<{ count: number }, [string]>('SELECT COUNT(*) AS count FROM one_time_prekeys WHERE user_id = ?').get(userId)!.count;
    function uploadKeys(user: User, body: Record<string, any> | null) {
        const identity = body?.identity, spk = body?.signedPreKey, oneTime = body?.oneTimePreKeys ?? [];
        const keyId = (value: unknown) => Number.isSafeInteger(value) && (value as number) > 0 && (value as number) < 2 ** 31;
        if (!identity || !KEY.test(identity.dh) || !KEY.test(identity.sign)) return json({ error: 'Invalid identity key' }, 400);
        if (spk !== undefined && (!spk || !keyId(spk.id) || !KEY.test(spk.key) || !SIGNATURE.test(spk.signature))) return json({ error: 'Invalid signed prekey' }, 400);
        if (!Array.isArray(oneTime) || oneTime.length > 100 || oneTime.some(value => !value || !keyId(value.id) || !KEY.test(value.key))) return json({ error: 'Invalid one-time prekeys' }, 400);
        const existing = db.query<{ dh: string; sign: string }, [string]>('SELECT dh, sign FROM identity_keys WHERE user_id = ?').get(user.id);
        const changed = Boolean(existing && (existing.dh !== identity.dh || existing.sign !== identity.sign));
        if ((!existing || changed) && !spk) return json({ error: 'A new identity needs a signed prekey' }, 400);
        try {
            db.transaction(() => {
                // A new identity is a new device: prekeys signed by the old one are void.
                if (changed) { db.query('DELETE FROM signed_prekeys WHERE user_id = ?').run(user.id); db.query('DELETE FROM one_time_prekeys WHERE user_id = ?').run(user.id); }
                db.query('INSERT OR REPLACE INTO identity_keys (user_id, dh, sign, updated_at) VALUES (?, ?, ?, ?)').run(user.id, identity.dh, identity.sign, now());
                if (spk) db.query('INSERT OR REPLACE INTO signed_prekeys (user_id, key_id, key, signature) VALUES (?, ?, ?, ?)').run(user.id, spk.id, spk.key, spk.signature);
                for (const value of oneTime) db.query('INSERT OR IGNORE INTO one_time_prekeys (user_id, key_id, key) VALUES (?, ?, ?)').run(user.id, value.id, value.key);
                if (prekeyCount(user.id) > MAX_PREKEYS) throw new Error('prekeys');
            })();
        } catch { return json({ error: `At most ${MAX_PREKEYS} one-time prekeys may wait on the server.` }, 400); }
        // Contacts re-check this identity; a change shows them a security-code notice.
        if (changed || !existing) for (const contact of mutualIds(user.id)) notify(contact, { type: 'keys', id: user.id });
        return json({ oneTimePreKeys: prekeyCount(user.id), changed });
    }
    /** Sends waiting envelopes in order, bounded by in-flight count and socket buffering. */
    function pump(socket: ServerWebSocket<EventsConnection>) {
        const { userId, sent } = socket.data;
        if (sent.size >= INFLIGHT || socket.readyState !== 1) return;
        const rows = db.query<{ id: string; sender_id: string; username: string; envelope: Uint8Array; created_at: number }, [string, number]>(
            'SELECT m.id, m.sender_id, u.username, m.envelope, m.created_at FROM mailbox m JOIN users u ON u.id = m.sender_id WHERE m.recipient_id = ? AND m.created_at > ? ORDER BY m.created_at, m.id LIMIT 128').all(userId, now() - MAILBOX_TTL);
        for (const row of rows) {
            if (sent.has(row.id)) continue;
            if (sent.size >= INFLIGHT || socket.getBufferedAmount() > 16384) break;
            sent.add(row.id);
            socket.send(JSON.stringify({ type: 'envelope', id: row.id, from: { id: row.sender_id, username: row.username }, envelope: Buffer.from(row.envelope).toString('base64url'), createdAt: row.created_at }));
        }
    }
    async function handle(request: Request, url: URL, server: { upgrade(request: Request, options: { data: EventsConnection }): boolean }, source: string): Promise<Response | undefined> {
        const requestOrigin = request.headers.get('origin');
        if (url.pathname === '/api/events' && request.method === 'GET') {
            if (requestOrigin !== options.origin) return json({ error: 'Origin required' }, 403);
            const user = sessionUser(request);
            if (!user) return json({ error: 'Unauthorized' }, 401);
            if ((listeners.get(user.id)?.size ?? 0) >= 8) return json({ error: 'Too many connections' }, 429);
            if (server.upgrade(request, { data: { kind: 'events', userId: user.id, session: user.session, allow: packetBudget(200), sent: new Set() } })) return undefined;
            return json({ error: 'WebSocket upgrade required' }, 400);
        }
        // Every state change must come from this app's own origin (CSRF defence beside SameSite).
        if (request.method !== 'GET' && requestOrigin !== options.origin) return json({ error: 'Origin required' }, 403);
        const path = url.pathname;
        if (/^\/api\/(register|login)\//.test(path) && !allowAuth(source)) return json({ error: 'Rate limited' }, 429);

        if (path === '/api/register/options' && request.method === 'POST') {
            const body = await readBody(request);
            const username = typeof body?.username === 'string' ? body.username.trim().toLowerCase() : '';
            const invite = typeof body?.invite === 'string' ? body.invite.trim() : '';
            if (!USERNAME.test(username) || RESERVED.has(username)) return json({ error: 'Usernames are 3–20 lowercase letters, digits or _.' }, 400);
            if (!INVITE.test(invite) || !inviteUsable(invite)) return json({ error: 'This invite code is invalid, expired or already used.' }, 400);
            if (userByName(username)) return json({ error: 'That username is taken.' }, 409);
            const userId = random(16);
            const registration = await generateRegistrationOptions({
                rpName: 'Private conversations', rpID, userName: username, userID: new TextEncoder().encode(userId), attestationType: 'none',
                authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
            });
            const flowId = addFlow({ kind: 'register', challenge: registration.challenge, source, invite, username, userId });
            return flowId ? json({ flowId, options: registration }) : json({ error: 'Busy, try again' }, 503);
        }
        if (path === '/api/register/verify' && request.method === 'POST') {
            const body = await readBody(request);
            const flow = takeFlow(body?.flowId, 'register');
            if (!flow) return json({ error: 'Registration expired. Start again.' }, 400);
            let credential;
            try {
                const result = await verifyRegistrationResponse({ response: body!.response, expectedChallenge: flow.challenge, expectedOrigin: options.origin, expectedRPID: rpID, requireUserVerification: false });
                if (!result.verified) throw new Error('unverified');
                credential = result.registrationInfo.credential;
            } catch { return json({ error: 'Passkey could not be verified.' }, 400); }
            try {
                db.transaction(() => {
                    db.query('INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)').run(flow.userId!, flow.username!, now());
                    // Consume the invite in the same transaction: a used or expired code rolls the account back.
                    const used = db.query('UPDATE invites SET used_by = ? WHERE code_hash = ? AND used_by IS NULL AND expires_at > ?').run(flow.userId!, hash(flow.invite!), now());
                    if (used.changes !== 1) throw new Error('invite');
                    db.query('INSERT INTO credentials (id, user_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?)').run(credential.id, flow.userId!, credential.publicKey, credential.counter, JSON.stringify(credential.transports ?? []));
                })();
            } catch (error: any) {
                return json({ error: error?.message === 'invite' ? 'This invite code is invalid, expired or already used.' : 'That username is taken.' }, 409);
            }
            return json({ user: { id: flow.userId, username: flow.username } }, 201, { 'Set-Cookie': startSession(flow.userId!) });
        }
        if (path === '/api/login/options' && request.method === 'POST') {
            // Usernameless: discoverable credentials, so the server never reveals which accounts exist.
            const authentication = await generateAuthenticationOptions({ rpID, userVerification: 'preferred' });
            const flowId = addFlow({ kind: 'login', challenge: authentication.challenge, source });
            return flowId ? json({ flowId, options: authentication }) : json({ error: 'Busy, try again' }, 503);
        }
        if (path === '/api/login/verify' && request.method === 'POST') {
            const body = await readBody(request);
            const flow = takeFlow(body?.flowId, 'login');
            const id = body?.response?.id;
            const row = flow && typeof id === 'string' && id.length <= 1024 ? db.query<{ id: string; user_id: string; public_key: Uint8Array; counter: number; transports: string }, [string]>('SELECT * FROM credentials WHERE id = ?').get(id) : null;
            if (!flow || !row) return json({ error: 'Sign-in failed.' }, 400);
            try {
                const result = await verifyAuthenticationResponse({
                    response: body!.response, expectedChallenge: flow.challenge, expectedOrigin: options.origin, expectedRPID: rpID, requireUserVerification: false,
                    credential: { id: row.id, publicKey: new Uint8Array(row.public_key), counter: row.counter, transports: JSON.parse(row.transports) },
                });
                if (!result.verified) throw new Error('unverified');
                db.query('UPDATE credentials SET counter = ? WHERE id = ?').run(result.authenticationInfo.newCounter, row.id);
            } catch { return json({ error: 'Sign-in failed.' }, 400); }
            const user = db.query<User, [string]>('SELECT id, username FROM users WHERE id = ?').get(row.user_id)!;
            return json({ user }, 200, { 'Set-Cookie': startSession(user.id) });
        }

        const user = sessionUser(request);
        if (!user) return json({ error: 'Unauthorized' }, 401);
        if (path === '/api/me' && request.method === 'GET') return json({ user: { id: user.id, username: user.username } });
        if (path === '/api/logout' && request.method === 'POST') {
            // ?all=1 signs out every device of this account.
            if (url.searchParams.get('all') === '1') db.query('DELETE FROM sessions WHERE user_id = ?').run(user.id);
            else db.query('DELETE FROM sessions WHERE token_hash = ?').run(user.session);
            closeDeadStreams(user.id);
            return json({ status: 'signed-out' }, 200, { 'Set-Cookie': `${cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? '; Secure' : ''}` });
        }
        if (path === '/api/invites' && request.method === 'POST') {
            const open = db.query<{ count: number }, [string, number]>('SELECT COUNT(*) AS count FROM invites WHERE created_by = ? AND used_by IS NULL AND expires_at > ?').get(user.id, now())!.count;
            if (open >= 20) return json({ error: 'Too many unused invites. Wait for some to be used or expire.' }, 429);
            return json(createInvite(db, user.id, now()), 201);
        }
        if (path === '/api/contacts' && request.method === 'GET') return json({ contacts: contacts(user) });
        if (path === '/api/contacts' && request.method === 'POST') {
            const body = await readBody(request);
            const username = typeof body?.username === 'string' ? body.username.trim().toLowerCase() : '';
            if (!USERNAME.test(username)) return json({ error: 'Usernames are 3–20 lowercase letters, digits or _.' }, 400);
            if (username === user.username) return json({ error: 'That is you.' }, 400);
            const target = userByName(username);
            const live = now() - REQUEST_LIFETIME;
            // Same answer whether or not the account exists; asking someone who already asked us accepts them.
            if (target && requested(target, user)) befriend(user, target);
            else if (!(target && mutual(user.id, target.id))) {
                db.query('DELETE FROM contact_requests WHERE created_at <= ?').run(live);
                const pending = db.query<{ count: number }, [string]>('SELECT COUNT(*) AS count FROM contact_requests WHERE user_id = ?').get(user.id)!.count;
                if (pending >= MAX_PENDING_REQUESTS && !db.query('SELECT 1 FROM contact_requests WHERE user_id = ? AND username = ?').get(user.id, username)) return json({ error: 'Too many pending requests. Cancel some first.' }, 429);
                db.query('INSERT OR REPLACE INTO contact_requests (user_id, username, created_at) VALUES (?, ?, ?)').run(user.id, username, now());
                if (target) notify(target.id, { type: 'contacts' });
            }
            return json({ status: 'requested' }, 202);
        }
        const contactMatch = /^\/api\/contacts\/([a-z0-9_]{3,20})(\/accept)?$/.exec(path);
        if (contactMatch) {
            const target = userByName(contactMatch[1]!);
            if (contactMatch[2] && request.method === 'POST') {
                if (!target || !requested(target, user)) return json({ error: 'No request from that person.' }, 404);
                befriend(user, target);
                return json({ status: 'accepted' });
            }
            if (!contactMatch[2] && request.method === 'DELETE') {
                // Removes the contact, cancels or declines requests both ways, ends any live room and stops presence.
                db.query('DELETE FROM contact_requests WHERE (user_id = ?1 AND username = ?2) OR (user_id = ?3 AND username = ?4)').run(user.id, contactMatch[1]!, target?.id ?? '', user.username);
                if (target) {
                    const wasMutual = mutual(user.id, target.id);
                    db.query('DELETE FROM contacts WHERE (user_id = ?1 AND contact_id = ?2) OR (user_id = ?2 AND contact_id = ?1)').run(user.id, target.id);
                    db.query('DELETE FROM mailbox WHERE (sender_id = ?1 AND recipient_id = ?2) OR (sender_id = ?2 AND recipient_id = ?1)').run(user.id, target.id);
                    calls.endPair([user.id, target.id].sort());
                    if (wasMutual) { notify(target.id, { type: 'presence', id: user.id, online: false }); notify(user.id, { type: 'presence', id: target.id, online: false }); }
                    notify(target.id, { type: 'contacts' });
                }
                return json({ status: 'removed' });
            }
        }
        if (path === '/api/keys' && request.method === 'PUT') return uploadKeys(user, await readBody(request));
        if (path === '/api/keys/count' && request.method === 'GET') {
            const spk = db.query<{ key_id: number }, [string]>('SELECT key_id FROM signed_prekeys WHERE user_id = ?').get(user.id);
            return json({ oneTimePreKeys: prekeyCount(user.id), signedPreKeyId: spk?.key_id ?? null });
        }
        const keysMatch = /^\/api\/keys\/([a-z0-9_]{3,20})(\/identity)?$/.exec(path);
        if (keysMatch && request.method === 'GET') {
            const target = userByName(keysMatch[1]!);
            if (!target || !mutual(user.id, target.id)) return json({ error: 'You can only reach accepted contacts.' }, 403);
            const identity = db.query<{ dh: string; sign: string }, [string]>('SELECT dh, sign FROM identity_keys WHERE user_id = ?').get(target.id);
            if (!identity) return json({ error: `${target.username} has not set up encrypted messaging yet.` }, 404);
            if (keysMatch[2]) return json({ userId: target.id, identity });
            // Fetching a bundle consumes a one-time prekey, so one contact may not drain them quickly.
            if (!allowBundle(`${user.id}>${target.id}`)) return json({ error: 'Rate limited' }, 429);
            const spk = db.query<{ key_id: number; key: string; signature: string }, [string]>('SELECT key_id, key, signature FROM signed_prekeys WHERE user_id = ?').get(target.id);
            if (!spk) return json({ error: `${target.username} has not set up encrypted messaging yet.` }, 404);
            const oneTime = db.transaction(() => {
                const row = db.query<{ key_id: number; key: string }, [string]>('SELECT key_id, key FROM one_time_prekeys WHERE user_id = ? ORDER BY key_id LIMIT 1').get(target.id);
                if (row) db.query('DELETE FROM one_time_prekeys WHERE user_id = ? AND key_id = ?').run(target.id, row.key_id);
                return row;
            })();
            return json({ userId: target.id, identity, signedPreKey: { id: spk.key_id, key: spk.key, signature: spk.signature }, oneTimePreKey: oneTime ? { id: oneTime.key_id, key: oneTime.key } : null });
        }
        if (path === '/api/messages' && request.method === 'POST') {
            const body = await readBody(request);
            const target = typeof body?.to === 'string' && USERNAME.test(body.to) ? userByName(body.to) : null;
            if (!target || !mutual(user.id, target.id)) return json({ error: 'You can only reach accepted contacts.' }, 403);
            const raw = body!.envelope;
            const envelope = typeof raw === 'string' && raw.length <= Math.ceil(ENVELOPE_MAX * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(raw) ? Buffer.from(raw, 'base64url') : null;
            if (!envelope || envelope.length === 0 || envelope.length > ENVELOPE_MAX || envelope.toString('base64url') !== raw) return json({ error: 'Invalid envelope' }, 400);
            if (!allowSend(user.id)) return json({ error: 'Rate limited' }, 429);
            const pending = db.query<{ count: number; bytes: number }, [string]>('SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(envelope)), 0) AS bytes FROM mailbox WHERE recipient_id = ?').get(target.id)!;
            if (pending.count >= MAILBOX_MAX_COUNT || pending.bytes + envelope.length > MAILBOX_MAX_BYTES) return json({ error: `${target.username}'s mailbox is full. Try again once they have been online.` }, 507);
            // One contact may hold only a share of someone's mailbox, so a flood cannot block everyone else.
            const mine = db.query<{ count: number; bytes: number }, [string, string]>('SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(envelope)), 0) AS bytes FROM mailbox WHERE recipient_id = ? AND sender_id = ?').get(target.id, user.id)!;
            if (mine.count >= SENDER_MAX_COUNT || mine.bytes + envelope.length > SENDER_MAX_BYTES) return json({ error: `Too many undelivered messages to ${target.username}. They arrive once ${target.username} is online.` }, 429);
            const id = random(16), createdAt = now();
            db.query('INSERT INTO mailbox (id, recipient_id, sender_id, envelope, created_at) VALUES (?, ?, ?, ?, ?)').run(id, target.id, user.id, envelope, createdAt);
            if (online(target.id)) for (const socket of listeners.get(target.id) ?? []) pump(socket);
            else self.pushNotify?.(target.id, { type: 'message', from: user.username });
            return json({ id, createdAt }, 201);
        }
        const conversationMatch = /^\/api\/conversations\/([a-z0-9_]{3,20})\/(session|decline)$/.exec(path);
        if (conversationMatch && request.method === 'POST') {
            const target = userByName(conversationMatch[1]!);
            if (!target || !mutual(user.id, target.id)) return json({ error: 'You can only reach accepted contacts.' }, 403);
            const body = await readBody(request);
            const pair = [user.id, target.id].sort();
            if (conversationMatch[2] === 'decline') {
                if (typeof body?.roomId !== 'string' || !calls.declinePairRoom(pair, body.roomId)) return json({ error: 'No such call' }, 404);
                return json({ status: 'declined' });
            }
            const kind = body?.kind;
            if (!['chat', 'voice', 'video'].includes(kind)) return json({ error: 'Invalid kind' }, 400);
            const room = calls.pairRoom(pair, user.id, kind);
            if (room === 'busy') return json({ error: 'Already connected to this conversation.' }, 409);
            if (room === 'full') return json({ error: 'Room capacity reached' }, 503);
            // Only the peer's own authenticated event stream receives its credential.
            if (room.peerToken) notify(target.id, { type: 'incoming', from: { id: user.id, username: user.username }, kind, roomId: room.roomId, token: room.peerToken });
            return json({ roomId: room.roomId, token: room.token, online: online(target.id) });
        }
        return json({ error: 'Not found' }, 404);
    }

    const self = {
        /** Set by the push notification module; called for envelopes stored while the recipient is offline. */
        pushNotify: undefined as undefined | ((userId: string, event: { type: 'message'; from: string }) => void),
        handle, notify, sessionUser, online, pump,
        roomEnded(users: string[], roomId: string) { for (const id of users) notify(id, { type: 'ended', roomId }); },
        sweep() {
            db.query('DELETE FROM sessions WHERE expires_at <= ?').run(now());
            for (const [id, value] of flows) if (value.expiresAt <= now()) flows.delete(id);
            closeDeadStreams();
            db.query('DELETE FROM mailbox WHERE created_at <= ?').run(now() - MAILBOX_TTL);
        },
        events: {
            open(socket: ServerWebSocket<EventsConnection>) {
                const { userId } = socket.data;
                const set = listeners.get(userId) ?? new Set();
                const first = set.size === 0;
                set.add(socket); listeners.set(userId, set);
                socket.send(JSON.stringify({ type: 'hello', online: mutualIds(userId).filter(online) }));
                if (first) announce(userId);
                // A contact may already be waiting in a conversation room for us.
                for (const waiting of calls.waitingFor(userId)) {
                    const from = db.query<User, [string]>('SELECT id, username FROM users WHERE id = ?').get(waiting.peerId);
                    if (from && mutual(userId, from.id)) socket.send(JSON.stringify({ type: 'incoming', from, kind: waiting.kind, roomId: waiting.roomId, token: waiting.token }));
                }
                pump(socket); // Envelopes that waited while this user was offline.
            },
            drain(socket: ServerWebSocket<EventsConnection>) { pump(socket); },
            message(socket: ServerWebSocket<EventsConnection>, raw: string | Buffer) {
                if (!socket.data.allow()) { socket.close(1008, 'Rate limited'); return; }
                if (!sessionLive(socket.data.session)) { socket.close(4401, 'Signed out'); return; }
                // The only client message: an acknowledgement that this device stored (or discarded) an envelope.
                let message: any;
                try { message = typeof raw === 'string' && raw.length <= 256 ? JSON.parse(raw) : null; } catch {}
                if (!message || message.type !== 'ack' || Object.keys(message).length !== 2 || typeof message.id !== 'string' || !MESSAGE_ID.test(message.id)) { socket.close(1008, 'Invalid event message'); return; }
                // Only the recipient's own envelopes can be deleted.
                db.query('DELETE FROM mailbox WHERE id = ? AND recipient_id = ?').run(message.id, socket.data.userId);
                socket.data.sent.delete(message.id);
                pump(socket);
            },
            close(socket: ServerWebSocket<EventsConnection>) {
                const set = listeners.get(socket.data.userId);
                if (!set?.delete(socket)) return;
                if (set.size === 0) { listeners.delete(socket.data.userId); announce(socket.data.userId); }
            },
        },
        // For tests and the bootstrap script; never exposed over HTTP.
        testing: {
            createUser(username: string) { const id = random(16); db.query('INSERT INTO users (id, username, created_at) VALUES (?, ?, ?)').run(id, username, now()); return { id, username }; },
            cookie(userId: string) { return startSession(userId).split(';')[0]!; },
        },
    };
    return self;
}
export type Accounts = ReturnType<typeof createAccounts>;
