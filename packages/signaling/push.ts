import type { Database } from 'bun:sqlite';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import webpush from 'web-push';
import { invalidToken, validNativeToken, type NativePlatform, type NativeSend } from './native-push';

// Web Push: the push service learns that some device got a notification and when; the
// payload is encrypted to that device and carries only the event type and a username.
export type PushEvent =
    | { type: 'message'; from: string }
    | { type: 'call'; from: string; kind: 'voice' | 'video'; roomId: string }
    | { type: 'missed'; from: string; kind: 'voice' | 'video' };
export type PushSubscriptionRecord = { endpoint: string; keys: { p256dh: string; auth: string } };
export type PushSend = (subscription: PushSubscriptionRecord, payload: string, options: { TTL: number; urgency: 'normal' | 'high'; topic?: string }) => Promise<{ statusCode: number }>;

const HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com'];
const SUFFIXES = ['.push.apple.com', '.notify.windows.com'];
const B64URL = /^[A-Za-z0-9_-]+$/;
const MAX_PER_USER = 10, MAX_NATIVE_PER_USER = 20, MAX_PENDING_PER_USER = 5, PENDING_LIFETIME = 120000;
const INSTALL_ID = /^[A-Za-z0-9_-]{16,64}$/;
const digest = (value: string) => createHash('sha256').update(value).digest();
export type NativeRegistration = 'registered' | 'pending' | 'invalid' | 'unconfigured' | 'busy' | 'unconfirmed';
const decode = (value: string) => Buffer.from(value, 'base64url');

/** Accepts only well-formed subscriptions on known push services, so the server never fetches arbitrary URLs. */
export function validSubscription(value: any): PushSubscriptionRecord | null {
    if (!value || typeof value !== 'object' || typeof value.endpoint !== 'string' || value.endpoint.length > 2048) return null;
    let url: URL;
    try { url = new URL(value.endpoint); } catch { return null; }
    const host = url.hostname.toLowerCase();
    if (url.protocol !== 'https:' || url.port || url.username || url.password || url.hash) return null;
    if (!HOSTS.includes(host) && !SUFFIXES.some(suffix => host.endsWith(suffix) && host.length > suffix.length)) return null;
    const { p256dh, auth } = value.keys ?? {};
    if (typeof p256dh !== 'string' || typeof auth !== 'string' || !B64URL.test(p256dh) || !B64URL.test(auth)) return null;
    const key = decode(p256dh), secret = decode(auth);
    if (key.length !== 65 || key[0] !== 4 || secret.length !== 16) return null;
    return { endpoint: url.href, keys: { p256dh, auth } };
}

function vapidKeys(dataDir: string) {
    if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) return { publicKey: process.env.VAPID_PUBLIC_KEY, privateKey: process.env.VAPID_PRIVATE_KEY };
    const path = join(dataDir, 'vapid.json');
    if (!existsSync(path)) {
        // Generated once; 'wx' refuses to overwrite, and only the service account can read it.
        try { writeFileSync(path, JSON.stringify(webpush.generateVAPIDKeys()), { mode: 0o600, flag: 'wx' }); }
        catch (error: any) { if (error.code !== 'EEXIST') throw error; }
    }
    const keys = JSON.parse(readFileSync(path, 'utf8'));
    if (typeof keys.publicKey !== 'string' || typeof keys.privateKey !== 'string') throw new Error('Invalid VAPID key file');
    return keys as { publicKey: string; privateKey: string };
}

export function createPush(options: { db: Database; dataDir: string; origin: string; send?: PushSend; now?: () => number; native?: { send: NativeSend; platforms: NativePlatform[] } | null }) {
    const { db } = options;
    const now = options.now ?? Date.now;
    db.exec(`CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_hash TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)`);
    // FCM and APNs device tokens of native apps, bound to the session (and app install) that proved it holds them.
    db.exec(`CREATE TABLE IF NOT EXISTS push_native (platform TEXT NOT NULL, token TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_hash TEXT NOT NULL, install_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (platform, token))`);
    // Registrations waiting for the device to echo the nonce pushed to it; only the nonce's hash is kept.
    db.exec(`CREATE TABLE IF NOT EXISTS push_native_pending (platform TEXT NOT NULL, token TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_hash TEXT NOT NULL, install_id TEXT NOT NULL, nonce_hash BLOB NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (platform, token, session_hash))`);
    const native = options.native ?? null;
    const keys = vapidKeys(options.dataDir);
    const origin = new URL(options.origin);
    const subject = process.env.VAPID_SUBJECT || (origin.protocol === 'https:' ? origin.origin : 'mailto:push@localhost');
    const send: PushSend = options.send ?? (async (subscription, payload, sendOptions) => {
        try { return await webpush.sendNotification(subscription, payload, { ...sendOptions, vapidDetails: { subject, ...keys } }); }
        catch (error: any) { return { statusCode: Number(error?.statusCode) || 0 }; }
    });

    return {
        publicKey: keys.publicKey,
        nativePlatforms: native?.platforms ?? [],
        /**
         * Starts binding a device token to this session. Knowing a token is not owning it: the binding moves
         * only after the device echoes a nonce pushed to that token (confirmNative), so nobody can redirect
         * another device's notifications by registering its token. Until then any existing binding stays.
         * PushKit VoIP tokens cannot take a silent nonce push (iOS requires every VoIP push to report a call),
         * so they bind only beside a confirmed APNs token of the same app install. An unclaimed VoIP token binds
         * directly; one already held by another session moves only with proof: a VoIP push carrying a nonce,
         * which the app reports to CallKit and ends immediately. A squatter is evicted by the real device,
         * and nobody can take over a device's token without receiving its pushes.
         */
        async registerNative(userId: string, session: string, platform: unknown, value: unknown, installId: unknown): Promise<NativeRegistration> {
            const token = validNativeToken(platform, value);
            if (!token || typeof installId !== 'string' || !INSTALL_ID.test(installId)) return 'invalid';
            if (!native?.platforms.includes(platform as NativePlatform)) return 'unconfigured';
            const bound = db.query<{ session_hash: string; install_id: string; created_at: number }, [string, string]>('SELECT session_hash, install_id, created_at FROM push_native WHERE platform = ? AND token = ?').get(platform as string, token);
            if (bound?.session_hash === session && bound.install_id === installId) return 'registered';
            const bind = () => db.transaction(() => {
                db.query('INSERT OR REPLACE INTO push_native (platform, token, user_id, session_hash, install_id, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(platform as string, token, userId, session, installId, now());
                db.query('DELETE FROM push_native WHERE user_id = ?1 AND rowid NOT IN (SELECT rowid FROM push_native WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ?2)').run(userId, MAX_NATIVE_PER_USER);
            })();
            if (platform === 'apns-voip') {
                if (!db.query("SELECT 1 FROM push_native WHERE platform = 'apns' AND session_hash = ? AND install_id = ?").get(session, installId)) return 'unconfirmed';
                if (!bound || bound.session_hash === session) { bind(); return 'registered'; }
                // Contested: fall through to the nonce proof below (sent over VoIP).
            }
            db.query('DELETE FROM push_native_pending WHERE expires_at <= ?').run(now());
            const pending = db.query<{ count: number }, [string, string, string, string]>('SELECT COUNT(*) AS count FROM push_native_pending WHERE user_id = ? AND NOT (platform = ? AND token = ? AND session_hash = ?)').get(userId, platform as string, token, session)!.count;
            if (pending >= MAX_PENDING_PER_USER) return 'busy';
            const nonce = randomBytes(32).toString('base64url');
            db.query('INSERT OR REPLACE INTO push_native_pending (platform, token, user_id, session_hash, install_id, nonce_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
                .run(platform as string, token, userId, session, installId, digest(nonce), now() + PENDING_LIFETIME);
            const result = await native.send(platform as NativePlatform, token, { type: 'verify', nonce });
            if (invalidToken(platform as NativePlatform, result)) {
                db.query('DELETE FROM push_native_pending WHERE platform = ? AND token = ? AND session_hash = ?').run(platform as string, token, session);
                return 'invalid';
            }
            return 'pending';
        },
        /** Completes a registration with the nonce the device received; single use, two-minute lifetime. */
        confirmNative(userId: string, session: string, platform: unknown, value: unknown, nonce: unknown) {
            const token = validNativeToken(platform, value);
            if (!token || typeof nonce !== 'string' || nonce.length > 64) return false;
            const row = db.query<{ install_id: string; nonce_hash: Uint8Array; expires_at: number }, [string, string, string, string]>(
                'SELECT install_id, nonce_hash, expires_at FROM push_native_pending WHERE platform = ? AND token = ? AND session_hash = ? AND user_id = ?').get(platform as string, token, session, userId);
            // One attempt per nonce: right or wrong, the pending registration is spent.
            db.query('DELETE FROM push_native_pending WHERE platform = ? AND token = ? AND session_hash = ?').run(platform as string, token, session);
            if (!row || row.expires_at <= now() || !timingSafeEqual(Buffer.from(row.nonce_hash), digest(nonce))) return false;
            if (platform === 'apns-voip' && !db.query("SELECT 1 FROM push_native WHERE platform = 'apns' AND session_hash = ? AND install_id = ?").get(session, row.install_id)) return false;
            db.transaction(() => {
                db.query('INSERT OR REPLACE INTO push_native (platform, token, user_id, session_hash, install_id, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(platform as string, token, userId, session, row.install_id, now());
                db.query('DELETE FROM push_native WHERE user_id = ?1 AND rowid NOT IN (SELECT rowid FROM push_native WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ?2)').run(userId, MAX_NATIVE_PER_USER);
            })();
            return true;
        },
        unregisterNative(userId: string, platform: unknown, value: unknown) {
            const token = validNativeToken(platform, value);
            if (token) db.query('DELETE FROM push_native WHERE user_id = ? AND platform = ? AND token = ?').run(userId, platform as string, token);
        },
        subscribe(userId: string, session: string, value: unknown) {
            const subscription = validSubscription(value);
            if (!subscription) return false;
            db.transaction(() => {
                db.query('INSERT OR REPLACE INTO push_subscriptions (endpoint, user_id, session_hash, p256dh, auth, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                    .run(subscription.endpoint, userId, session, subscription.keys.p256dh, subscription.keys.auth, now());
                db.query('DELETE FROM push_subscriptions WHERE user_id = ?1 AND endpoint NOT IN (SELECT endpoint FROM push_subscriptions WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ?2)').run(userId, MAX_PER_USER);
            })();
            return true;
        },
        unsubscribe(userId: string, endpoint: unknown) {
            if (typeof endpoint !== 'string') return;
            db.query('DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?').run(userId, endpoint);
        },
        /** Sign-out: the session's device stops receiving notifications. */
        forgetSession(session: string) {
            db.query('DELETE FROM push_subscriptions WHERE session_hash = ?').run(session);
            db.query('DELETE FROM push_native WHERE session_hash = ?').run(session);
            db.query('DELETE FROM push_native_pending WHERE session_hash = ?').run(session);
        },
        forgetUser(userId: string) {
            db.query('DELETE FROM push_subscriptions WHERE user_id = ?').run(userId);
            db.query('DELETE FROM push_native WHERE user_id = ?').run(userId);
            db.query('DELETE FROM push_native_pending WHERE user_id = ?').run(userId);
        },
        /** Expired or deleted sessions take their subscriptions with them. */
        sweep() {
            db.query('DELETE FROM push_subscriptions WHERE session_hash NOT IN (SELECT token_hash FROM sessions)').run();
            db.query('DELETE FROM push_native WHERE session_hash NOT IN (SELECT token_hash FROM sessions)').run();
            db.query('DELETE FROM push_native_pending WHERE expires_at <= ? OR session_hash NOT IN (SELECT token_hash FROM sessions)').run(now());
        },
        async notify(userId: string, event: PushEvent) {
            // Explicit construction: never forward caller fields (message text, tokens) into a payload.
            const payload = JSON.stringify(event.type === 'message' ? { type: 'message', from: event.from }
                : event.type === 'call' ? { type: 'call', from: event.from, kind: event.kind, roomId: event.roomId }
                : { type: 'missed', from: event.from, kind: event.kind });
            const sendOptions = event.type === 'call' ? { TTL: 30, urgency: 'high' as const } : { TTL: 86400, urgency: 'normal' as const };
            const rows = db.query<{ endpoint: string; p256dh: string; auth: string }, [string]>('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?').all(userId);
            const web = rows.map(async row => {
                const { statusCode } = await send({ endpoint: row.endpoint, keys: { p256dh: row.p256dh, auth: row.auth } }, payload, sendOptions);
                // Gone or unknown subscriptions are dropped; other failures are retried by the next event.
                if (statusCode === 404 || statusCode === 410) db.query('DELETE FROM push_subscriptions WHERE endpoint = ?').run(row.endpoint);
            });
            const devices = native ? db.query<{ platform: NativePlatform; token: string; session_hash: string }, [string]>('SELECT platform, token, session_hash FROM push_native WHERE user_id = ?').all(userId) : [];
            // VoIP pushes are only for calls (iOS ends apps that receive one without reporting a call);
            // a device with a VoIP token gets the call that way instead of as an alert.
            const voip = new Set(devices.filter(row => row.platform === 'apns-voip').map(row => row.session_hash));
            const targets = devices.filter(row => event.type === 'call' ? !(row.platform === 'apns' && voip.has(row.session_hash)) : row.platform !== 'apns-voip');
            const sent = targets.map(async row => {
                const result = await native!.send(row.platform, row.token, event);
                if (invalidToken(row.platform, result)) db.query('DELETE FROM push_native WHERE platform = ? AND token = ?').run(row.platform, row.token);
            });
            await Promise.all([...web, ...sent]);
            return rows.length + targets.length;
        },
    };
}
export type Push = ReturnType<typeof createPush>;
