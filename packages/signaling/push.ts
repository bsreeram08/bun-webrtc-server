import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import webpush from 'web-push';

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
const MAX_PER_USER = 10;
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

export function createPush(options: { db: Database; dataDir: string; origin: string; send?: PushSend; now?: () => number }) {
    const { db } = options;
    const now = options.now ?? Date.now;
    db.exec(`CREATE TABLE IF NOT EXISTS push_subscriptions (endpoint TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_hash TEXT NOT NULL, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL)`);
    const keys = vapidKeys(options.dataDir);
    const origin = new URL(options.origin);
    const subject = process.env.VAPID_SUBJECT || (origin.protocol === 'https:' ? origin.origin : 'mailto:push@localhost');
    const send: PushSend = options.send ?? (async (subscription, payload, sendOptions) => {
        try { return await webpush.sendNotification(subscription, payload, { ...sendOptions, vapidDetails: { subject, ...keys } }); }
        catch (error: any) { return { statusCode: Number(error?.statusCode) || 0 }; }
    });

    return {
        publicKey: keys.publicKey,
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
        forgetSession(session: string) { db.query('DELETE FROM push_subscriptions WHERE session_hash = ?').run(session); },
        forgetUser(userId: string) { db.query('DELETE FROM push_subscriptions WHERE user_id = ?').run(userId); },
        /** Expired or deleted sessions take their subscriptions with them. */
        sweep() { db.query('DELETE FROM push_subscriptions WHERE session_hash NOT IN (SELECT token_hash FROM sessions)').run(); },
        async notify(userId: string, event: PushEvent) {
            // Explicit construction: never forward caller fields (message text, tokens) into a payload.
            const payload = JSON.stringify(event.type === 'message' ? { type: 'message', from: event.from }
                : event.type === 'call' ? { type: 'call', from: event.from, kind: event.kind, roomId: event.roomId }
                : { type: 'missed', from: event.from, kind: event.kind });
            const sendOptions = event.type === 'call' ? { TTL: 30, urgency: 'high' as const } : { TTL: 86400, urgency: 'normal' as const };
            const rows = db.query<{ endpoint: string; p256dh: string; auth: string }, [string]>('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?').all(userId);
            await Promise.all(rows.map(async row => {
                const { statusCode } = await send({ endpoint: row.endpoint, keys: { p256dh: row.p256dh, auth: row.auth } }, payload, sendOptions);
                // Gone or unknown subscriptions are dropped; other failures are retried by the next event.
                if (statusCode === 404 || statusCode === 410) db.query('DELETE FROM push_subscriptions WHERE endpoint = ?').run(row.endpoint);
            }));
            return rows.length;
        },
    };
}
export type Push = ReturnType<typeof createPush>;
