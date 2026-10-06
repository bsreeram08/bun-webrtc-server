import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http2 from 'node:http2';

// Native push transports: Firebase Cloud Messaging (Android) and APNs (iOS, including PushKit VoIP).
// Unlike Web Push these payloads are not encrypted to the device: Google or Apple can read them,
// so they carry only the event type, the sender's username and, for calls, the room id.
export type NativePlatform = 'fcm' | 'apns' | 'apns-voip';
export type NativePayload =
    | { type: 'message'; from: string }
    | { type: 'call'; from: string; kind: 'voice' | 'video'; roomId: string }
    | { type: 'missed'; from: string; kind: 'voice' | 'video' }
    /** Proof that a device holds a token: a silent push whose nonce the app posts back. Never shown. */
    | { type: 'verify'; nonce: string };
/** status: HTTP status from Google/Apple (0 for a network failure); reason: their error code, if any. */
export type NativeResult = { status: number; reason?: string };
export type NativeSend = (platform: NativePlatform, token: string, payload: NativePayload) => Promise<NativeResult>;

const FCM_TOKEN = /^[A-Za-z0-9_:-]{100,4096}$/, APNS_TOKEN = /^[0-9a-f]{64,200}$/;
/** Normalised token, or null when it cannot be a real FCM or APNs device token. */
export function validNativeToken(platform: unknown, token: unknown): string | null {
    if (typeof token !== 'string') return null;
    if (platform === 'fcm') return FCM_TOKEN.test(token) ? token : null;
    if (platform === 'apns' || platform === 'apns-voip') return APNS_TOKEN.test(token.toLowerCase()) ? token.toLowerCase() : null;
    return null;
}
/** Google and Apple say this token will never work again, so it is deleted. */
export function invalidToken(platform: NativePlatform, result: NativeResult) {
    if (platform === 'fcm') return result.status === 404 || result.reason === 'UNREGISTERED' || (result.status === 400 && result.reason === 'INVALID_ARGUMENT');
    return result.status === 410 || (result.status === 400 && ['BadDeviceToken', 'DeviceTokenNotForTopic'].includes(result.reason ?? ''));
}

// Explicit construction everywhere: caller fields (message text, tokens) never reach Google or Apple.
const fields = (payload: NativePayload): Record<string, string> => payload.type === 'call'
    ? { type: 'call', from: payload.from, kind: payload.kind, roomId: payload.roomId }
    : payload.type === 'missed' ? { type: 'missed', from: payload.from, kind: payload.kind }
    : payload.type === 'verify' ? { type: 'verify', nonce: payload.nonce } : { type: 'message', from: payload.from };

/** FCM v1 message: data-only, so the app decides what to show; calls are high priority with a 30 s lifetime. */
export function fcmMessage(token: string, payload: NativePayload) {
    const ttl = payload.type === 'call' ? '30s' : payload.type === 'verify' ? '120s' : '86400s';
    return { message: { token, data: fields(payload), android: { priority: payload.type === 'missed' || payload.type === 'verify' ? 'normal' : 'high', ttl } } };
}
/** APNs request: VoIP pushes wake CallKit; token checks are silent background pushes; everything else is an alert. */
export function apnsRequest(platform: 'apns' | 'apns-voip', payload: NativePayload, bundleId: string, nowSeconds: number) {
    const voip = platform === 'apns-voip';
    if (payload.type === 'verify') return {
        headers: { 'apns-topic': bundleId, 'apns-push-type': 'background', 'apns-priority': '5', 'apns-expiration': String(nowSeconds + 120) } as Record<string, string>,
        body: { ...fields(payload), aps: { 'content-available': 1 } } as Record<string, unknown>,
    };
    const alert = payload.type === 'message' ? { title: payload.from, body: 'New message' }
        : payload.type === 'missed' ? { title: payload.from, body: `Missed ${payload.kind} call` }
        : { title: payload.from, body: `Incoming ${payload.kind} call` };
    return {
        headers: {
            'apns-topic': voip ? `${bundleId}.voip` : bundleId,
            'apns-push-type': voip ? 'voip' : 'alert',
            'apns-priority': payload.type === 'missed' ? '5' : '10',
            'apns-expiration': String(nowSeconds + (payload.type === 'call' ? 30 : 86400)),
            ...(payload.type === 'message' ? {} : { 'apns-collapse-id': `call-${payload.from}` }),
        } as Record<string, string>,
        body: (voip ? { ...fields(payload), aps: {} } : { ...fields(payload), aps: { alert, sound: 'default' } }) as Record<string, unknown>,
    };
}

const b64url = (value: Buffer | string) => Buffer.from(value).toString('base64url');
/** Compact JWS; ES256 signatures use the raw r||s form JWT requires. */
export function signJwt(header: object, claims: object, key: KeyObject) {
    const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
    const alg = (header as { alg: string }).alg;
    const signature = alg === 'ES256' ? sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }) : sign('sha256', Buffer.from(input), key);
    return `${input}.${b64url(signature)}`;
}

/** FCM HTTP v1 with a service-account OAuth token, cached until shortly before it expires. */
export function fcmSender(serviceAccountPath: string, fetcher: typeof fetch = fetch) {
    const account = JSON.parse(readFileSync(serviceAccountPath, 'utf8'));
    if (typeof account.project_id !== 'string' || typeof account.client_email !== 'string' || typeof account.private_key !== 'string') throw new Error('Invalid FCM service account file');
    const tokenUri = typeof account.token_uri === 'string' ? account.token_uri : 'https://oauth2.googleapis.com/token';
    if (new URL(tokenUri).protocol !== 'https:') throw new Error('FCM token_uri must be HTTPS');
    const key = createPrivateKey(account.private_key);
    let cached: { token: string; until: number } | null = null;
    async function accessToken() {
        if (cached && cached.until > Date.now()) return cached.token;
        const iat = Math.floor(Date.now() / 1000);
        const assertion = signJwt({ alg: 'RS256', typ: 'JWT' }, { iss: account.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: tokenUri, iat, exp: iat + 3600 }, key);
        const response = await fetcher(tokenUri, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }) });
        const result = await response.json() as { access_token?: string; expires_in?: number };
        if (!response.ok || typeof result.access_token !== 'string') throw new Error(`FCM authorisation failed (${response.status})`);
        cached = { token: result.access_token, until: Date.now() + Math.max(60, (result.expires_in ?? 3600) - 120) * 1000 };
        return cached.token;
    }
    const url = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(account.project_id)}/messages:send`;
    return async (token: string, payload: NativePayload): Promise<NativeResult> => {
        try {
            const response = await fetcher(url, { method: 'POST', headers: { Authorization: `Bearer ${await accessToken()}`, 'Content-Type': 'application/json' }, body: JSON.stringify(fcmMessage(token, payload)) });
            if (response.status === 401) cached = null;
            if (response.ok) return { status: response.status };
            const error = await response.json().catch(() => null) as any;
            const reason = error?.error?.details?.find?.((detail: any) => typeof detail?.errorCode === 'string')?.errorCode ?? error?.error?.status;
            return { status: response.status, reason: typeof reason === 'string' ? reason : undefined };
        } catch { return { status: 0 }; }
    };
}

/** APNs over HTTP/2 with token (.p8) authentication; the JWT is renewed every 40 minutes as Apple requires. */
export function apnsSender(config: { keyPath: string; keyId: string; teamId: string; bundleId: string; production: boolean; host?: string }) {
    const key = createPrivateKey(readFileSync(config.keyPath, 'utf8'));
    const host = config.host ?? (config.production ? 'https://api.push.apple.com' : 'https://api.sandbox.push.apple.com');
    let jwt: { value: string; until: number } | null = null;
    let session: http2.ClientHttp2Session | null = null;
    const bearer = () => {
        if (!jwt || jwt.until <= Date.now()) jwt = { value: signJwt({ alg: 'ES256', kid: config.keyId }, { iss: config.teamId, iat: Math.floor(Date.now() / 1000) }, key), until: Date.now() + 40 * 60000 };
        return jwt.value;
    };
    const connection = () => {
        if (session && !session.closed && !session.destroyed) return session;
        session = http2.connect(host);
        session.on('error', () => { session = null; });
        session.on('goaway', () => { session = null; });
        session.unref?.();
        return session;
    };
    return (platform: 'apns' | 'apns-voip', token: string, payload: NativePayload) => new Promise<NativeResult>(resolve => {
        const request = apnsRequest(platform, payload, config.bundleId, Math.floor(Date.now() / 1000));
        let status = 0, body = '';
        try {
            const stream = connection().request({ ':method': 'POST', ':path': `/3/device/${token}`, authorization: `bearer ${bearer()}`, 'content-type': 'application/json', ...request.headers });
            stream.setTimeout(10000, () => stream.close(http2.constants.NGHTTP2_CANCEL));
            stream.on('response', headers => { status = Number(headers[':status']) || 0; });
            stream.setEncoding('utf8');
            stream.on('data', chunk => { if (body.length < 4096) body += chunk; });
            stream.on('error', () => resolve({ status: 0 }));
            stream.on('close', () => {
                let reason: string | undefined;
                try { reason = JSON.parse(body)?.reason; } catch {}
                if (status === 403 && reason === 'ExpiredProviderToken') jwt = null;
                resolve({ status, reason: typeof reason === 'string' ? reason : undefined });
            });
            stream.end(JSON.stringify(request.body));
        } catch { session = null; resolve({ status: 0 }); }
    });
}

/** Builds the native sender from environment variables; transports without configuration are absent. */
export function nativeSenderFromEnv(env: Record<string, string | undefined> = process.env): { send: NativeSend; platforms: NativePlatform[] } | null {
    const fcm = env.FCM_SERVICE_ACCOUNT_JSON_PATH ? fcmSender(env.FCM_SERVICE_ACCOUNT_JSON_PATH) : null;
    const apnsConfigured = Boolean(env.APNS_KEY_PATH && env.APNS_KEY_ID && env.APNS_TEAM_ID && env.APNS_BUNDLE_ID);
    if (env.APNS_ENV && !['sandbox', 'production'].includes(env.APNS_ENV)) throw new Error('APNS_ENV must be sandbox or production');
    const apns = apnsConfigured ? apnsSender({ keyPath: env.APNS_KEY_PATH!, keyId: env.APNS_KEY_ID!, teamId: env.APNS_TEAM_ID!, bundleId: env.APNS_BUNDLE_ID!, production: env.APNS_ENV === 'production' }) : null;
    if (!fcm && !apns) return null;
    const platforms: NativePlatform[] = [...(fcm ? ['fcm' as const] : []), ...(apns ? ['apns' as const, 'apns-voip' as const] : [])];
    return {
        platforms,
        send: (platform, token, payload) => platform === 'fcm' ? fcm!(token, payload) : apns!(platform, token, payload),
    };
}
