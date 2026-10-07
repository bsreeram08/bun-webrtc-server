import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import http2 from 'node:http2';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apnsRequest, apnsSender, fcmMessage, fcmSender, invalidToken, signJwt, validNativeToken, type NativePayload, type NativePlatform } from '../../packages/signaling/native-push';
import { androidOrigins, nativeApps, startSignaling, wellKnown } from '../../packages/signaling/server';
import { createInvite } from '../../packages/signaling/accounts';

const origin = 'http://localhost:3000';
const adminToken = 'native-test-admin-secret-0000000000000000';
const cert = Array(32).fill('AB').join(':');
const apkHash = Buffer.from(cert.replaceAll(':', ''), 'hex').toString('base64url');
const apps = { appleAppIds: ['ABCDE12345.in.sreerams.calls'], androidPackage: 'in.sreerams.calls', androidCertSha256: [cert] };
const fcmToken = `fcm-${'a'.repeat(140)}:APA91b_x`, apnsToken = 'ab'.repeat(32);
type Sent = { platform: NativePlatform; token: string; payload: NativePayload };
let dataDir: string, app: ReturnType<typeof startSignaling>, sent: Sent[], result: { status: number; reason?: string };
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'native-'));
    sent = []; result = { status: 200 };
    app = startSignaling({ adminToken, origin, port: 0, dataDir, ringAckMs: 50, apps, pushSend: async () => ({ statusCode: 201 }),
        nativePush: { platforms: ['fcm', 'apns', 'apns-voip'], send: async (platform, token, payload) => { sent.push({ platform, token, payload }); return result; } } });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });

/** A native client: no Origin header, optional bearer token. */
const native = (path: string, init: { method?: string; body?: unknown; bearer?: string; headers?: Record<string, string> } = {}) => fetch(new URL(path, app.server.url), {
    method: init.method ?? 'GET', body: init.body === undefined ? undefined : JSON.stringify(init.body),
    headers: { 'Content-Type': 'application/json', ...(init.bearer ? { Authorization: `Bearer ${init.bearer}` } : {}), ...init.headers },
});
const web = (path: string, init: { method?: string; body?: unknown; cookie?: string; headers?: Record<string, string> } = {}) => fetch(new URL(path, app.server.url), {
    method: init.method ?? 'GET', body: init.body === undefined ? undefined : JSON.stringify(init.body),
    headers: { 'Content-Type': 'application/json', Origin: origin, ...(init.cookie ? { Cookie: init.cookie } : {}), ...init.headers },
});
function user(name: string) {
    const created = app.accounts!.testing.createUser(name);
    return { ...created, cookie: app.accounts!.testing.cookie(created.id), bearer: app.accounts!.testing.bearer(created.id) };
}
async function befriend(a: ReturnType<typeof user>, b: ReturnType<typeof user>) {
    expect((await native('/api/contacts', { method: 'POST', body: { username: b.username }, bearer: a.bearer })).status).toBe(202);
    expect((await native(`/api/contacts/${a.username}/accept`, { method: 'POST', body: {}, bearer: b.bearer })).status).toBe(200);
}
function events(headers: Record<string, string>) {
    const url = new URL('/api/events', app.server.url); url.protocol = 'ws:';
    const socket = new WebSocket(url, { headers } as any);
    const inbox: any[] = [];
    socket.onmessage = event => inbox.push(JSON.parse(String(event.data)));
    const next = async (type: string) => {
        for (let i = 0; i < 100; i++) { const index = inbox.findIndex(message => message.type === type); if (index >= 0) return inbox.splice(index, 1)[0]; await Bun.sleep(10); }
        throw new Error(`No ${type}`);
    };
    return { socket, next, closed: new Promise<CloseEvent>(resolve => socket.addEventListener('close', resolve as any, { once: true })), opened: new Promise(resolve => socket.addEventListener('open', resolve, { once: true })) };
}

// ---------- A software passkey: enough CBOR and WebAuthn to drive real ceremonies ----------
function cbor(value: unknown): Buffer {
    const head = (major: number, length: number) => length < 24 ? Buffer.from([major << 5 | length]) : length < 256 ? Buffer.from([major << 5 | 24, length]) : Buffer.from([major << 5 | 25, length >> 8, length & 255]);
    if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
    if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
    if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
    const entries = value instanceof Map ? [...value] : Object.entries(value as object);
    return Buffer.concat([head(5, entries.length), ...entries.flatMap(([key, item]) => [cbor(key), cbor(item)])]);
}
function authenticator() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    const credentialId = Buffer.from(createHash('sha256').update(String(Math.random())).digest()).subarray(0, 16);
    let counter = 0;
    const rpHash = createHash('sha256').update('localhost').digest();
    const authData = (attested: boolean) => {
        const count = Buffer.alloc(4); count.writeUInt32BE(++counter);
        if (!attested) return Buffer.concat([rpHash, Buffer.from([0x05]), count]);
        const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
        const length = Buffer.alloc(2); length.writeUInt16BE(credentialId.length);
        return Buffer.concat([rpHash, Buffer.from([0x45]), count, Buffer.alloc(16), length, credentialId, cose]);
    };
    const id = credentialId.toString('base64url');
    return {
        create(challenge: string, clientOrigin: string) {
            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: clientOrigin, crossOrigin: false }));
            const attestationObject = cbor({ fmt: 'none', attStmt: {}, authData: authData(true) });
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: clientDataJSON.toString('base64url'), attestationObject: attestationObject.toString('base64url'), transports: ['internal'] } };
        },
        get(challenge: string, clientOrigin: string) {
            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: clientOrigin, crossOrigin: false }));
            const data = authData(false);
            const signature = sign('sha256', Buffer.concat([data, createHash('sha256').update(clientDataJSON).digest()]), privateKey);
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: data.toString('base64url'), signature: signature.toString('base64url') } };
        },
    };
}
async function nativeRegister(username: string, client: string, passkey: ReturnType<typeof authenticator>, clientOrigin: string) {
    const invite = createInvite(app.accounts!.testing.db, null).code;
    const options = await (await native('/api/register/options', { method: 'POST', body: { username, invite, client } })).json() as any;
    return native('/api/register/verify', { method: 'POST', body: { flowId: options.flowId, response: passkey.create(options.options.challenge, clientOrigin) } });
}

describe('native bearer sessions', () => {
    test('a bearer token authenticates API calls and the events socket only without an Origin header', async () => {
        const alice = user('alice');
        expect((await (await native('/api/me', { bearer: alice.bearer })).json() as any).user.username).toBe('alice');
        // Any Origin means a browser: same-origin is refused by the account layer, foreign by the server.
        expect((await native('/api/me', { bearer: alice.bearer, headers: { Origin: origin } })).status).toBe(403);
        expect((await native('/api/me', { bearer: alice.bearer, headers: { Origin: 'https://evil.example' } })).status).toBe(403);
        expect((await native('/api/contacts', { method: 'POST', body: { username: 'bob' }, bearer: alice.bearer, headers: { Origin: origin } })).status).toBe(403);
        const stream = events({ Authorization: `Bearer ${alice.bearer}` }); await stream.opened;
        expect((await stream.next('hello')).type).toBe('hello');
        stream.socket.close();
        const refused = events({ Authorization: `Bearer ${alice.bearer}`, Origin: origin });
        expect((await refused.closed).code).not.toBe(1000);
    });
    test('cookie and bearer sessions cannot stand in for each other', async () => {
        const alice = user('alice');
        const cookieToken = alice.cookie.split('=')[1]!;
        expect((await native('/api/me', { bearer: cookieToken })).status).toBe(401);
        expect((await web('/api/me', { cookie: `session=${alice.bearer}` })).status).toBe(401);
        expect((await web('/api/me', { cookie: alice.cookie })).status).toBe(200);
        expect((await native('/api/me', { bearer: 'not-a-token' })).status).toBe(401);
        expect((await native('/api/me', { headers: { Cookie: alice.cookie } })).status).toBe(200); // Unchanged: cookie GETs need no Origin.
        expect((await native('/api/contacts', { method: 'POST', body: { username: 'bob' }, headers: { Cookie: alice.cookie } })).status).toBe(403); // Cookie writes still need it.
    });
    test('sign-out and sign-out everywhere revoke bearer tokens and close their streams', async () => {
        const alice = user('alice'), second = app.accounts!.testing.bearer(alice.id, 'android');
        const stream = events({ Authorization: `Bearer ${second}` }); await stream.opened;
        const signedOut = await native('/api/logout', { method: 'POST', body: {}, bearer: alice.bearer });
        expect(signedOut.status).toBe(200);
        expect(signedOut.headers.get('set-cookie')).toBeNull();
        expect((await native('/api/me', { bearer: alice.bearer })).status).toBe(401);
        expect((await native('/api/me', { bearer: second })).status).toBe(200);
        expect((await native('/api/logout?all=1', { method: 'POST', body: {}, bearer: second })).status).toBe(200);
        expect((await stream.closed).code).toBe(4401);
        expect((await web('/api/me', { cookie: alice.cookie })).status).toBe(401);
    });
});

describe('native passkeys', () => {
    test('a native app registers and signs in with a passkey and gets a bearer token, never a cookie', async () => {
        const passkey = authenticator();
        const registered = await nativeRegister('alice', 'android', passkey, `android:apk-key-hash:${apkHash}`);
        expect(registered.status).toBe(201);
        expect(registered.headers.get('set-cookie')).toBeNull();
        const body = await registered.json() as any;
        expect(body.session.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect((await native('/api/me', { bearer: body.session.token })).status).toBe(200);
        const login = await (await native('/api/login/options', { method: 'POST', body: { client: 'ios' } })).json() as any;
        const signedIn = await native('/api/login/verify', { method: 'POST', body: { flowId: login.flowId, response: passkey.get(login.options.challenge, origin) } });
        expect(signedIn.status).toBe(200);
        expect(signedIn.headers.get('set-cookie')).toBeNull();
        const token = ((await signedIn.json()) as any).session.token;
        expect(token).not.toBe(body.session.token);
        expect((await native('/api/me', { bearer: token })).status).toBe(200);
    });
    test('web ceremonies still set a cookie and never accept the Android app origin', async () => {
        const passkey = authenticator();
        const invite = createInvite(app.accounts!.testing.db, null).code;
        const options = await (await web('/api/register/options', { method: 'POST', body: { username: 'bob', invite } })).json() as any;
        const forged = await web('/api/register/verify', { method: 'POST', body: { flowId: options.flowId, response: passkey.create(options.options.challenge, `android:apk-key-hash:${apkHash}`) } });
        expect(forged.status).toBe(400);
        const again = await (await web('/api/register/options', { method: 'POST', body: { username: 'bob', invite } })).json() as any;
        const ok = await web('/api/register/verify', { method: 'POST', body: { flowId: again.flowId, response: passkey.create(again.options.challenge, origin) } });
        expect(ok.status).toBe(201);
        expect(ok.headers.get('set-cookie')).toContain('session=');
        expect(((await ok.json()) as any).session).toBeUndefined();
    });
    test('native sign-in must name a platform, and a ceremony cannot switch between web and native', async () => {
        expect((await native('/api/login/options', { method: 'POST', body: {} })).status).toBe(400);
        expect((await native('/api/login/options', { method: 'POST', body: { client: 'blackberry' } })).status).toBe(400);
        const passkey = authenticator();
        await nativeRegister('carol', 'ios', passkey, origin);
        const nativeFlow = await (await native('/api/login/options', { method: 'POST', body: { client: 'ios' } })).json() as any;
        expect((await web('/api/login/verify', { method: 'POST', body: { flowId: nativeFlow.flowId, response: passkey.get(nativeFlow.options.challenge, origin) } })).status).toBe(400);
        const webFlow = await (await web('/api/login/options', { method: 'POST', body: {} })).json() as any;
        expect((await native('/api/login/verify', { method: 'POST', body: { flowId: webFlow.flowId, response: passkey.get(webFlow.options.challenge, origin) } })).status).toBe(400);
    });
    test('Android origins come from configured key hashes and signing-certificate fingerprints', () => {
        expect(androidOrigins({ androidCertSha256: [cert] })).toEqual([`android:apk-key-hash:${apkHash}`]);
        expect(androidOrigins({ androidCertSha256: [cert], androidApkKeyHashes: [apkHash] })).toHaveLength(1);
        expect(nativeApps({ APPLE_APP_IDS: 'ABCDE12345.in.sreerams.calls', ANDROID_PACKAGE: 'in.sreerams.calls', ANDROID_CERT_SHA256: cert.toLowerCase() }).androidCertSha256).toEqual([cert]);
        for (const env of [{ APPLE_APP_IDS: 'in.sreerams.calls' }, { ANDROID_PACKAGE: 'not a package' }, { ANDROID_CERT_SHA256: 'AB:CD' }, { ANDROID_APK_KEY_HASHES: 'short' }]) expect(() => nativeApps(env)).toThrow();
    });
});

describe('app association files and versions', () => {
    test('well-known files are exact JSON when configured and 404 otherwise', async () => {
        const apple = await fetch(new URL('/.well-known/apple-app-site-association', app.server.url), { redirect: 'manual' });
        expect(apple.status).toBe(200);
        expect(apple.headers.get('content-type')).toBe('application/json');
        expect(await apple.json()).toEqual({ applinks: { details: [{ appIDs: ['ABCDE12345.in.sreerams.calls'], components: [{ '/': '/*' }] }] }, webcredentials: { apps: ['ABCDE12345.in.sreerams.calls'] } });
        const android = await fetch(new URL('/.well-known/assetlinks.json', app.server.url));
        expect(android.headers.get('content-type')).toBe('application/json');
        expect(await android.json()).toEqual([{ relation: ['delegate_permission/common.get_login_creds', 'delegate_permission/common.handle_all_urls'], target: { namespace: 'android_app', package_name: 'in.sreerams.calls', sha256_cert_fingerprints: [cert] } }]);
        expect(wellKnown({})).toEqual({ apple: null, android: null });
        const bare = startSignaling({ adminToken, origin, port: 0 });
        try {
            for (const path of ['/.well-known/apple-app-site-association', '/.well-known/assetlinks.json', '/.well-known/other']) expect((await fetch(new URL(path, bare.server.url))).status).toBe(404);
        } finally { await bare.stop(); }
    });
    test('the version endpoint tells apps the API level and minimum versions, without CORS', async () => {
        const response = await native('/api/version');
        expect(await response.json()).toEqual({ api: 1, minClient: { ios: '1.0.0', android: '1.0.0', macos: '1.0.0', windows: '1.0.0', linux: '1.0.0' } });
        expect(response.headers.get('access-control-allow-origin')).toBeNull();
    });
});

describe('native push', () => {
    const install = 'install-aaaaaaaaaaaaaaaa', otherInstall = 'install-bbbbbbbbbbbbbbbb', voipToken = 'cd'.repeat(32);
    const register = (bearer: string, platform: string, token: string, installId = install) => native('/api/push/native', { method: 'POST', body: { platform, token, installId }, bearer });
    const confirm = (bearer: string, platform: string, token: string, nonce: string) => native('/api/push/native/confirm', { method: 'POST', body: { platform, token, nonce }, bearer });
    /** The nonce the server pushed to this token (what the real device would receive). */
    const nonceFor = (token: string) => (sent.filter(item => item.token === token && item.payload.type === 'verify').at(-1)!.payload as { nonce: string }).nonce;
    async function bind(bearer: string, platform: string, token: string, installId = install) {
        expect((await register(bearer, platform, token, installId)).status).toBe(202);
        expect((await confirm(bearer, platform, token, nonceFor(token))).status).toBe(201);
    }
    const owner = (platform: string, token: string) => (app.accounts!.testing.db.query('SELECT user_id FROM push_native WHERE platform = ? AND token = ?').get(platform, token) as any)?.user_id;
    const count = () => (app.accounts!.testing.db.query('SELECT COUNT(*) AS count FROM push_native').get() as any).count;

    test('device tokens are validated, need a native session, and bind only after the device echoes a pushed nonce', async () => {
        const alice = user('alice');
        expect(validNativeToken('fcm', fcmToken)).toBe(fcmToken);
        expect(validNativeToken('apns', apnsToken.toUpperCase())).toBe(apnsToken);
        for (const [platform, token] of [['fcm', 'short'], ['fcm', `${'a'.repeat(120)}/../x`], ['apns', 'zz'.repeat(32)], ['apns-voip', 'ab'], ['gcm', fcmToken], ['apns', 42]] as const) expect(validNativeToken(platform, token)).toBeNull();
        expect((await native('/api/push/native', { method: 'POST', body: { platform: 'fcm', token: fcmToken, installId: install } })).status).toBe(403); // No Origin, no token.
        expect((await register('x'.repeat(43), 'fcm', fcmToken)).status).toBe(401);
        expect((await web('/api/push/native', { method: 'POST', body: { platform: 'fcm', token: fcmToken, installId: install }, cookie: alice.cookie })).status).toBe(403);
        expect((await register(alice.bearer, 'fcm', 'short')).status).toBe(400);
        expect((await register(alice.bearer, 'fcm', fcmToken, 'short')).status).toBe(400); // Install id required.
        expect((await register(alice.bearer, 'fcm', fcmToken)).status).toBe(202);
        expect(count()).toBe(0); // Pending until confirmed.
        const verify = sent.at(-1)!;
        expect(verify).toEqual({ platform: 'fcm', token: fcmToken, payload: { type: 'verify', nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) } });
        expect((await confirm(alice.bearer, 'fcm', fcmToken, nonceFor(fcmToken))).status).toBe(201);
        expect(owner('fcm', fcmToken)).toBe(alice.id);
        expect((await register(alice.bearer, 'fcm', fcmToken)).status).toBe(201); // Already bound here: no new nonce.
        expect((await native('/api/push/native', { method: 'DELETE', body: { platform: 'fcm', token: fcmToken }, bearer: alice.bearer })).status).toBe(200);
        expect(count()).toBe(0);
        const bare = startSignaling({ adminToken, origin, port: 0, dataDir: await mkdtemp(join(tmpdir(), 'native-bare-')), pushSend: async () => ({ statusCode: 201 }) });
        try {
            const bob = bare.accounts!.testing.bearer(bare.accounts!.testing.createUser('bob').id);
            const response = await fetch(new URL('/api/push/native', bare.server.url), { method: 'POST', body: JSON.stringify({ platform: 'fcm', token: fcmToken, installId: install }), headers: { Authorization: `Bearer ${bob}` } });
            expect(response.status).toBe(404);
        } finally { await bare.stop(); }
    });
    test('another account that learns a token cannot move it without the nonce; a confirmed sign-in on that device can', async () => {
        const alice = user('alice'), mallory = user('mallory');
        await bind(alice.bearer, 'fcm', fcmToken);
        const aliceNonce = nonceFor(fcmToken);
        expect((await register(mallory.bearer, 'fcm', fcmToken)).status).toBe(202);
        expect(owner('fcm', fcmToken)).toBe(alice.id); // Still Alice's while Mallory's claim is pending.
        expect((await confirm(mallory.bearer, 'fcm', fcmToken, 'guess'.padEnd(43, 'x'))).status).toBe(400);
        expect((await confirm(mallory.bearer, 'fcm', fcmToken, aliceNonce)).status).toBe(400); // An old, used nonce.
        expect(owner('fcm', fcmToken)).toBe(alice.id);
        await app.accounts!.pushNotify(alice.id, { type: 'message', from: 'bob' });
        expect(sent.at(-1)).toEqual({ platform: 'fcm', token: fcmToken, payload: { type: 'message', from: 'bob' } });
        // The real device (now signed in as Mallory) receives the nonce and confirms: that rebind is legitimate.
        expect((await register(mallory.bearer, 'fcm', fcmToken)).status).toBe(202);
        expect((await confirm(mallory.bearer, 'fcm', fcmToken, nonceFor(fcmToken))).status).toBe(201);
        expect(owner('fcm', fcmToken)).toBe(mallory.id);
    });
    test('nonces are single-use and expire; a wrong guess spends the claim; pending claims are capped', async () => {
        const alice = user('alice');
        expect((await register(alice.bearer, 'fcm', fcmToken)).status).toBe(202);
        const nonce = nonceFor(fcmToken);
        expect((await confirm(alice.bearer, 'fcm', fcmToken, 'wrong')).status).toBe(400);
        expect((await confirm(alice.bearer, 'fcm', fcmToken, nonce)).status).toBe(400); // Spent by the wrong attempt.
        expect((await register(alice.bearer, 'fcm', fcmToken)).status).toBe(202);
        const fresh = nonceFor(fcmToken);
        expect((await confirm(alice.bearer, 'fcm', fcmToken, fresh)).status).toBe(201);
        expect((await confirm(alice.bearer, 'fcm', fcmToken, fresh)).status).toBe(400); // Reused.
        app.accounts!.testing.db.query('DELETE FROM push_native').run();
        expect((await register(alice.bearer, 'apns', apnsToken)).status).toBe(202);
        app.accounts!.testing.db.query('UPDATE push_native_pending SET expires_at = 0').run();
        expect((await confirm(alice.bearer, 'apns', apnsToken, nonceFor(apnsToken))).status).toBe(400); // Expired.
        expect(count()).toBe(0);
        await Bun.sleep(1000); // Fresh rate-limit window.
        const statuses = [];
        for (let index = 0; index < 6; index++) statuses.push((await register(alice.bearer, 'apns', String(index).repeat(64))).status);
        expect(statuses).toEqual([202, 202, 202, 202, 202, 429]);
    });
    test('a token Google or Apple rejects during registration is not kept pending', async () => {
        const alice = user('alice');
        result = { status: 410, reason: 'Unregistered' };
        expect((await register(alice.bearer, 'apns', apnsToken)).status).toBe(400);
        expect(app.accounts!.testing.db.query('SELECT COUNT(*) AS count FROM push_native_pending').get()).toEqual({ count: 0 });
    });
    test('VoIP tokens bind only beside a confirmed APNs token of the same install; a held token moves only with a VoIP nonce', async () => {
        const alice = user('alice'), mallory = user('mallory');
        expect((await register(alice.bearer, 'apns-voip', voipToken)).status).toBe(409);
        await bind(alice.bearer, 'apns', apnsToken);
        expect((await register(alice.bearer, 'apns-voip', voipToken, otherInstall)).status).toBe(409);
        expect((await register(alice.bearer, 'apns-voip', voipToken)).status).toBe(201); // Unclaimed: binds directly.
        expect(sent.some(item => item.platform === 'apns-voip')).toBe(false);
        // Mallory claims the held token: only a VoIP nonce push goes out, and the binding stays with alice.
        await bind(mallory.bearer, 'apns', 'ef'.repeat(32), otherInstall);
        expect((await register(mallory.bearer, 'apns-voip', voipToken, otherInstall)).status).toBe(202);
        expect(sent.filter(item => item.platform === 'apns-voip').map(item => item.payload.type)).toEqual(['verify']);
        expect((await confirm(mallory.bearer, 'apns-voip', voipToken, 'guess')).status).toBe(400);
        expect(owner('apns-voip', voipToken)).toBe(alice.id);
        // The device that really holds a token (it receives the nonce) can always move it.
        const second = '12'.repeat(32);
        await Bun.sleep(1000); // Fresh rate-limit window.
        expect((await register(alice.bearer, 'apns-voip', second)).status).toBe(201);
        await Bun.sleep(1000);
        expect((await register(mallory.bearer, 'apns-voip', second, otherInstall)).status).toBe(202);
        expect((await confirm(mallory.bearer, 'apns-voip', second, nonceFor(second))).status).toBe(201);
        expect(owner('apns-voip', second)).toBe(mallory.id);
    });
    test('verification pushes to one device token are budgeted, so claims cannot be used to ring a phone repeatedly', async () => {
        const alice = user('alice'), mallory = user('mallory');
        await bind(alice.bearer, 'apns', apnsToken);
        expect((await register(alice.bearer, 'apns-voip', voipToken)).status).toBe(201);
        await bind(mallory.bearer, 'apns', 'ef'.repeat(32), otherInstall);
        expect((await register(mallory.bearer, 'apns-voip', voipToken, otherInstall)).status).toBe(202);
        await Bun.sleep(1000); // Fresh rate-limit window: the per-token budget is what refuses.
        expect((await register(mallory.bearer, 'apns-voip', voipToken, otherInstall)).status).toBe(429);
        expect(sent.filter(item => item.platform === 'apns-voip')).toHaveLength(1);
        // Mallory's spent budget does not stop the real holder's install from proving it again.
        await Bun.sleep(1000);
        const carol = user('carol');
        await bind(carol.bearer, 'apns', '34'.repeat(32), 'install-cccccccccccccccc');
        expect((await register(carol.bearer, 'apns-voip', voipToken, 'install-cccccccccccccccc')).status).toBe(202);
    });
    test('messages reach FCM and APNs alerts; calls use VoIP instead of an alert on that device; no text ever', async () => {
        const alice = user('alice'), bob = user('bob');
        await befriend(alice, bob);
        await bind(bob.bearer, 'fcm', fcmToken, otherInstall);
        await bind(bob.bearer, 'apns', apnsToken);
        expect((await register(bob.bearer, 'apns-voip', voipToken)).status).toBe(201);
        sent = [];
        const envelope = Buffer.from('ciphertext with a secret marker').toString('base64url');
        expect((await native('/api/messages', { method: 'POST', body: { to: 'bob', envelope }, bearer: alice.bearer })).status).toBe(201);
        await Bun.sleep(50);
        expect(sent.map(item => item.platform).sort()).toEqual(['apns', 'fcm']);
        expect(sent.every(item => JSON.stringify(item.payload) === JSON.stringify({ type: 'message', from: 'alice' }))).toBe(true);
        sent = [];
        const call = await (await native('/api/conversations/bob/session', { method: 'POST', body: { kind: 'video' }, bearer: alice.bearer })).json() as any;
        await Bun.sleep(50);
        expect(sent.map(item => item.platform).sort()).toEqual(['apns-voip', 'fcm']);
        expect(sent[0]!.payload).toEqual({ type: 'call', from: 'alice', kind: 'video', roomId: call.roomId });
    });
    test('tokens Google or Apple reject as gone are deleted; transient failures are kept; others\' rows are untouched', async () => {
        const alice = user('alice'), bob = user('bob');
        await bind(alice.bearer, 'fcm', fcmToken);
        await bind(alice.bearer, 'apns', apnsToken);
        await bind(bob.bearer, 'apns', 'ef'.repeat(32), otherInstall);
        result = { status: 503 };
        await app.accounts!.pushNotify(alice.id, { type: 'message', from: 'bob' });
        expect(count()).toBe(3);
        result = { status: 404, reason: 'UNREGISTERED' }; // Gone for FCM; Apple uses 410, so the APNs token stays.
        await app.accounts!.pushNotify(alice.id, { type: 'message', from: 'bob' });
        expect(count()).toBe(2);
        result = { status: 410, reason: 'Unregistered' };
        await app.accounts!.pushNotify(alice.id, { type: 'message', from: 'bob' });
        expect(count()).toBe(1);
        expect(owner('apns', 'ef'.repeat(32))).toBe(bob.id);
        expect((await native('/api/push/native', { method: 'DELETE', body: { platform: 'apns', token: 'ef'.repeat(32) }, bearer: alice.bearer })).status).toBe(200);
        expect(owner('apns', 'ef'.repeat(32))).toBe(bob.id); // DELETE only touches the caller's rows.
        expect(invalidToken('apns', { status: 410, reason: 'Unregistered' })).toBe(true);
        expect(invalidToken('apns-voip', { status: 400, reason: 'BadDeviceToken' })).toBe(true);
        expect(invalidToken('apns', { status: 429, reason: 'TooManyRequests' })).toBe(false);
        expect(invalidToken('fcm', { status: 500, reason: 'INTERNAL' })).toBe(false);
    });
    test('signing out removes that device\'s tokens and pending claims', async () => {
        const alice = user('alice');
        await bind(alice.bearer, 'fcm', fcmToken);
        expect((await register(alice.bearer, 'apns', apnsToken)).status).toBe(202);
        await native('/api/logout', { method: 'POST', body: {}, bearer: alice.bearer });
        expect(count()).toBe(0);
        expect(app.accounts!.testing.db.query('SELECT COUNT(*) AS count FROM push_native_pending').get()).toEqual({ count: 0 });
    });
});

describe('native push wire formats', () => {
    const leaky = { type: 'message', from: 'alice', text: 'secret text', token: 'secret token' } as unknown as NativePayload;
    test('FCM messages are data-only and carry only the event fields', () => {
        expect(fcmMessage('device', leaky)).toEqual({ message: { token: 'device', data: { type: 'message', from: 'alice' }, android: { priority: 'high', ttl: '86400s' } } });
        const call = fcmMessage('device', { type: 'call', from: 'alice', kind: 'voice', roomId: 'r'.repeat(43), text: 'secret' } as any);
        expect(call.message.android).toEqual({ priority: 'high', ttl: '30s' });
        expect(JSON.stringify(call)).not.toContain('secret');
    });
    test('APNs alerts and VoIP pushes use the right topic, type, priority and expiry', () => {
        const alert = apnsRequest('apns', leaky, 'in.sreerams.calls', 1000);
        expect(alert.headers).toEqual({ 'apns-topic': 'in.sreerams.calls', 'apns-push-type': 'alert', 'apns-priority': '10', 'apns-expiration': String(1000 + 86400) });
        expect(JSON.stringify(alert.body)).not.toContain('secret');
        const voip = apnsRequest('apns-voip', { type: 'call', from: 'alice', kind: 'video', roomId: 'room' }, 'in.sreerams.calls', 1000);
        expect(voip.headers).toEqual({ 'apns-topic': 'in.sreerams.calls.voip', 'apns-push-type': 'voip', 'apns-priority': '10', 'apns-expiration': '1030', 'apns-collapse-id': 'call-alice' });
        expect(voip.body).toEqual({ type: 'call', from: 'alice', kind: 'video', roomId: 'room', aps: {} });
    });
    test('ownership checks are silent: FCM data and an APNs background push carrying only the nonce', () => {
        expect(fcmMessage('device', { type: 'verify', nonce: 'n' })).toEqual({ message: { token: 'device', data: { type: 'verify', nonce: 'n' }, android: { priority: 'normal', ttl: '120s' } } });
        expect(apnsRequest('apns', { type: 'verify', nonce: 'n' }, 'in.sreerams.calls', 1000)).toEqual({
            headers: { 'apns-topic': 'in.sreerams.calls', 'apns-push-type': 'background', 'apns-priority': '5', 'apns-expiration': '1120' },
            body: { type: 'verify', nonce: 'n', aps: { 'content-available': 1 } },
        });
    });
    test('JWTs verify: ES256 in JOSE form for APNs, RS256 for Google', () => {
        const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
        for (const [alg, pair] of [['ES256', ec], ['RS256', rsa]] as const) {
            const [header, claims, signature] = signJwt({ alg }, { iss: 'team' }, pair.privateKey).split('.');
            const ok = verify('sha256', Buffer.from(`${header}.${claims}`), alg === 'ES256' ? { key: pair.publicKey, dsaEncoding: 'ieee-p1363' } : pair.publicKey, Buffer.from(signature!, 'base64url'));
            expect(ok).toBe(true);
        }
    });
    test('the FCM sender caches its OAuth token and reports Google\'s error code', async () => {
        const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        const path = join(dataDir, 'service-account.json');
        await writeFile(path, JSON.stringify({ project_id: 'calls-test', client_email: 'push@calls-test.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), token_uri: 'https://oauth2.googleapis.com/token' }));
        const calls: { url: string; body: string; authorization?: string }[] = [];
        let unregistered = false;
        const fetcher = (async (url: string, init: RequestInit) => {
            calls.push({ url, body: String(init.body), authorization: (init.headers as any).Authorization });
            if (url.includes('oauth2')) return Response.json({ access_token: 'oauth-token', expires_in: 3600 });
            return unregistered ? Response.json({ error: { status: 'NOT_FOUND', details: [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode: 'UNREGISTERED' }] } }, { status: 404 }) : Response.json({ name: 'ok' });
        }) as unknown as typeof fetch;
        const send = fcmSender(path, fetcher);
        expect(await send(fcmToken, { type: 'message', from: 'alice' })).toEqual({ status: 200 });
        unregistered = true;
        expect(await send(fcmToken, { type: 'message', from: 'alice' })).toEqual({ status: 404, reason: 'UNREGISTERED' });
        expect(calls.filter(call => call.url.includes('oauth2'))).toHaveLength(1);
        const assertion = new URLSearchParams(calls[0]!.body).get('assertion')!;
        expect(JSON.parse(Buffer.from(assertion.split('.')[1]!, 'base64url').toString())).toMatchObject({ iss: 'push@calls-test.iam.gserviceaccount.com', scope: 'https://www.googleapis.com/auth/firebase.messaging' });
        expect(calls[1]!.url).toBe('https://fcm.googleapis.com/v1/projects/calls-test/messages:send');
        expect(calls[1]!.authorization).toBe('Bearer oauth-token');
        expect(JSON.parse(calls[1]!.body)).toEqual(fcmMessage(fcmToken, { type: 'message', from: 'alice' }));
    });
    test('the APNs sender speaks HTTP/2 with a team-signed token and reads Apple\'s reason', async () => {
        const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const keyPath = join(dataDir, 'AuthKey.p8');
        await writeFile(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
        const seen: Record<string, any>[] = [];
        const server = http2.createServer();
        server.on('stream', (stream: http2.ServerHttp2Stream, headers) => {
            let body = '';
            stream.setEncoding('utf8'); stream.on('data', chunk => { body += chunk; });
            stream.on('end', () => {
                seen.push({ ...headers, body: JSON.parse(body) });
                const gone = String(headers[':path']).endsWith(apnsToken);
                stream.respond({ ':status': gone ? 410 : 200 }); stream.end(gone ? JSON.stringify({ reason: 'Unregistered' }) : '');
            });
        });
        await new Promise<void>(resolve => server.listen(0, resolve));
        try {
            const send = apnsSender({ keyPath, keyId: 'KEYID12345', teamId: 'TEAMID1234', bundleId: 'in.sreerams.calls', production: false, host: `http://localhost:${(server.address() as any).port}` });
            expect(await send('apns-voip', 'cd'.repeat(32), { type: 'call', from: 'alice', kind: 'voice', roomId: 'room' })).toEqual({ status: 200, reason: undefined });
            expect(await send('apns', apnsToken, { type: 'message', from: 'alice' })).toEqual({ status: 410, reason: 'Unregistered' });
            expect(seen[0]![':path']).toBe(`/3/device/${'cd'.repeat(32)}`);
            expect(seen[0]!['apns-push-type']).toBe('voip');
            expect(seen[0]!['apns-topic']).toBe('in.sreerams.calls.voip');
            const [header, claims, signature] = String(seen[0]!.authorization).replace('bearer ', '').split('.');
            expect(JSON.parse(Buffer.from(header!, 'base64url').toString())).toEqual({ alg: 'ES256', kid: 'KEYID12345' });
            expect(JSON.parse(Buffer.from(claims!, 'base64url').toString()).iss).toBe('TEAMID1234');
            expect(verify('sha256', Buffer.from(`${header}.${claims}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature!, 'base64url'))).toBe(true);
            expect(seen[1]!.body).toEqual({ type: 'message', from: 'alice', aps: { alert: { title: 'alice', body: 'New message' }, sound: 'default' } });
        } finally { server.close(); }
    });
});
