import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from 'bun:test';
setDefaultTimeout(30000); // Some tests wait out the one-emoji-a-second limit.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isPrivateAddress, sniff } from '../../packages/signaling/emoji';
import { startSignaling } from '../../packages/signaling/server';

const origin = 'http://localhost:3000';
const adminToken = 'emoji-test-admin-secret-0000000000000000000';
// Smallest valid images of each accepted kind (only the magic bytes matter to the sniffer).
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
const GIF = new Uint8Array([...Buffer.from('GIF89a'), 1, 0, 1, 0, 0, 0, 0, 0x21, 0xf9, 4, 0, 0, 0, 0, 0, 0x21, 0xf9, 4, 0, 0, 0, 0, 0, 0x3b]);
const WEBP = new Uint8Array([...Buffer.from('RIFF'), 20, 0, 0, 0, ...Buffer.from('WEBPVP8 ')]);
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
let dataDir: string, app: ReturnType<typeof startSignaling>, fetched: string[], respond: (url: string) => Response, dns: Record<string, string[]>;
beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'emoji-'));
    fetched = []; respond = () => new Response(GIF); dns = { 'emojis.slackmojis.com': ['104.21.1.1'], 'cdn.example.com': ['93.184.216.34'] };
    app = startSignaling({
        adminToken, origin, port: 0, dataDir, emojiImportHosts: ['cdn.example.com'],
        emojiFetcher: async url => { fetched.push(url); return respond(url); },
        emojiResolver: async host => { if (!dns[host]) throw new Error('NXDOMAIN'); return dns[host]!; },
    });
});
afterEach(async () => { await app.stop(); await rm(dataDir, { recursive: true, force: true }); });
const user = (name: string) => { const created = app.accounts!.testing.createUser(name); return { ...created, cookie: app.accounts!.testing.cookie(created.id) }; };
const call = (path: string, method = 'GET', cookie?: string, body?: unknown, extra: Record<string, string> = {}) => fetch(new URL(path, app.server.url), {
    method, headers: { 'Content-Type': 'application/json', ...(method !== 'GET' ? { Origin: origin } : {}), ...(cookie ? { Cookie: cookie } : {}), ...extra }, body: body === undefined ? undefined : JSON.stringify(body),
});
const upload = (cookie: string, name: string, bytes: Uint8Array) => call('/api/emoji', 'POST', cookie, { name, image: Buffer.from(bytes).toString('base64') });
const importing = (cookie: string, name: string, url: string) => call('/api/emoji/import', 'POST', cookie, { name, url });
const tick = () => Bun.sleep(1050); // The per-user write limit is one emoji a second.

describe('custom emoji helpers', () => {
    test('images are recognised by magic bytes; SVG and anything else are refused', () => {
        expect(sniff(PNG)).toEqual({ ext: 'png', animated: false });
        expect(sniff(GIF)).toEqual({ ext: 'gif', animated: true });
        expect(sniff(WEBP)).toEqual({ ext: 'webp', animated: false });
        expect(sniff(SVG)).toBeNull();
        expect(sniff(new TextEncoder().encode('<html>'))).toBeNull();
    });
    test('private, loopback, link-local, CGNAT and mapped addresses are refused', () => {
        for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', 'not-an-ip']) expect(isPrivateAddress(address)).toBe(true);
        for (const address of ['104.21.1.1', '93.184.216.34', '2606:4700::1111']) expect(isPrivateAddress(address)).toBe(false);
    });
});

describe('custom emoji API', () => {
    test('upload, list, serve with a sandboxing CSP, and delete by its creator only', async () => {
        const alice = user('alice'), bob = user('bob');
        const created = await upload(alice.cookie, 'party_parrot', GIF);
        expect(created.status).toBe(201);
        const { emoji } = await created.json() as any;
        expect(emoji).toMatchObject({ name: 'party_parrot', animated: true });
        expect(emoji.url).toMatch(/^\/emoji\/[0-9a-f]{64}\.gif$/);
        const listed = await (await call('/api/emoji', 'GET', bob.cookie)).json() as any;
        expect(listed.emoji).toEqual([{ name: 'party_parrot', url: emoji.url, animated: true, mine: false }]);
        const served = await fetch(new URL(emoji.url, app.server.url));
        expect(served.status).toBe(200);
        expect(served.headers.get('content-type')).toBe('image/gif');
        expect(served.headers.get('x-content-type-options')).toBe('nosniff');
        expect(served.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
        expect(served.headers.get('cache-control')).toContain('immutable');
        expect(new Uint8Array(await served.arrayBuffer())).toEqual(GIF);
        expect((await fetch(new URL(`/emoji/${'b'.repeat(64)}.gif`, app.server.url))).status).toBe(404);
        expect((await fetch(new URL('/emoji/../accounts.sqlite', app.server.url))).status).toBe(404);
        expect((await call('/api/emoji/party_parrot', 'DELETE', bob.cookie)).status).toBe(403);
        expect((await call('/api/emoji/party_parrot', 'DELETE', alice.cookie)).status).toBe(200);
        expect((await fetch(new URL(emoji.url, app.server.url))).status).toBe(404);
    });
    test('the server admin token can delete anyone’s emoji', async () => {
        const alice = user('alice');
        await upload(alice.cookie, 'cat', PNG);
        expect((await call('/api/emoji/cat', 'DELETE', undefined, undefined, { Authorization: `Bearer ${adminToken}` })).status).toBe(200);
    });
    test('auth, origin, names, uniqueness, size and format rules', async () => {
        const alice = user('alice');
        expect((await call('/api/emoji')).status).toBe(401);
        expect((await fetch(new URL('/api/emoji', app.server.url), { method: 'POST', headers: { Cookie: alice.cookie, 'Content-Type': 'application/json' }, body: '{}' })).status).toBe(403);
        for (const name of ['a', 'UPPER', 'has space', 'x'.repeat(33), '../evil', 'semi;colon']) { expect((await upload(alice.cookie, name, PNG)).status).toBe(400); await tick(); }
        expect((await upload(alice.cookie, 'svg_attack', SVG)).status).toBe(400); await tick();
        expect((await upload(alice.cookie, 'too_big', new Uint8Array([...PNG, ...new Uint8Array(512 * 1024)]))).status).toBe(400); await tick();
        expect((await upload(alice.cookie, 'ok_one', PNG)).status).toBe(201); await tick();
        expect((await upload(alice.cookie, 'ok_one', WEBP)).status).toBe(409);
    });
    test('writes are rate limited per user', async () => {
        const alice = user('alice');
        expect((await upload(alice.cookie, 'first', PNG)).status).toBe(201);
        expect((await upload(alice.cookie, 'second', PNG)).status).toBe(429);
    });
});

describe('custom emoji import (server-side fetch)', () => {
    test('imports from an allowlisted host over https without following redirects', async () => {
        const alice = user('alice');
        const response = await importing(alice.cookie, 'parrot', 'https://emojis.slackmojis.com/emojis/images/1/1/parrot.gif');
        expect(response.status).toBe(201);
        expect(fetched).toEqual(['https://emojis.slackmojis.com/emojis/images/1/1/parrot.gif']);
        await tick();
        expect((await importing(alice.cookie, 'extra_host', 'https://cdn.example.com/a.gif')).status).toBe(201); // EMOJI_IMPORT_HOSTS
    });
    test('SSRF defences: scheme, host allowlist, private DNS, redirects, size, SVG and magic bytes', async () => {
        const alice = user('alice');
        const attempt = async (url: string) => { const status = (await importing(alice.cookie, 'x_emoji', url)).status; await tick(); return status; };
        expect(await attempt('http://emojis.slackmojis.com/a.gif')).toBe(400);
        expect(await attempt('https://evil.example/a.gif')).toBe(400);
        expect(await attempt('https://127.0.0.1/a.gif')).toBe(400);
        expect(await attempt('https://user:pass@emojis.slackmojis.com/a.gif')).toBe(400);
        expect(await attempt('https://emojis.slackmojis.com:8443/a.gif')).toBe(400);
        dns['emojis.slackmojis.com'] = ['104.21.1.1', '10.0.0.5']; // Any private answer refuses the host.
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        dns['emojis.slackmojis.com'] = ['169.254.169.254'];
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        dns['emojis.slackmojis.com'] = ['104.21.1.1'];
        respond = () => new Response(null, { status: 302, headers: { Location: 'http://169.254.169.254/latest/meta-data' } });
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        respond = () => new Response(new Uint8Array([...GIF, ...new Uint8Array(600 * 1024)]));
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        respond = () => new Response(SVG, { headers: { 'Content-Type': 'image/gif' } }); // Content-Type is never trusted.
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        respond = () => new Response(new TextEncoder().encode('<html>not an image</html>'), { headers: { 'Content-Type': 'image/png' } });
        expect(await attempt('https://emojis.slackmojis.com/a.gif')).toBe(400);
        expect(((await (await call('/api/emoji', 'GET', alice.cookie)).json()) as any).emoji).toEqual([]);
    });
});

describe('request body limits', () => {
    const stream = (bytes: number) => new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(bytes).fill(32)); controller.close(); } });
    test('bodies without an exact Content-Length (chunked) are refused on every JSON route', async () => {
        const alice = user('alice');
        for (const [path, method] of [['/api/messages', 'POST'], ['/api/login/options', 'POST'], ['/api/keys', 'PUT']] as const) {
            const response = await fetch(new URL(path, app.server.url), { method, headers: { Origin: origin, Cookie: alice.cookie, 'Content-Type': 'application/json' }, body: stream(200 * 1024), duplex: 'half' } as any);
            expect(response.status).toBe(411);
        }
    });
    test('declared bodies over 128 KiB are refused outside emoji uploads', async () => {
        const alice = user('alice');
        for (const [path, method] of [['/api/messages', 'POST'], ['/api/login/options', 'POST'], ['/api/keys', 'PUT']] as const) {
            expect((await call(path, method, alice.cookie, { padding: 'x'.repeat(200 * 1024) })).status).toBe(413);
        }
    });
    test('an unauthenticated emoji upload is refused before its body is read', async () => {
        // The body never finishes: if the server tried to buffer it, this request would hang until the timeout.
        const stalled = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(1024)); } });
        const started = Date.now();
        const response = await fetch(new URL('/api/emoji', app.server.url), { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', 'Content-Length': String(700 * 1024) }, body: stalled, duplex: 'half', signal: AbortSignal.timeout(4000) } as any);
        expect(response.status).toBe(401);
        expect(Date.now() - started).toBeLessThan(3000);
    });
    test('an authenticated emoji upload near the limit works', async () => {
        const alice = user('alice'), big = new Uint8Array(500 * 1024); big.set(PNG);
        expect((await upload(alice.cookie, 'large_one', big)).status).toBe(201);
    });
});
