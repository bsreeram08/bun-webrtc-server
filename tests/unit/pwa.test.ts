import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { startSignaling } from '../../packages/signaling/server';

const source = readFileSync(new URL('../../packages/signaling/public/sw.js', import.meta.url), 'utf8');
function worker(network: () => Promise<Response>) {
    const handlers: Record<string, (event: any) => void> = {};
    const saved = new Map<string, Response>([['/app.js', new Response('offline app')]]);
    const cache = { match: async (path: string) => saved.get(path)?.clone(), put: async (path: string, response: Response) => { saved.set(path, response); } };
    runInNewContext(source, { URL, self: { location: { origin: 'https://calls.example' }, addEventListener: (name: string, handler: any) => { handlers[name] = handler; } }, caches: { open: async () => cache }, fetch: network });
    return { saved, fetch(request: Request) { let result: Promise<Response> | undefined; handlers.fetch({ request, respondWith(value: Promise<Response>) { result = value; } }); return result; } };
}
describe('installable app privacy boundaries', () => {
    test('manifest launches without an invitation and exposes only public assets', async () => {
        const app = startSignaling({ adminToken: 'test-admin-token-that-is-long-enough', origin: 'http://localhost:3000', port: 0 });
        try {
            const response = await fetch(new URL('/manifest.webmanifest', app.server.url));
            const manifest = await response.json() as any;
            expect(manifest.start_url).toBe('/'); expect(manifest.id).toBe('/');
            expect(response.headers.get('content-security-policy')).toContain("worker-src 'self'");
            for (const path of ['/sw.js', '/install.js', ...manifest.icons.map((icon: any) => icon.src)]) expect((await fetch(new URL(path, app.server.url))).status).toBe(200);
            expect((await fetch(new URL('/chat-history', app.server.url))).status).toBe(404);
            expect((await fetch(new URL('/chat-backup', app.server.url))).status).toBe(404);
        } finally { await app.stop(); }
    });
    test('worker does not intercept room APIs, authorization, foreign origins or query strings', () => {
        const app = worker(async () => { throw new Error('must not fetch'); });
        for (const request of [
            new Request('https://calls.example/rooms/example/ice'),
            new Request('https://calls.example/app.js', { headers: { Authorization: 'Bearer private' } }),
            new Request('https://calls.example/?token=private'),
            new Request('https://other.example/app.js'),
            new Request('https://calls.example/', { method: 'POST', body: 'private' }),
        ]) expect(app.fetch(request)).toBeUndefined();
    });
    test('offline fallback serves only the public shell', async () => {
        const app = worker(async () => { throw new TypeError('Offline'); });
        expect(await (await app.fetch(new Request('https://calls.example/app.js'))!).text()).toBe('offline app');
        expect(app.fetch(new Request('https://calls.example/rooms/private'))).toBeUndefined();
    });
    test('unsuccessful or redirected responses cannot replace the offline shell', async () => {
        const failure = new Response('error', { status: 500 });
        const app = worker(async () => failure);
        expect((await app.fetch(new Request('https://calls.example/app.js'))!).status).toBe(500);
        expect(await app.saved.get('/app.js')!.text()).toBe('offline app');
        const redirect = new Response('redirect'); Object.defineProperties(redirect, { redirected: { value: true }, type: { value: 'basic' } });
        const redirected = worker(async () => redirect);
        await redirected.fetch(new Request('https://calls.example/app.js'));
        expect(await redirected.saved.get('/app.js')!.text()).toBe('offline app');
    });
});
