import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { startSignaling } from '../../packages/signaling/server';

// Choosing the encryption core is a local, per-account setting. A link (?core=wasm) must never switch it:
// that would move someone onto an empty key store, i.e. a new identity for every contact.
const source = readFileSync(new URL('../../packages/signaling/public/core.js', import.meta.url), 'utf8');
function page(options: { search?: string; testFlags: boolean; stored?: Record<string, string> }) {
    const storage = new Map(Object.entries(options.stored ?? {}));
    const context: Record<string, any> = {
        URLSearchParams, crypto, location: { search: options.search ?? '' },
        localStorage: { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value), removeItem: (key: string) => storage.delete(key) },
        fetch: async (path: string) => ({ ok: path === '/test-flags.json' && options.testFlags }),
    };
    context.window = context;
    runInNewContext(source, context);
    return { Core: context.Core as { backend(userId: string): Promise<string>; setBackend(userId: string, value: string): void }, storage };
}

describe('choosing the encryption core', () => {
    test('a ?core=wasm link is ignored unless the server turns test flags on', async () => {
        expect(await page({ search: '?core=wasm', testFlags: false }).Core.backend('alice')).toBe('signal');
        expect(await page({ testFlags: false, stored: { 'core-backend-test': 'wasm' } }).Core.backend('alice')).toBe('signal');
        expect(await page({ search: '?core=wasm', testFlags: true }).Core.backend('alice')).toBe('wasm');
    });
    test('the per-account setting decides, and always wins over a test override', async () => {
        const { Core, storage } = page({ testFlags: true, search: '?core=wasm' });
        Core.setBackend('alice', 'signal');
        expect(await Core.backend('alice')).toBe('signal');
        Core.setBackend('alice', 'wasm');
        expect(storage.get('core-backend-v1:alice')).toBe('wasm');
        expect(await page({ testFlags: false, stored: { 'core-backend-v1:alice': 'wasm' } }).Core.backend('alice')).toBe('wasm');
        expect(await page({ testFlags: false, stored: { 'core-backend-v1:alice': 'wasm' } }).Core.backend('bob')).toBe('signal');
    });
});

describe('test flags endpoint', () => {
    const admin = 'core-backend-test-admin-token-000000000000';
    for (const [label, origin, allow, status] of [
        ['off by default', 'http://localhost:3000', false, 404],
        ['refused on a public origin even when requested', 'https://calls.example.com', true, 404],
        ['on for a loopback origin when requested', 'http://localhost:3000', true, 200],
    ] as const) {
        test(label, async () => {
            const app = startSignaling({ adminToken: admin, origin, port: 0, allowTestFlags: allow });
            try { expect((await fetch(new URL('/test-flags.json', app.server.url))).status).toBe(status); }
            finally { await app.stop(); }
        });
    }
});
