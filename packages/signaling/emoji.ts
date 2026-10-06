import type { Database } from 'bun:sqlite';
import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { requestLimiter } from './rate-limit';

// Custom emoji: a workspace pack of small images. They are shared assets, not secrets — messages stay end to
// end encrypted and only ever carry the `:name:` text, which each recipient renders from this pack.
// Images are accepted only as PNG/APNG, GIF or WebP, recognised by their magic bytes (never by Content-Type),
// stored under a content hash and served same-origin with a sandboxing CSP. SVG is never accepted.
export const NAME = /^[a-z0-9_+-]{2,32}$/;
export const MAX_BYTES = 512 * 1024, MAX_EMOJI = 500, MAX_PER_USER = 100, FETCH_TIMEOUT = 5000;
export const DEFAULT_HOSTS = ['emojis.slackmojis.com', 'slackmojis.com'];
const TYPES = { png: 'image/png', gif: 'image/gif', webp: 'image/webp' } as const;
type Ext = keyof typeof TYPES;
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
export type Resolver = (host: string) => Promise<string[]>;
type User = { id: string; username: string };
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const coded = (status: number, error: string) => Object.assign(new Error(error), { status });

/** Identifies an image by its bytes; animated is a best-effort hint for reduced-motion rendering. */
export function sniff(bytes: Uint8Array): { ext: Ext; animated: boolean } | null {
    const ascii = (start: number, end: number) => String.fromCharCode(...bytes.subarray(start, end));
    const has = (marker: string) => Buffer.from(bytes).includes(marker);
    if (bytes.length >= 8 && bytes[0] === 0x89 && ascii(1, 8) === 'PNG\r\n\x1a\n') return { ext: 'png', animated: has('acTL') };
    if (bytes.length >= 6 && (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a')) {
        let frames = 0;
        for (let index = 0; index + 1 < bytes.length && frames < 2; index++) if (bytes[index] === 0x21 && bytes[index + 1] === 0xf9) frames++;
        return { ext: 'gif', animated: frames > 1 || has('NETSCAPE2.0') };
    }
    if (bytes.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 12) === 'WEBP') return { ext: 'webp', animated: has('ANIM') };
    return null;
}

/** Private, loopback, link-local, CGNAT, multicast, unspecified and documentation ranges, v4 and v6. */
export function isPrivateAddress(address: string): boolean {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) return isPrivateAddress(mapped[1]!);
    if (isIP(address) === 4) {
        const [a, b] = address.split('.').map(Number) as [number, number];
        return a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 ||
            a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 192 && b === 0 || a === 198 && (b === 18 || b === 19) || a === 198 && b === 51 || a === 203 && b === 0;
    }
    if (isIP(address) === 6) {
        const value = address.toLowerCase();
        return value === '::' || value === '::1' || /^f[cd]/.test(value) || /^fe[89ab]/.test(value) || /^ff/.test(value) || value.startsWith('2001:db8') || value.startsWith('64:ff9b');
    }
    return true; // Anything that is not an IP literal is not something we connect to.
}

export function createEmoji(options: { db: Database; dataDir: string; origin: string; now: () => number; adminToken?: string; fetcher?: Fetcher; resolver?: Resolver; importHosts?: string[] }) {
    const { db, now } = options;
    const directory = join(options.dataDir, 'emoji');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    db.run(`CREATE TABLE IF NOT EXISTS custom_emoji (name TEXT PRIMARY KEY, sha TEXT NOT NULL, ext TEXT NOT NULL, animated INTEGER NOT NULL,
        created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL)`);
    const hosts = new Set([...DEFAULT_HOSTS, ...(options.importHosts ?? [])].map(host => host.trim().toLowerCase()).filter(Boolean));
    const fetcher: Fetcher = options.fetcher ?? ((url, init) => fetch(url, init));
    const resolver: Resolver = options.resolver ?? (async host => (await lookup(host, { all: true, verbatim: true })).map(entry => entry.address));
    const allowWrite = requestLimiter({ perSource: 1, global: 20 });
    const fileFor = (sha: string, ext: string) => join(directory, `${sha}.${ext}`);

    function save(user: User, name: unknown, bytes: Uint8Array) {
        if (typeof name !== 'string' || !NAME.test(name)) throw coded(400, 'Names are 2–32 characters: a–z, 0–9, _, + or -.');
        if (!bytes.length || bytes.length > MAX_BYTES) throw coded(400, 'Images must be at most 512 KB.');
        const kind = sniff(bytes);
        if (!kind) throw coded(400, 'Only PNG, GIF or WebP images are accepted.');
        const count = db.query<{ total: number; mine: number }, [string]>('SELECT COUNT(*) AS total, SUM(created_by = ?) AS mine FROM custom_emoji').get(user.id)!;
        if (count.total >= MAX_EMOJI) throw coded(409, `The workspace already has ${MAX_EMOJI} custom emoji.`);
        if ((count.mine ?? 0) >= MAX_PER_USER) throw coded(409, `You have added ${MAX_PER_USER} custom emoji. Delete some first.`);
        if (db.query('SELECT 1 FROM custom_emoji WHERE name = ?').get(name)) throw coded(409, `:${name}: already exists.`);
        const sha = createHash('sha256').update(bytes).digest('hex');
        writeFileSync(fileFor(sha, kind.ext), bytes, { mode: 0o600 });
        db.query('INSERT INTO custom_emoji (name, sha, ext, animated, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(name, sha, kind.ext, kind.animated ? 1 : 0, user.id, now());
        return { name, url: `/emoji/${sha}.${kind.ext}`, animated: kind.animated };
    }
    /**
     * Server-side fetch of an emoji image from an allowlisted host. SSRF-safe: https only, allowlisted host,
     * every resolved address must be public, no redirects, 5-second timeout, 512 KB cap while streaming,
     * and the bytes must be a real PNG/GIF/WebP.
     */
    async function download(raw: unknown) {
        let url: URL;
        try { url = new URL(String(raw)); } catch { throw coded(400, 'Paste the image address (https://…).'); }
        if (url.protocol !== 'https:' || url.username || url.password || url.port && url.port !== '443') throw coded(400, 'Only plain https image addresses can be imported.');
        const host = url.hostname.toLowerCase();
        if (!hosts.has(host)) throw coded(400, `Imports are allowed only from ${[...hosts].join(', ')}.`);
        let addresses: string[];
        try { addresses = await resolver(host); } catch { throw coded(400, 'That host could not be resolved.'); }
        if (!addresses.length || addresses.some(isPrivateAddress)) throw coded(400, 'That host resolves to a private address and cannot be used.');
        let response: Response;
        try { response = await fetcher(url.href, { redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT), headers: { Accept: 'image/png,image/gif,image/webp' } }); }
        catch { throw coded(502, 'The image could not be downloaded in time.'); }
        if (response.status >= 300 && response.status < 400) throw coded(400, 'Redirects are not followed. Paste the final image address.');
        if (!response.ok || !response.body) throw coded(502, `The image host answered HTTP ${response.status}.`);
        const declared = Number(response.headers.get('content-length') || 0);
        if (declared > MAX_BYTES) throw coded(400, 'Images must be at most 512 KB.');
        const chunks: Uint8Array[] = []; let size = 0;
        const reader = response.body.getReader();
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                size += value.byteLength;
                if (size > MAX_BYTES) throw coded(400, 'Images must be at most 512 KB.');
                chunks.push(value);
            }
        } finally { reader.cancel().catch(() => {}); }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        return bytes;
    }

    async function handle(request: Request, url: URL, user: User | null, source: string): Promise<Response> {
        const admin = Boolean(options.adminToken) && request.headers.get('authorization') === `Bearer ${options.adminToken}`;
        if (!user && !admin) return json({ error: 'Unauthorized' }, 401);
        if (request.method !== 'GET' && !admin && request.headers.get('origin') !== options.origin) return json({ error: 'Origin required' }, 403);
        try {
            if (url.pathname === '/api/emoji' && request.method === 'GET') {
                const rows = db.query<{ name: string; sha: string; ext: string; animated: number; created_by: string }, []>('SELECT name, sha, ext, animated, created_by FROM custom_emoji ORDER BY name').all();
                return json({ emoji: rows.map(row => ({ name: row.name, url: `/emoji/${row.sha}.${row.ext}`, animated: Boolean(row.animated), mine: row.created_by === user?.id })) });
            }
            if ((url.pathname === '/api/emoji' || url.pathname === '/api/emoji/import') && request.method === 'POST') {
                // Authenticated and within the rate limit before a single byte of the body is read.
                if (!user) return json({ error: 'Sign in to add emoji.' }, 401);
                if (!allowWrite(user.id)) return json({ error: 'Slow down: one emoji a second.' }, 429);
                const raw = await request.text().catch(() => '');
                if (raw.length > (url.pathname === '/api/emoji' ? 786432 : 4096)) return json({ error: 'Request too large' }, 413);
                let body: Record<string, unknown> | null = null;
                try { body = JSON.parse(raw); } catch {}
                if (!body || typeof body !== 'object') return json({ error: 'Invalid request' }, 400);
                if (url.pathname === '/api/emoji/import') return json({ emoji: save(user, body.name, await download(body.url)) }, 201);
                const image = typeof body.image === 'string' ? body.image.replace(/^data:image\/(png|gif|webp);base64,/, '') : '';
                if (!image || image.length > Math.ceil(MAX_BYTES / 3) * 4 + 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(image)) return json({ error: 'Send the image as base64 PNG, GIF or WebP up to 512 KB.' }, 400);
                return json({ emoji: save(user, body.name, new Uint8Array(Buffer.from(image, 'base64'))) }, 201);
            }
            const match = /^\/api\/emoji\/([a-z0-9_+-]{2,32})$/.exec(url.pathname);
            if (match && request.method === 'DELETE') {
                if (!user && !admin) return json({ error: 'Unauthorized' }, 401);
                const row = db.query<{ sha: string; ext: string; created_by: string }, [string]>('SELECT sha, ext, created_by FROM custom_emoji WHERE name = ?').get(match[1]!);
                if (!row) return json({ error: 'No such emoji' }, 404);
                if (row.created_by !== user?.id && !admin) return json({ error: 'Only the person who added it can delete it.' }, 403);
                db.query('DELETE FROM custom_emoji WHERE name = ?').run(match[1]!);
                if (!db.query('SELECT 1 FROM custom_emoji WHERE sha = ? AND ext = ?').get(row.sha, row.ext)) rmSync(fileFor(row.sha, row.ext), { force: true });
                return json({ status: 'deleted' });
            }
            return json({ error: 'Not found' }, 404);
        } catch (error: any) {
            return json({ error: error?.status ? error.message : 'Could not save this emoji.' }, error?.status ?? 500);
        }
    }
    /** Same-origin image response: exact type, no sniffing, sandboxed, immutable (the name is a content hash). */
    function serve(url: URL): Response | undefined {
        const match = /^\/emoji\/([0-9a-f]{64})\.(png|gif|webp)$/.exec(url.pathname);
        if (!match) return undefined;
        const [, sha, ext] = match as unknown as [string, string, Ext];
        if (!db.query('SELECT 1 FROM custom_emoji WHERE sha = ? AND ext = ?').get(sha, ext) || !existsSync(fileFor(sha, ext))) return new Response('Not found', { status: 404 });
        return new Response(Bun.file(fileFor(sha, ext)), { headers: {
            'Content-Type': TYPES[ext], 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox",
            'Cache-Control': 'public, max-age=31536000, immutable', 'Content-Disposition': 'inline', 'Cross-Origin-Resource-Policy': 'same-origin',
        } });
    }
    return { handle, serve };
}
export type Emoji = ReturnType<typeof createEmoji>;
