// Integrity of the committed WebAssembly core (packages/signaling/public/core). Fail-closed: the directory must
// hold exactly manifest.json plus the two files it names, each with the SHA-256 the manifest records.
// The server refuses to start otherwise and serves only these files, from the bytes it verified (no re-read).
// `bun run build:wasm --check` runs the same verification before comparing the files with a rebuild from source.
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export type CoreFile = { name: string; type: string; sha256: string; bytes: Buffer };
const NAME = /^chatcore(?:_bg)?\.[0-9a-f]{16}\.(?:js|wasm)$/;

/** Verifies `dir` and returns the files that may be served (manifest.json included). Throws on any mismatch. */
export function verifyCore(dir: string): Map<string, CoreFile> {
    const fail = (why: string): never => { throw new Error(`WebAssembly core at ${dir} failed verification: ${why}`); };
    let manifest: any, manifestBytes: Buffer = Buffer.alloc(0);
    try { manifestBytes = readFileSync(join(dir, 'manifest.json')); manifest = JSON.parse(manifestBytes.toString('utf8')); } catch { fail('manifest.json is missing or unreadable'); }
    const named = [manifest.js, manifest.wasm];
    if (typeof manifest.js !== 'string' || typeof manifest.wasm !== 'string' || !NAME.test(manifest.js) || !NAME.test(manifest.wasm)
        || !manifest.js.endsWith('.js') || !manifest.wasm.endsWith('.wasm')) fail('manifest names are invalid');
    const recorded = manifest.sha256 && typeof manifest.sha256 === 'object' ? Object.keys(manifest.sha256).sort() : [];
    if (recorded.join() !== [...named].sort().join()) fail('manifest hashes must cover exactly its two files');
    const present = readdirSync(dir).sort();
    const expected = ['manifest.json', ...named].sort();
    if (present.join('\n') !== expected.join('\n')) fail(`directory must contain exactly ${expected.join(', ')} (found ${present.join(', ') || 'nothing'})`);
    const files = new Map<string, CoreFile>();
    for (const name of named) {
        const path = join(dir, name), info = lstatSync(path);
        if (!info.isFile() || info.isSymbolicLink()) fail(`${name} is not a regular file`);
        const bytes = readFileSync(path), digest = createHash('sha256').update(bytes).digest('hex');
        if (digest !== manifest.sha256[name] || !name.includes(digest.slice(0, 16))) fail(`${name} does not match its recorded SHA-256`);
        files.set(name, { name, type: name.endsWith('.wasm') ? 'application/wasm' : 'text/javascript; charset=utf-8', sha256: digest, bytes });
    }
    files.set('manifest.json', { name: 'manifest.json', type: 'application/json', sha256: createHash('sha256').update(manifestBytes).digest('hex'), bytes: manifestBytes });
    return files;
}
