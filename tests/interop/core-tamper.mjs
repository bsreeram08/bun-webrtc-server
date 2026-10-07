// build:wasm --check must fail closed on every kind of tampering with the committed core, including a swapped
// file whose manifest was rewritten to match (only the rebuild comparison can catch that). Runs on the
// canonical build host (CI: macos-14), like --check itself.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const dir = join(root, 'packages/signaling/public/core');
const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const flip = path => { const bytes = readFileSync(path); bytes[bytes.length - 1] ^= 1; return bytes; };

const cases = {
    'extra file': target => writeFileSync(join(target, 'evil.js'), 'alert(1)'),
    'modified file': target => writeFileSync(join(target, manifest.wasm), flip(join(target, manifest.wasm))),
    'missing file': target => rmSync(join(target, manifest.js)),
    'manifest edited to match a modified file': target => {
        const bytes = flip(join(target, manifest.wasm)), name = `chatcore_bg.${sha(bytes).slice(0, 16)}.wasm`;
        rmSync(join(target, manifest.wasm));
        writeFileSync(join(target, name), bytes);
        writeFileSync(join(target, 'manifest.json'), JSON.stringify({ ...manifest, wasm: name,
            sha256: { [manifest.js]: manifest.sha256[manifest.js], [name]: sha(bytes) },
            bytes: { [manifest.js]: manifest.bytes[manifest.js], [name]: bytes.length } }));
    },
};

let failed = 0;
for (const [label, tamper] of Object.entries(cases)) {
    const target = mkdtempSync(join(tmpdir(), 'core-tamper-'));
    try {
        cpSync(dir, target, { recursive: true });
        tamper(target);
        const result = spawnSync('bun', ['scripts/build-wasm.ts', '--check', '--core-dir', target], { cwd: root, encoding: 'utf8' });
        const caught = result.status !== 0;
        if (!caught) failed++;
        console.log(`${caught ? 'ok  ' : 'FAIL'} ${label}: --check exited ${result.status}: ${result.stderr.trim().split('\n')[0] || result.stdout.trim()}`);
    } finally {
        rmSync(target, { recursive: true, force: true });
    }
}
process.exitCode = failed ? 1 : 0;
