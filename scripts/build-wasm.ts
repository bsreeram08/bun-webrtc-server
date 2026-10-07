// Builds crates/chatcore-wasm for the browser into packages/signaling/public/core/ (content-hashed files plus
// manifest.json), and optionally a node build for the interop matrix.
//
//   bun run build:wasm                 rebuild the committed browser artifacts
//   bun run build:wasm --check         rebuild into a temp dir and fail if it differs from the committed files
//   bun run build:wasm --node <dir>    also emit a nodejs-target build (tests/interop uses this)
//   … --node <dir> --node-only         only the nodejs build; the committed browser files are untouched
//
// The artifacts are committed because the server has no Rust toolchain: deploy.sh only pulls main. --check
// (run in CI) proves the committed bytes are what this source produces. No wasm-opt: it isn't on every
// machine, and an optional step would make the output depend on which machine built it.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dir, '..');
const crate = join(root, 'crates/chatcore-wasm');
const out = join(root, 'packages/signaling/public/core');
const args = process.argv.slice(2);
const check = args.includes('--check');
const nodeDir = args.includes('--node') ? resolve(args[args.indexOf('--node') + 1]) : null;
const nodeOnly = args.includes('--node-only');

function run(command: string, argv: string[], env: Record<string, string> = {}) {
    const result = spawnSync(command, argv, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env }, encoding: 'utf8' });
    if (result.status !== 0) { console.error(result.stdout, result.stderr); throw new Error(`${command} ${argv.join(' ')} failed`); }
    return result.stdout.trim();
}

// The CLI must match the crate's pinned wasm-bindgen exactly, or the generated glue won't fit the module.
const pinned = /wasm-bindgen = "=([\d.]+)"/.exec(readFileSync(join(crate, 'Cargo.toml'), 'utf8'))![1];
const cli = (() => { try { return run('wasm-bindgen', ['--version']).split(' ')[1]; } catch { return null; } })();
if (cli !== pinned) {
    console.error(`wasm-bindgen CLI ${cli ?? 'missing'}; installing ${pinned}…`);
    run('cargo', ['install', 'wasm-bindgen-cli', '--version', pinned, '--locked', '--quiet']);
}

// Path remapping keeps local paths out of the binary, so builds on different machines can match byte for byte.
const remap = `--remap-path-prefix=${root}=/src --remap-path-prefix=${join(homedir(), '.cargo')}=/cargo --remap-path-prefix=${join(homedir(), '.rustup')}=/rustup`;
run('cargo', ['build', '--release', '--locked', '--quiet', '--target', 'wasm32-unknown-unknown', '--manifest-path', join(crate, 'Cargo.toml')], { RUSTFLAGS: remap, CARGO_INCREMENTAL: '0' });
const built = join(crate, 'target/wasm32-unknown-unknown/release/chatcore_wasm.wasm');

const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const staging = mkdtempSync(join(tmpdir(), 'chatcore-wasm-'));
try {
    run('wasm-bindgen', ['--target', 'web', '--no-typescript', '--out-name', 'chatcore', '--out-dir', staging, built]);
    const wasm = readFileSync(join(staging, 'chatcore_bg.wasm')), glue = readFileSync(join(staging, 'chatcore.js'));
    const wasmName = `chatcore_bg.${sha(wasm).slice(0, 16)}.wasm`, jsName = `chatcore.${sha(glue).slice(0, 16)}.js`;
    const manifest = {
        js: jsName, wasm: wasmName, sha256: { [jsName]: sha(glue), [wasmName]: sha(wasm) },
        bytes: { [jsName]: glue.length, [wasmName]: wasm.length },
        protocol: 'chatcore-commands-1', wasmBindgen: pinned, rustc: run('rustc', ['--version']),
    };
    const manifestText = JSON.stringify(manifest, null, 2) + '\n';

    if (nodeOnly) {
        // Only the nodejs build was asked for (tests): leave the committed browser files alone.
    } else if (check) {
        const committed = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
        const same = committed.js === jsName && committed.wasm === wasmName && readFileSync(join(out, jsName)).equals(glue) && readFileSync(join(out, wasmName)).equals(wasm);
        if (!same) {
            console.error(`Committed core differs from this source.\n  committed: ${committed.js} ${committed.wasm} (${committed.rustc})\n  rebuilt:   ${jsName} ${wasmName} (${manifest.rustc})\nRun bun run build:wasm and commit the result.`);
            process.exit(1);
        }
        console.log(`Committed core matches the source: ${jsName}, ${wasmName}`);
    } else {
        mkdirSync(out, { recursive: true });
        for (const name of readdirSync(out)) if (/^chatcore(_bg)?\.[0-9a-f]{16}\.(js|wasm)$/.test(name)) rmSync(join(out, name));
        copyFileSync(join(staging, 'chatcore_bg.wasm'), join(out, wasmName));
        copyFileSync(join(staging, 'chatcore.js'), join(out, jsName));
        writeFileSync(join(out, 'manifest.json'), manifestText);
        console.log(`Built ${jsName} (${glue.length} B) and ${wasmName} (${wasm.length} B)`);
    }

    if (nodeDir) {
        mkdirSync(nodeDir, { recursive: true });
        run('wasm-bindgen', ['--target', 'nodejs', '--no-typescript', '--out-name', 'chatcore', '--out-dir', nodeDir, built]);
        console.log(`Node build in ${nodeDir}`);
    }
} finally {
    rmSync(staging, { recursive: true, force: true });
}
