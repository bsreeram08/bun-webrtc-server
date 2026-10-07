// Builds crates/chatcore-wasm for the browser into packages/signaling/public/core/ (content-hashed files plus
// manifest.json).
//
//   bun run build:wasm            rebuild the committed browser artifacts
//   bun run build:wasm --check    fail unless the committed artifacts were built from exactly this source
//
// The artifacts are committed because the server has no Rust toolchain: deploy.sh only pulls main.
//
// What --check guarantees (CI runs it, then runs the interop matrix against the *committed* bytes):
// - Provenance: the manifest records a hash of every input (both crates' manifests, lockfiles and sources,
//   rustc and wasm-bindgen versions); --check recomputes it, so stale artifacts can't be committed.
// - Bytes: rebuilding on the same kind of host must reproduce the committed files exactly. A build on a
//   different OS/architecture is not byte-identical — Cargo mixes the host triple into the metadata of crates
//   that use proc-macros (serde, wasm-bindgen), which reorders the module — so across hosts --check reports
//   the difference without failing, and the interop matrix proves the committed module's behaviour.
// No wasm-opt: it isn't on every machine, and an optional step would make the output machine-dependent.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, copyFileSync, cpSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { arch, homedir, platform, tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';

const root = resolve(import.meta.dir, '..');
const crates = ['chatcore', 'chatcore-wasm'];
const out = join(root, 'packages/signaling/public/core');
const check = process.argv.includes('--check');

function run(command: string, argv: string[], env: Record<string, string> = {}) {
    const result = spawnSync(command, argv, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env }, encoding: 'utf8' });
    if (result.status !== 0) { console.error(result.stdout, result.stderr); throw new Error(`${command} ${argv.join(' ')} failed`); }
    return result.stdout.trim();
}
const sha = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');

// Pinned toolchain, checked and never installed here: a build must not fetch or upgrade tools by itself.
// The wasm-bindgen CLI must equal the crate's pinned wasm-bindgen exactly (or the glue won't fit the module).
const RUSTC = '1.93.1';
const pinned = /wasm-bindgen = "=([\d.]+)"/.exec(readFileSync(join(root, 'crates/chatcore-wasm/Cargo.toml'), 'utf8'))![1];
const cli = (() => { try { return run('wasm-bindgen', ['--version']).split(' ')[1]; } catch { return null; } })();
const rustc = (() => { try { return run('rustc', ['--version']); } catch { return 'missing'; } })();
if (cli !== pinned || !rustc.startsWith(`rustc ${RUSTC} `)) {
    console.error(`Toolchain mismatch: need rustc ${RUSTC} (have ${rustc}) and wasm-bindgen ${pinned} (have ${cli ?? 'none'}).
Install them explicitly, then re-run:
  rustup toolchain install ${RUSTC} --target wasm32-unknown-unknown
  cargo install wasm-bindgen-cli --version =${pinned} --locked`);
    process.exit(1);
}

/** Hash of every build input: what the committed artifacts must have been built from. */
function sourceHash() {
    const files: string[] = [];
    const walk = (dir: string) => {
        for (const name of readdirSync(dir).sort()) {
            const path = join(dir, name);
            if (name === 'target' || name.startsWith('.')) continue;
            if (statSync(path).isDirectory()) walk(path); else files.push(path);
        }
    };
    for (const name of crates) { for (const file of ['Cargo.toml', 'Cargo.lock']) files.push(join(root, 'crates', name, file)); walk(join(root, 'crates', name, 'src')); }
    const hash = createHash('sha256').update(`${rustc}\nwasm-bindgen ${pinned}\n`);
    for (const file of files) hash.update(`${relative(root, file)}\n`).update(readFileSync(file)).update('\n');
    return hash.digest('hex');
}

// Reproducibility on one kind of host, from any checkout: Cargo hashes the *literal absolute path* of path
// crates into their symbol metadata, so the sources are built from one fixed path (not resolved through
// symlinks, so /tmp/… is the same string everywhere); path remapping keeps local paths out of the binary.
// A fixed path in /tmp could be pre-created by another local user to inject a build, so it is only used if
// it is a real directory (not a symlink), owned by this user and private (0700); otherwise the build stops.
const BUILD = '/tmp/webrtc-bun-chatcore-build';
function privateDirectory(path: string) {
    try { mkdirSync(path, { mode: 0o700 }); } catch (error: any) { if (error.code !== 'EEXIST') throw error; }
    const info = lstatSync(path);
    if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid!() || (info.mode & 0o077) !== 0) {
        throw new Error(`${path} is not a private directory owned by you (it may have been planted). Remove it and re-run.`);
    }
}
/** Copies one regular file, refusing symlinks or anything else at the source. */
function copyRegular(from: string, to: string) {
    const info = lstatSync(from);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`refusing to copy ${from}: not a regular file`);
    rmSync(to, { force: true });
    copyFileSync(from, to, constants.COPYFILE_EXCL);
}

function main() {
    privateDirectory(BUILD);
    rmSync(join(BUILD, 'crates'), { recursive: true, force: true });
    for (const name of crates) cpSync(join(root, 'crates', name), join(BUILD, 'crates', name), { recursive: true, verbatimSymlinks: true, filter: source => !source.split('/').includes('target') && !lstatSync(source).isSymbolicLink() });
    const remap = `--remap-path-prefix=${BUILD}=/src --remap-path-prefix=${join(homedir(), '.cargo')}=/cargo --remap-path-prefix=${join(homedir(), '.rustup')}=/rustup`;
    run('cargo', ['build', '--release', '--locked', '--quiet', '--target', 'wasm32-unknown-unknown', '--manifest-path', join(BUILD, 'crates/chatcore-wasm/Cargo.toml')],
        { RUSTFLAGS: remap, CARGO_INCREMENTAL: '0', CARGO_TARGET_DIR: join(BUILD, 'target') });
    const built = join(BUILD, 'target/wasm32-unknown-unknown/release/chatcore_wasm.wasm');

    // wasm-bindgen writes into a fresh private (0700) directory, removed afterwards.
    const staging = mkdtempSync(join(tmpdir(), 'chatcore-wasm-'));
    try {
        run('wasm-bindgen', ['--target', 'web', '--no-typescript', '--out-name', 'chatcore', '--out-dir', staging, built]);
        const stagedWasm = join(staging, 'chatcore_bg.wasm'), stagedJs = join(staging, 'chatcore.js');
        for (const file of [stagedWasm, stagedJs]) { const info = lstatSync(file); if (!info.isFile() || info.isSymbolicLink()) throw new Error(`unexpected ${file}`); }
        const wasm = readFileSync(stagedWasm), glue = readFileSync(stagedJs);
        const wasmName = `chatcore_bg.${sha(wasm).slice(0, 16)}.wasm`, jsName = `chatcore.${sha(glue).slice(0, 16)}.js`;
        const source = sourceHash(), host = `${platform()}-${arch()}`;

        if (check) {
            const committed = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
            if (committed.source !== source) {
                console.error('The committed WebAssembly core was not built from this source (its input hash differs).\nRun bun run build:wasm and commit packages/signaling/public/core/.');
                return 1;
            }
            const same = committed.js === jsName && committed.wasm === wasmName && readFileSync(join(out, jsName)).equals(glue) && readFileSync(join(out, wasmName)).equals(wasm);
            if (same) { console.log(`Committed core matches the source byte for byte: ${jsName}, ${wasmName}`); return 0; }
            if (committed.host !== host) {
                console.log(`Committed core was built from this source (input hash matches) on ${committed.host}; a ${host} rebuild differs in layout only, as expected across hosts.`);
                return 0;
            }
            console.error(`Same host (${host}) but different bytes: the build is not reproducible.\n  committed: ${committed.js} ${committed.wasm}\n  rebuilt:   ${jsName} ${wasmName}`);
            const keep = join(root, 'wasm-rebuilt'); // CI uploads this so a mismatch can be inspected.
            mkdirSync(keep, { recursive: true });
            copyRegular(stagedWasm, join(keep, wasmName));
            copyRegular(stagedJs, join(keep, jsName));
            return 1;
        }

        mkdirSync(out, { recursive: true });
        for (const name of readdirSync(out)) if (/^chatcore(_bg)?\.[0-9a-f]{16}\.(js|wasm)$/.test(name)) rmSync(join(out, name));
        copyRegular(stagedWasm, join(out, wasmName));
        copyRegular(stagedJs, join(out, jsName));
        // The manifest describes the files as written into the repository, re-read from there.
        const written = { [jsName]: readFileSync(join(out, jsName)), [wasmName]: readFileSync(join(out, wasmName)) };
        if (sha(written[jsName]!) !== sha(glue) || sha(written[wasmName]!) !== sha(wasm)) throw new Error('written core files differ from the build output');
        const manifest = {
            js: jsName, wasm: wasmName,
            sha256: Object.fromEntries(Object.entries(written).map(([name, bytes]) => [name, sha(bytes)])),
            bytes: Object.fromEntries(Object.entries(written).map(([name, bytes]) => [name, bytes.length])),
            protocol: 'chatcore-commands-1', wasmBindgen: pinned, rustc, source, host,
        };
        writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
        console.log(`Built ${jsName} (${glue.length} B) and ${wasmName} (${wasm.length} B)`);
        return 0;
    } finally {
        rmSync(staging, { recursive: true, force: true });
    }
}
process.exitCode = main();
