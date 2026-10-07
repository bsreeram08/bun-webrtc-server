// Interop matrix: packages/signaling/public/signal.js and verify.js (run in a vm, as the browser
// does) against crates/chatcore, both natively (the interop CLI over real sealed SQLite) and as WebAssembly
// (the committed crates/chatcore-wasm build in this process, persisting only through its journal). Every scenario
// runs in every direction between the three. Usage: node tests/interop/run.mjs   (builds the CLI first)
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runInNewContext } from 'node:vm';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const crate = join(root, 'crates/chatcore');
const build = spawnSync('cargo', ['build', '--quiet', '--bin', 'interop', '--manifest-path', join(crate, 'Cargo.toml')], { stdio: 'inherit' });
if (build.status !== 0) process.exit(build.status ?? 1);
const binary = join(crate, 'target/debug/interop');
// The WebAssembly party loads the *committed* browser build (packages/signaling/public/core), the exact bytes
// the server ships; `bun run build:wasm --check` separately proves they were built from this source.
const coreDir = join(root, 'packages/signaling/public/core');
const coreManifest = JSON.parse(readFileSync(join(coreDir, 'manifest.json'), 'utf8'));
const coreModule = await import(pathToFileURL(join(coreDir, coreManifest.js)).href);
coreModule.initSync({ module: readFileSync(join(coreDir, coreManifest.wasm)) });
const { ChatCore } = coreModule;
// Rust parties use real SQLite stores, one file each.
const dataDir = mkdtempSync(join(tmpdir(), 'chatcore-interop-'));
let databases = 0;
process.on('exit', () => rmSync(dataDir, { recursive: true, force: true }));

const context = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, DataView, atob, btoa };
context.globalThis = context; context.window = context;
runInNewContext(readFileSync(join(root, 'packages/signaling/public/signal.js'), 'utf8'), context);
runInNewContext(readFileSync(join(root, 'packages/signaling/public/verify.js'), 'utf8'), context);
const { Signal, Verify } = context;

const NOW = 1_800_000_000_000;
let failures = 0, checks = 0;
function check(condition, label) {
    checks++;
    if (!condition) { failures++; console.log(`  ✗ ${label}`); }
}
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---------- Parties ----------
function memory() {
    const map = new Map();
    return {
        sids: contact => map.get(`sessions:${contact}`)?.order ?? [],
        get: async key => map.get(key), put: async (key, value) => { map.set(key, value); }, delete: async key => { map.delete(key); },
        deletePrefix: async prefix => { for (const key of [...map.keys()]) if (key.startsWith(prefix)) map.delete(key); },
        batch: async writes => { for (const write of writes) if ('put' in write) map.set(write.put, write.value); else map.delete(write.delete); },
    };
}
function jsParty(name) {
    const store = memory(), box = Signal.box(store);
    return {
        kind: 'js', name,
        async bundle(withOpk = true) {
            const keys = await box.prekeys(NOW);
            const opk = withOpk ? (await box.oneTimePreKeys(1))[0] : null;
            return { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: opk };
        },
        async send(contact, payload, bundleFor) {
            try { return { envelope: await box.encryptTo(contact, payload, async () => bundleFor()) }; }
            catch (error) { return { code: error.code ?? null, error: error.message }; }
        },
        async receive(contact, envelope) {
            let payload = null, info = null;
            // Like account.js: a {type:'rotate'} payload answers { rotate: true } so the box keeps only the new session.
            try { await box.decryptFrom(contact, envelope, async (value, details) => { payload = value; info = details; return value?.type === 'rotate' ? { rotate: true } : undefined; }); return { payload, info }; }
            catch (error) { return { code: error.code ?? null, error: error.message }; }
        },
        rotate: contact => box.rotate(contact),
        sessionInfo: contact => box.sessionInfo(contact),
        sids: async contact => store.sids(contact),
        safety: (me, contact, them) => box.safety(me, contact, them),
        peer: contact => box.peer(contact),
        acceptChange: contact => box.acceptChange(contact),
        setVerified: (contact, value) => box.setVerified(contact, value),
        forget: contact => box.forget(contact),
        close() {},
    };
}
function rustParty(name) {
    const child = spawn(binary, [join(dataDir, `party-${++databases}.sqlite`)], { stdio: ['pipe', 'pipe', 'inherit'] });
    const lines = createInterface({ input: child.stdout });
    const waiting = [];
    lines.on('line', line => waiting.shift()?.(JSON.parse(line)));
    const call = command => new Promise(resolve => { waiting.push(resolve); child.stdin.write(JSON.stringify(command) + '\n'); });
    return commandParty('rust', name, call, () => { child.stdin.end(); child.kill(); });
}
/**
 * The WebAssembly core as the browser worker runs it: its key database exists only as the journaled writes
 * each call returns (here a Map standing in for IndexedDB), and the core is rebuilt from that Map after every
 * call that leaves no decrypt pending — so every row must really have been persisted.
 */
function wasmParty(name) {
    const disk = new Map();
    let existed = false, pending = 0, core = new ChatCore('{}', false);
    const call = async command => {
        const result = JSON.parse(core.call(JSON.stringify(command)));
        for (const write of result.writes) if ('put' in write) disk.set(write.put, write.value); else disk.delete(write.delete);
        delete result.writes;
        existed ||= disk.size > 0;
        if (command.cmd === 'decrypt' && command.commit === false && 'ok' in result) pending++;
        if (command.cmd === 'commit' || command.cmd === 'abort') pending = Math.max(0, pending - 1);
        if (!pending) { core.free(); core = new ChatCore(JSON.stringify(Object.fromEntries(disk)), existed); }
        return result;
    };
    return commandParty('wasm', name, call, () => core.free());
}
/** A party driven through chatcore's JSON command protocol (the native CLI or the WebAssembly build). */
function commandParty(kind, name, call, close) {
    const unwrap = async command => { const result = await call(command); if ('error' in result) throw Object.assign(new Error(result.error), { code: result.code }); return result.ok; };
    return {
        kind, name,
        async bundle(withOpk = true) {
            const keys = await unwrap({ cmd: 'prekeys', now: NOW });
            const opk = withOpk ? (await unwrap({ cmd: 'opks', count: 1 }))[0] : null;
            return { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: opk };
        },
        async send(contact, payload, bundleFor) {
            const plaintext = JSON.stringify(payload);
            let result = await call({ cmd: 'encrypt', contact, plaintext });
            if (result.ok?.needsBundle) result = await call({ cmd: 'encrypt', contact, plaintext, bundle: await bundleFor() });
            return 'error' in result ? { code: result.code, error: result.error } : { envelope: result.ok.envelope };
        },
        async receive(contact, envelope) {
            // Two-phase, as the app does: decrypt, look at the payload, then commit (with rotate for a session reset).
            const result = await call({ cmd: 'decrypt', contact, envelope, commit: false });
            if ('error' in result) return { code: result.code, error: result.error };
            const ok = result.ok, payload = JSON.parse(ok.plaintext);
            const committed = await call({ cmd: 'commit', pendingId: ok.pendingId, rotate: payload?.type === 'rotate' });
            if ('error' in committed) return { code: committed.code, error: committed.error };
            return { payload, info: { identityChanged: ok.identityChanged, firstContact: ok.firstContact, identity: ok.identity } };
        },
        rotate: async contact => unwrap({ cmd: 'rotate', contact }),
        sessionInfo: async contact => unwrap({ cmd: 'sessionInfo', contact }),
        sids: async contact => unwrap({ cmd: 'sids', contact }),
        safety: async (me, contact, them) => unwrap({ cmd: 'safety', me, contact, them }),
        peer: async contact => unwrap({ cmd: 'peer', contact }),
        acceptChange: async contact => unwrap({ cmd: 'acceptChange', contact }),
        setVerified: async (contact, verified) => unwrap({ cmd: 'setVerified', contact, verified }),
        forget: async contact => unwrap({ cmd: 'forget', contact }),
        call: unwrap,
        close,
    };
}

// Envelope surgery for tamper tests.
const decode = envelope => JSON.parse(Buffer.from(envelope, 'base64url').toString('utf8'));
const encode = packet => Buffer.from(JSON.stringify(packet), 'utf8').toString('base64url');
const message = (text, n) => ({ v: 1, type: 'message', id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`, text, createdAt: NOW, expiresAt: null });

/** A fresh pair: `a` initiates to `b`. Contact ids are the peer's name. */
async function setup(makeA, makeB, withOpk) {
    const a = makeA('alice'), b = makeB('bob');
    const bBundle = await b.bundle(withOpk);
    let bundleFetches = 0;
    const toB = (payload) => a.send('bob', payload, async () => { bundleFetches++; return bBundle; });
    const toA = (payload) => b.send('alice', payload, async () => a.bundle(true));
    return { a, b, toB, toA, fetches: () => bundleFetches };
}

// Every ordered pair of signal.js, the native core and the WebAssembly core.
const implementations = [['js', jsParty], ['rust', rustParty], ['wasm', wasmParty]];
const directions = implementations.flatMap(([nameA, makeA]) => implementations.filter(([nameB]) => nameB !== nameA).map(([nameB, makeB]) => [nameA, makeA, nameB, makeB]));

async function scenario(title, body) {
    for (const [nameA, makeA, nameB, makeB] of directions) {
        const label = `${title} [${nameA} → ${nameB}]`;
        const before = failures;
        const parties = [];
        try { await body(label, (...args) => setup(...args).then(value => { parties.push(value.a, value.b); return value; }), makeA, makeB); }
        catch (error) { failures++; console.log(`  ✗ ${label}: threw ${error.stack}`); }
        finally { for (const party of parties) party.close(); }
        console.log(`${failures === before ? '✓' : '✗'} ${label}`);
    }
}

// ---------- Scenarios ----------
for (const withOpk of [true, false]) {
    await scenario(`X3DH ${withOpk ? 'with' : 'without'} a one-time prekey, reply and continued chat`, async (label, open, makeA, makeB) => {
        const { a, b, toB, toA, fetches } = await open(makeA, makeB, withOpk);
        const first = await toB(message('hello bob', 1));
        check(first.envelope, `${label}: encrypt`);
        const got = await b.receive('alice', first.envelope);
        check(got.payload?.text === 'hello bob', `${label}: first message decrypts (${got.error})`);
        check(got.info?.firstContact === true && got.info?.identityChanged === false, `${label}: first contact flagged`);
        const x = decode(first.envelope).x;
        check(withOpk ? Number.isInteger(x.opk) : x.opk === null, `${label}: opk in header`);
        const reply = await toA(message('hi alice', 2));
        const back = await a.receive('bob', reply.envelope);
        check(back.payload?.text === 'hi alice', `${label}: reply decrypts (${back.error})`);
        check(!('x' in decode(reply.envelope)), `${label}: reply carries no handshake`);
        const more = await toB(message('after reply', 3));
        check(!('x' in decode(more.envelope)), `${label}: handshake dropped after reply`);
        check((await b.receive('alice', more.envelope)).payload?.text === 'after reply', `${label}: third message`);
        check(fetches() === 1, `${label}: one bundle fetch`);
    });
}

await scenario('long conversation with alternating ratchet steps and bursts', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    let n = 0;
    for (let round = 0; round < 12; round++) {
        const burst = (round % 3) + 1;
        for (let i = 0; i < burst; i++) {
            const out = await toB(message(`a${round}.${i}`, ++n));
            const got = await b.receive('alice', out.envelope);
            check(got.payload?.text === `a${round}.${i}`, `${label}: a→b ${round}.${i} (${got.error})`);
        }
        for (let i = 0; i < burst; i++) {
            const out = await toA(message(`b${round}.${i}`, ++n));
            const got = await a.receive('bob', out.envelope);
            check(got.payload?.text === `b${round}.${i}`, `${label}: b→a ${round}.${i} (${got.error})`);
        }
    }
});

await scenario('out-of-order delivery and skipped keys across chains', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    const firsts = [];
    for (let i = 0; i < 6; i++) firsts.push((await toB(message(`m${i}`, i))).envelope);
    const order = [2, 0, 5, 1, 4, 3];
    for (const i of order) check((await b.receive('alice', firsts[i])).payload?.text === `m${i}`, `${label}: first chain m${i}`);
    const r = await toA(message('ack', 50));
    check((await a.receive('bob', r.envelope)).payload?.text === 'ack', `${label}: reply`);
    // Second chain: hold some back, deliver later after a third chain started (pn skipping).
    const second = [];
    for (let i = 0; i < 4; i++) second.push((await toB(message(`s${i}`, 100 + i))).envelope);
    check((await b.receive('alice', second[3])).payload?.text === 's3', `${label}: skip ahead in chain`);
    const r2 = await toA(message('ack2', 60));
    check((await a.receive('bob', r2.envelope)).payload?.text === 'ack2', `${label}: second reply`);
    const third = (await toB(message('t0', 200))).envelope;
    check((await b.receive('alice', third)).payload?.text === 't0', `${label}: new chain`);
    for (const i of [1, 0, 2]) check((await b.receive('alice', second[i])).payload?.text === `s${i}`, `${label}: late s${i} from earlier chain`);
});

await scenario('duplicates and replays are rejected with the same codes', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, false);
    const first = (await toB(message('one', 1))).envelope;
    check((await b.receive('alice', first)).payload, `${label}: first`);
    const dup = await b.receive('alice', first);
    check(dup.code === 'replay', `${label}: duplicate initial is replay (got ${dup.code})`);
    const second = (await toB(message('two', 2))).envelope;
    check((await b.receive('alice', second)).payload, `${label}: second`);
    check((await b.receive('alice', second)).code === 'replay', `${label}: duplicate in chain is replay`);
    const reply = (await toA(message('r', 3))).envelope;
    check((await a.receive('bob', reply)).payload, `${label}: reply`);
    const next = (await toB(message('three', 4))).envelope;
    check((await b.receive('alice', next)).payload, `${label}: new chain`);
    check((await b.receive('alice', second)).code === 'replay', `${label}: late duplicate from old chain is replay`);
    await b.forget('alice');
    const again = await b.receive('alice', first);
    check(again.code === 'replay', `${label}: initial replay after forgotten session (got ${again.code})`);
});

await scenario('tampered ciphertext, header and handshake are rejected', async (label, open, makeA, makeB) => {
    const { b, toB } = await open(makeA, makeB, true);
    const first = (await toB(message('genuine', 1))).envelope;
    const packet = decode(first);
    const flip = text => { const bytes = Buffer.from(text, 'base64url'); bytes[bytes.length - 1] ^= 1; return bytes.toString('base64url'); };
    const cases = {
        ciphertext: { ...packet, c: flip(packet.c) },
        counter: { ...packet, h: { ...packet.h, n: packet.h.n + 1 } },
        previous: { ...packet, h: { ...packet.h, pn: 7 } },
        identity: { ...packet, x: { ...packet.x, ik: { ...packet.x.ik, sign: flip(packet.x.ik.sign) } } },
    };
    for (const [name, tampered] of Object.entries(cases)) {
        const result = await b.receive('alice', encode(tampered));
        check(result.code === 'auth', `${label}: tampered ${name} → auth (got ${result.code}: ${result.error})`);
    }
    for (const [name, raw] of Object.entries({ notBase64: '!!!', notJson: Buffer.from('nope').toString('base64url'), badVersion: encode({ ...packet, v: 2 }), ekMismatch: encode({ ...packet, x: { ...packet.x, ek: packet.x.ik.dh } }) })) {
        const result = await b.receive('alice', raw);
        check(result.code === 'malformed', `${label}: ${name} → malformed (got ${result.code})`);
    }
    check((await b.receive('alice', first)).payload?.text === 'genuine', `${label}: genuine still decrypts after rejected forgeries`);
});

await scenario('identity change is flagged, blocks sending, and resumes after acceptance', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    check((await b.receive('alice', (await toB(message('hi', 1))).envelope)).payload, `${label}: first contact`);
    check((await a.receive('bob', (await toA(message('yo', 2))).envelope)).payload, `${label}: reply`);
    // "alice" reinstalls: a new party of the same kind and name, with a new identity.
    const reborn = makeA('alice');
    try {
        const out = await reborn.send('bob', message('new phone', 3), async () => b.bundle(true));
        const got = await b.receive('alice', out.envelope);
        check(got.payload?.text === 'new phone' && got.info?.identityChanged === true, `${label}: changed identity flagged (${got.error})`);
        const peer = await b.peer('alice');
        check(peer?.changed === true && peer?.blocked === true && peer?.verified === false, `${label}: peer record changed+blocked`);
        const blocked = await toA(message('should not send', 4));
        check(blocked.code === 'identity-blocked', `${label}: sending blocked (got ${blocked.code})`);
        await b.acceptChange('alice');
        const resumed = await b.send('alice', message('welcome back', 5), async () => reborn.bundle(true));
        const back = await reborn.receive('bob', resumed.envelope);
        check(back.payload?.text === 'welcome back', `${label}: messaging resumes after accept (${back.error})`);
    } finally { reborn.close(); }
});

await scenario('safety numbers match on both sides', async (label, open, makeA, makeB) => {
    const { a, b, toB } = await open(makeA, makeB, true);
    const first = (await toB(message('hi', 1))).envelope;
    await b.receive('alice', first);
    const fromA = await a.safety('alice', 'bob', 'bob');
    const fromB = await b.safety('bob', 'alice', 'alice');
    check(fromA?.number && fromA.number === fromB?.number, `${label}: ${fromA?.number} vs ${fromB?.number}`);
    check(/^(\d{5} ){11}\d{5}$/.test(fromA?.number || ''), `${label}: 60 digits in groups of five`);
});

// ---------- Chat key rotation ----------
const rotateMessage = n => ({ v: 1, type: 'rotate', id: `00000000-0000-4000-9000-${String(n).padStart(12, '0')}`, reason: 'manual' });

await scenario('rotation: a fresh X3DH session, in-flight messages still decrypt, then both sides drop old chains', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    check((await b.receive('alice', (await toB(message('hi', 1))).envelope)).payload, `${label}: first`);
    check((await a.receive('bob', (await toA(message('yo', 2))).envelope)).payload, `${label}: reply`);
    const old = (await a.sessionInfo('bob'))?.sid;
    const inFlight = (await toA(message('late from bob', 3))).envelope; // Sent on the old session.
    await a.rotate('bob');
    const rotation = (await a.send('bob', rotateMessage(4), async () => b.bundle(true))).envelope;
    check(rotation && 'x' in decode(rotation), `${label}: the rotation opens a new X3DH session`);
    const fresh = (await a.sessionInfo('bob'))?.sid;
    check(fresh && fresh !== old, `${label}: new active session`);
    check((await a.receive('bob', inFlight)).payload?.text === 'late from bob', `${label}: in-flight message on the old session decrypts`);
    check((await a.sessionInfo('bob'))?.sid === fresh, `${label}: the late message does not undo the rotation`);
    const got = await b.receive('alice', rotation);
    check(got.payload?.type === 'rotate', `${label}: peer receives the reset (${got.error})`);
    check(eq(await b.sids('alice'), [fresh]), `${label}: peer keeps only the new session`);
    const answer = (await toA(message('on the new one', 5))).envelope;
    check(!('x' in decode(answer)), `${label}: the peer answers on the new session`);
    check((await a.receive('bob', answer)).payload?.text === 'on the new one', `${label}: answer decrypts`);
    check(eq(await a.sids('bob'), [fresh]), `${label}: rotator drops its old chains once answered`);
    check((await a.receive('bob', inFlight)).code === 'unknown-session', `${label}: the dropped old session cannot decrypt`);
    check((await a.safety('alice', 'bob', 'bob'))?.number === (await b.safety('bob', 'alice', 'alice'))?.number, `${label}: security code unchanged by rotation`);
});

await scenario('rotation: a pending rotation is not revived by a late message', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    await b.receive('alice', (await toB(message('hi', 1))).envelope);
    await a.receive('bob', (await toA(message('yo', 2))).envelope);
    const old = (await a.sessionInfo('bob'))?.sid;
    const late = (await toA(message('late', 3))).envelope;
    await a.rotate('bob');
    check((await a.receive('bob', late)).payload?.text === 'late', `${label}: late message decrypts`);
    const next = (await a.send('bob', message('next', 4), async () => b.bundle(true))).envelope;
    check(next && 'x' in decode(next), `${label}: the next send still opens a new session`);
    check((await a.sessionInfo('bob'))?.sid !== old, `${label}: old session not reactivated`);
    check((await b.receive('alice', next)).payload?.text === 'next', `${label}: peer decrypts the new session`);
});

await scenario('rotation: a reset arriving on an old session is ignored', async (label, open, makeA, makeB) => {
    const { a, b, toB, toA } = await open(makeA, makeB, true);
    await b.receive('alice', (await toB(message('hi', 1))).envelope);
    await a.receive('bob', (await toA(message('yo', 2))).envelope);
    const stale = (await toB(rotateMessage(3))).envelope; // A reset sent on the old session.
    await a.rotate('bob');
    const opening = (await a.send('bob', message('new', 4), async () => b.bundle(true))).envelope;
    check((await b.receive('alice', opening)).payload?.text === 'new', `${label}: new session opens`);
    const fresh = (await b.sessionInfo('alice'))?.sid;
    check((await b.sids('alice')).length === 2, `${label}: two sessions before the stale reset`);
    check((await b.receive('alice', stale)).payload?.type === 'rotate', `${label}: stale reset decrypts`);
    const after = await b.sids('alice');
    check(after.length === 2 && after.includes(fresh), `${label}: nothing pruned by a reset on an old session (${after.length})`);
});

// ---------- Call verification code ----------
for (const [kind, make] of [['rust', rustParty], ['wasm', wasmParty]]) {
    const rust = make('sas');
    const label = `call verification code (verify.js ↔ chatcore ${kind})`;
    const before = failures;
    try {
        const print = byte => `sha-256 ${Array(32).fill(byte).join(':')}`;
        const sdp = (p, extra = '') => `v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:${p}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:${p}${extra}\r\n`;
        for (let trial = 0; trial < 20; trial++) {
            const hex = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex');
            const nonces = [hex(), hex()], local = print(trial.toString(16).padStart(2, '0').toUpperCase()), remote = print('ab');
            const jsCode = await Verify.sasCode([Verify.fingerprints(sdp(local)), Verify.fingerprints(sdp(remote.toLowerCase()))], nonces);
            const rustCode = await rust.call({ cmd: 'sas', localSdp: sdp(remote.toLowerCase()), remoteSdp: sdp(local), nonces: [nonces[1], nonces[0]] });
            check(jsCode === rustCode, `${label}: trial ${trial} ${jsCode} vs ${rustCode}`);
            const jsCommit = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nonces[0]))).toString('hex');
            check(jsCommit === await rust.call({ cmd: 'sasCommitment', nonce: nonces[0] }), `${label}: commitment ${trial}`);
            check(await rust.call({ cmd: 'sasCheck', commitment: jsCommit, nonce: nonces[0] }) === true, `${label}: reveal check ${trial}`);
        }
        for (const [name, bad] of Object.entries({ decoy: sdp(print('AA'), `\r\na=fingerprint:${print('BB')}`), sha1: 'a=fingerprint:sha-1 AA:BB\r\n', none: 'v=0\r\n', upper: `a=FINGERPRINT:${print('AA')}\r\n` })) {
            let jsThrows = false; try { Verify.fingerprints(bad); } catch { jsThrows = true; }
            let rustThrows = false; try { await rust.call({ cmd: 'sas', localSdp: bad, remoteSdp: sdp(print('AA')), nonces: ['a'.repeat(64), 'b'.repeat(64)] }); } catch { rustThrows = true; }
            check(jsThrows && rustThrows, `${label}: ${name} rejected by both (js ${jsThrows}, rust ${rustThrows})`);
        }
    } catch (error) { failures++; console.log(`  ✗ ${label}: threw ${error.stack}`); }
    finally { rust.close(); }
    console.log(`${failures === before ? '✓' : '✗'} ${label}`);
}

console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
