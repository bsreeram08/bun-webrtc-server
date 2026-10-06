import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/signal.js', import.meta.url), 'utf8');
const context: Record<string, any> = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, atob, btoa };
context.globalThis = context;
runInNewContext(source, context);
const Signal = context.Signal;
const text = (value: string) => new TextEncoder().encode(value);
const read = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

/** A Map-backed key/value store standing in for IndexedDB (CryptoKeys stay in memory). */
function memory() {
    const map = new Map<string, any>();
    return {
        map, get: async (key: string) => map.get(key), put: async (key: string, value: any) => { map.set(key, value); }, delete: async (key: string) => { map.delete(key); },
        deletePrefix: async (prefix: string) => { for (const key of [...map.keys()]) if (key.startsWith(prefix)) map.delete(key); },
        batch: async (writes: any[]) => { for (const write of writes) if ('put' in write) map.set(write.put, write.value); else map.delete(write.delete); },
    };
}
async function party(withOneTime = true) {
    const identity = await Signal.generateIdentity();
    const spk = await Signal.generateSignedPreKey(identity, 1);
    const opk = withOneTime ? { id: 7, pair: await (async () => { const kp = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as unknown as CryptoKeyPair; return { keyPair: kp, pub: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) }; })() } : null;
    const bundle = { identity: identity.pub, signedPreKey: { id: spk.id, key: spk.pub, signature: spk.signature }, oneTimePreKey: opk ? { id: opk.id, key: Signal.b64(opk.pair.pub) } : null };
    return { identity, spk, opk, bundle };
}
async function pair(withOneTime = true) {
    const alice = await Signal.generateIdentity(), bob = await party(withOneTime);
    const aliceState = await Signal.initiate(alice, bob.bundle);
    return { alice, bob, aliceState };
}
async function open(bob: Awaited<ReturnType<typeof party>>, envelope: string) {
    const parsed = Signal.parseEnvelope(envelope);
    const state = await Signal.respond(bob.identity, bob.spk, bob.opk, parsed.header);
    return Signal.decrypt(state, parsed);
}

describe('X3DH and the Double Ratchet', () => {
    for (const withOneTime of [true, false]) test(`both sides derive the same secret ${withOneTime ? 'with' : 'without'} a one-time prekey`, async () => {
        const { bob, aliceState } = await pair(withOneTime);
        const sent = await Signal.encrypt(aliceState, text('hello bob'));
        const received = await open(bob, sent.envelope);
        expect(read(received.plaintext)).toBe('hello bob');
        const reply = await Signal.encrypt(received.session, text('hi alice'));
        expect(read((await Signal.decrypt(sent.session, Signal.parseEnvelope(reply.envelope))).plaintext)).toBe('hi alice');
    });
    test('a wrong one-time prekey or identity produces no shared secret', async () => {
        const { aliceState } = await pair(true), other = await party(true);
        const sent = await Signal.encrypt(aliceState, text('secret'));
        await expect(open(other, sent.envelope)).rejects.toThrow('Message authentication failed');
    });
    test('in-order, out-of-order and multi-ratchet delivery', async () => {
        const { bob, aliceState } = await pair();
        let a = aliceState; const envelopes: string[] = [];
        for (let index = 0; index < 5; index++) { const out = await Signal.encrypt(a, text(`a${index}`)); a = out.session; envelopes.push(out.envelope); }
        let first = await open(bob, envelopes[0]!), b = first.session;
        const seen = [read(first.plaintext)];
        for (const index of [3, 1, 2, 4]) { const out = await Signal.decrypt(b, Signal.parseEnvelope(envelopes[index]!)); b = out.session; seen.push(read(out.plaintext)); }
        expect(seen).toEqual(['a0', 'a3', 'a1', 'a2', 'a4']);
        // Several DH ratchet turns, with a delayed message from an earlier chain.
        const late = await Signal.encrypt(b, text('b-late')); b = late.session;
        const now = await Signal.encrypt(b, text('b-now')); b = now.session;
        let out = await Signal.decrypt(a, Signal.parseEnvelope(now.envelope)); a = out.session; expect(read(out.plaintext)).toBe('b-now');
        const next = await Signal.encrypt(a, text('a-next')); a = next.session;
        out = await Signal.decrypt(b, Signal.parseEnvelope(next.envelope)); b = out.session; expect(read(out.plaintext)).toBe('a-next');
        out = await Signal.decrypt(a, Signal.parseEnvelope(late.envelope)); a = out.session; expect(read(out.plaintext)).toBe('b-late');
    });
    test('the skipped-message bound is enforced', async () => {
        const { bob, aliceState } = await pair();
        let a = aliceState, last = '';
        for (let index = 0; index <= Signal.MAX_SKIP + 1; index++) { const out = await Signal.encrypt(a, text('x')); a = out.session; last = out.envelope; }
        await expect(open(bob, last)).rejects.toThrow('Too many skipped messages');
    });
    test('tampered ciphertext, header or handshake fields are rejected', async () => {
        const { bob, aliceState } = await pair();
        const { envelope } = await Signal.encrypt(aliceState, text('integrity'));
        const packet = JSON.parse(read(Signal.unb64(envelope)));
        const variants = [
            { ...packet, c: packet.c.slice(0, -2) + (packet.c.endsWith('AA') ? 'BA' : 'AA') },
            { ...packet, h: { ...packet.h, pn: packet.h.pn + 1 } },
            { ...packet, x: { ...packet.x, opk: null } },
        ];
        for (const variant of variants) await expect(open(bob, Signal.b64(text(JSON.stringify(variant))))).rejects.toThrow();
        expect(read((await open(bob, envelope)).plaintext)).toBe('integrity');
    });
    test('replays are rejected and used message keys are deleted', async () => {
        const { bob, aliceState } = await pair();
        const m0 = await Signal.encrypt(aliceState, text('m0')), m1 = await Signal.encrypt(m0.session, text('m1')), m2 = await Signal.encrypt(m1.session, text('m2'));
        let b = (await open(bob, m0.envelope)).session;
        b = (await Signal.decrypt(b, Signal.parseEnvelope(m2.envelope))).session;
        expect(Object.keys(b.skipped)).toHaveLength(1); // m1's key waits for m1.
        b = (await Signal.decrypt(b, Signal.parseEnvelope(m1.envelope))).session;
        expect(Object.keys(b.skipped)).toHaveLength(0); // ...and is gone once used.
        for (const old of [m0, m1, m2]) await expect(Signal.decrypt(b, Signal.parseEnvelope(old.envelope))).rejects.toThrow();
    });
    test('a late duplicate from an earlier chain is recognised as a replay, not a decryption failure', async () => {
        const { bob, aliceState } = await pair();
        const a0 = await Signal.encrypt(aliceState, text('a0'));
        let b = (await open(bob, a0.envelope)).session;
        const b0 = await Signal.encrypt(b, text('b0')); b = b0.session;
        let a = (await Signal.decrypt(a0.session, Signal.parseEnvelope(b0.envelope))).session;
        const a1 = await Signal.encrypt(a, text('a1')); a = a1.session;
        b = (await Signal.decrypt(b, Signal.parseEnvelope(a1.envelope))).session; // Bob's receiving chain moved on.
        for (const old of [a0, a1]) await expect(Signal.decrypt(b, Signal.parseEnvelope(old.envelope))).rejects.toMatchObject({ code: 'replay' });
    });
    test('a bad signed prekey signature is rejected', async () => {
        const alice = await Signal.generateIdentity(), bob = await party(), mallory = await Signal.generateIdentity();
        const forged = await Signal.generateSignedPreKey(mallory, 1);
        await expect(Signal.initiate(alice, { ...bob.bundle, signedPreKey: { ...bob.bundle.signedPreKey, signature: forged.signature } })).rejects.toThrow('signature');
        await expect(Signal.initiate(alice, { ...bob.bundle, signedPreKey: { id: 1, key: forged.pub, signature: bob.bundle.signedPreKey.signature } })).rejects.toThrow('signature');
    });
    test('safety numbers match on both sides and change with an identity', async () => {
        const a = await Signal.generateIdentity(), b = await Signal.generateIdentity(), c = await Signal.generateIdentity();
        const mine = await Signal.safetyNumber({ username: 'alice', identity: a.pub }, { username: 'bob', identity: b.pub });
        expect(mine).toMatch(/^(\d{5} ){11}\d{5}$/);
        expect(await Signal.safetyNumber({ username: 'bob', identity: b.pub }, { username: 'alice', identity: a.pub })).toBe(mine);
        expect(await Signal.safetyNumber({ username: 'alice', identity: a.pub }, { username: 'bob', identity: c.pub })).not.toBe(mine);
    });
});

describe('persistent box', () => {
    async function people() {
        const alice = memory(), bob = memory(), changes: string[] = [];
        const A = Signal.box(alice, { identityChanged: (id: string) => changes.push(`alice:${id}`) }), B = Signal.box(bob, { identityChanged: (id: string) => changes.push(`bob:${id}`) });
        // The server hands out one one-time prekey per fetch and deletes it.
        let pool = await B.oneTimePreKeys(3);
        const bundleOf = async (box: any) => { const keys = await box.prekeys(); const oneTimePreKey = box === B ? pool.shift() ?? null : null; return { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey }; };
        return { alice, bob, A, B, changes, bundleOf, refill: async () => { pool = await B.oneTimePreKeys(3); } };
    }
    test('first contact, replies and one-time prekey consumption', async () => {
        const { bob, A, B, bundleOf } = await people();
        const first = await A.encryptTo('bob', { text: 'hi' }, () => bundleOf(B));
        const inbox: any[] = [];
        await B.decryptFrom('alice', first, async (message: any) => { inbox.push(message); });
        expect(inbox).toEqual([{ text: 'hi' }]);
        expect([...bob.map.keys()].filter(key => key.startsWith('opk:'))).toHaveLength(2);
        // The same initial message cannot be replayed into a fresh session: its one-time prekey is gone.
        await bob.delete('sessions:alice');
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toThrow('One-time prekey already used');
        await bob.deletePrefix('claim:'); // Even without the replay record, the consumed one-time prekey refuses it.
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toThrow('One-time prekey already used');
    });
    test('a failing store leaves the ratchet unchanged so the message can be processed again', async () => {
        const { A, B, bundleOf } = await people();
        const first = await A.encryptTo('bob', { text: 'one' }, () => bundleOf(B));
        await expect(B.decryptFrom('alice', first, async () => { throw new Error('disk full'); })).rejects.toThrow('disk full');
        const got: any[] = [];
        await B.decryptFrom('alice', first, async (message: any) => { got.push(message); });
        expect(got).toEqual([{ text: 'one' }]);
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toThrow('Replayed');
    });
    test('concurrent sends and receives are serialized per contact', async () => {
        const { A, B, bundleOf } = await people();
        const envelopes = await Promise.all(Array.from({ length: 6 }, (_, index) => A.encryptTo('bob', { n: index }, () => bundleOf(B))));
        const got: number[] = [];
        await Promise.all(envelopes.map(envelope => B.decryptFrom('alice', envelope, async (message: any) => { got.push(message.n); })));
        expect(got.sort()).toEqual([0, 1, 2, 3, 4, 5]);
        const reply = await B.encryptTo('alice', { n: 'reply' }, () => bundleOf(A));
        await A.decryptFrom('bob', reply, async (message: any) => { expect(message.n).toBe('reply'); });
    });
    test('simultaneous first messages from both sides still decrypt', async () => {
        const { A, B, bundleOf } = await people();
        const fromA = await A.encryptTo('bob', { t: 'a' }, () => bundleOf(B)), fromB = await B.encryptTo('alice', { t: 'b' }, () => bundleOf(A));
        const got: string[] = [];
        await B.decryptFrom('alice', fromA, async (m: any) => { got.push(m.t); });
        await A.decryptFrom('bob', fromB, async (m: any) => { got.push(m.t); });
        for (let round = 0; round < 3; round++) {
            await B.decryptFrom('alice', await A.encryptTo('bob', { t: `a${round}` }, () => bundleOf(B)), async (m: any) => { got.push(m.t); });
            await A.decryptFrom('bob', await B.encryptTo('alice', { t: `b${round}` }, () => bundleOf(A)), async (m: any) => { got.push(m.t); });
        }
        expect(got).toEqual(['a', 'b', 'a0', 'b0', 'a1', 'b1', 'a2', 'b2']);
    });
    test('an identity change is reported, clears verification and drops old sessions', async () => {
        const { alice, A, B, changes, bundleOf } = await people();
        await B.decryptFrom('alice', await A.encryptTo('bob', { t: 1 }, () => bundleOf(B)), async () => {});
        await A.setVerified('bob', true);
        expect((await A.safety('alice', 'bob', 'bob')).verified).toBe(true);
        // Bob reinstalls: a new identity on a new device.
        const B2 = Signal.box(memory()); const fresh = await B2.oneTimePreKeys(1); const keys = await B2.prekeys();
        await A.encryptTo('bob', { t: 2 }, async () => ({ identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: fresh[0] })).catch(() => {});
        expect((await A.notePeer('bob', keys.identity)).changed).toBe(true);
        expect(changes).toContain('alice:bob');
        const safety = await A.safety('alice', 'bob', 'bob');
        expect(safety.verified).toBe(false); expect(safety.changed).toBe(true);
        expect(alice.map.get('sessions:bob')).toBeUndefined();
    });
    test('an initial message without a one-time prekey cannot be replayed after its session is gone', async () => {
        const { bob, A, B, bundleOf } = await people();
        // The server ran out of one-time prekeys.
        const first = await A.encryptTo('bob', { t: 'once' }, async () => ({ ...await bundleOf(B), oneTimePreKey: null }));
        expect(JSON.parse(read(Signal.unb64(first))).x.opk).toBeNull();
        const got: string[] = [];
        await B.decryptFrom('alice', first, async (m: any) => { got.push(m.t); });
        await bob.delete('sessions:alice'); // Evicted, or dropped by an identity change.
        await expect(B.decryptFrom('alice', first, async (m: any) => { got.push(m.t); })).rejects.toThrow('Replayed');
        expect(got).toEqual(['once']);
    });
    test('a transient storage failure during decryption is coded for retry, and the retry succeeds in step', async () => {
        const { bob, A, B, bundleOf } = await people();
        const m1 = await A.encryptTo('bob', { t: 1 }, () => bundleOf(B)), m2 = await A.encryptTo('bob', { t: 2 }, () => bundleOf(B));
        const original = bob.batch; let failures = 1;
        bob.batch = async (writes: any[]) => { if (failures-- > 0) throw new Error('QuotaExceededError'); return original(writes); };
        const got: number[] = [];
        await expect(B.decryptFrom('alice', m1, async (m: any) => { got.push(m.t); })).rejects.toMatchObject({ code: 'storage' });
        await B.decryptFrom('alice', m1, async (m: any) => { if (!got.includes(m.t)) got.push(m.t); }); // redelivered: idempotent caller
        await B.decryptFrom('alice', m2, async (m: any) => { got.push(m.t); });
        expect(got).toEqual([1, 2]);
        await A.decryptFrom('bob', await B.encryptTo('alice', { t: 'reply' }, () => bundleOf(A)), async (m: any) => { expect(m.t).toBe('reply'); });
    });
    test('authentication failures, malformed envelopes and replays carry permanent codes', async () => {
        const { A, B, bundleOf } = await people();
        const first = await A.encryptTo('bob', { t: 1 }, () => bundleOf(B));
        const packet = JSON.parse(read(Signal.unb64(first)));
        const tampered = Signal.b64(text(JSON.stringify({ ...packet, c: packet.c.slice(0, -2) + (packet.c.endsWith('AA') ? 'BA' : 'AA') })));
        await expect(B.decryptFrom('alice', tampered, async () => {})).rejects.toMatchObject({ code: 'auth' });
        for (const junk of ['', 'not base64!', Signal.b64(text('{"v":2}')), Signal.b64(text('[not json'))]) await expect(B.decryptFrom('alice', junk, async () => {})).rejects.toMatchObject({ code: 'malformed' });
        await B.decryptFrom('alice', first, async () => {});
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toMatchObject({ code: 'replay' });
        const stranger = Signal.b64(text(JSON.stringify({ ...packet, sid: packet.h.dh, x: undefined })));
        await expect(B.decryptFrom('carol', stranger, async () => {})).rejects.toMatchObject({ code: 'unknown-session' });
    });
    test('one initial envelope delivered concurrently as if from two contacts opens at most one session', async () => {
        for (const withOneTime of [true, false]) {
            const { bob, A, B, bundleOf } = await people();
            const first = await A.encryptTo('bob', { t: 'once' }, async () => withOneTime ? bundleOf(B) : { ...await bundleOf(B), oneTimePreKey: null });
            const opksBefore = [...bob.map.keys()].filter(key => key.startsWith('opk:')).length;
            const delivered: string[] = [];
            const results = await Promise.allSettled(['alice', 'mallory', 'alice-again'].map(contact => B.decryptFrom(contact, first, async () => { delivered.push(contact); })));
            expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
            expect(delivered).toHaveLength(1);
            expect([...bob.map.keys()].filter(key => key.startsWith('sessions:'))).toHaveLength(1);
            expect([...bob.map.keys()].filter(key => key.startsWith('opk:')).length).toBe(opksBefore - (withOneTime ? 1 : 0));
        }
    });
    test('a message whose storage failed after its claim is processed once on redelivery', async () => {
        const { A, B, bundleOf } = await people();
        const first = await A.encryptTo('bob', { t: 'retry' }, () => bundleOf(B));
        await expect(B.decryptFrom('alice', first, async () => { throw new Error('crash'); })).rejects.toThrow('crash');
        await expect(B.decryptFrom('mallory', first, async () => {})).rejects.toThrow('Replayed'); // still claimed for alice
        const got: string[] = [];
        await B.decryptFrom('alice', first, async (m: any) => { got.push(m.t); });
        await expect(B.decryptFrom('alice', first, async (m: any) => { got.push(m.t); })).rejects.toThrow('Replayed');
        expect(got).toEqual(['retry']);
    });
    test('replays stay rejected after the session is forgotten, and after the signed prekey retires', async () => {
        const { bob, A, B, bundleOf } = await people();
        const first = await A.encryptTo('bob', { t: 'x' }, async () => ({ ...await bundleOf(B), oneTimePreKey: null }));
        await B.decryptFrom('alice', first, async () => {});
        await B.forget('alice');
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toThrow('Replayed');
        await B.prekeys(Date.now() + 8 * 86400000); await B.prekeys(Date.now() + 16 * 86400000);
        expect([...bob.map.keys()].filter(key => key.startsWith('claim:1:'))).toHaveLength(0); // pruned with its prekey
        await expect(B.decryptFrom('alice', first, async () => {})).rejects.toThrow('Unknown signed prekey');
    });
    test('one contact flooding new sessions hits its own cap; others still get through and nothing rotates', async () => {
        const bob = memory(), B = Signal.box(bob);
        const keys = await B.prekeys();
        const bundle = { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: null };
        // Throwaway sessions all attributed to one contact (for example a hostile contact re-initiating).
        const outcomes: string[] = [];
        for (let index = 0; index < Signal.MAX_CLAIMS_PER_CONTACT + 3; index++) {
            const sender = Signal.box(memory());
            await B.decryptFrom('mallory', await sender.encryptTo('bob', { n: index }, async () => bundle), async () => {}).then(() => outcomes.push('ok'), (error: any) => outcomes.push(error.message));
        }
        expect(outcomes.filter(value => value === 'ok')).toHaveLength(Signal.MAX_CLAIMS_PER_CONTACT);
        expect(outcomes.slice(-3)).toEqual(Array(3).fill('Too many new sessions from this contact'));
        expect([...bob.map.keys()].filter(key => key.startsWith('claim:'))).toHaveLength(Signal.MAX_CLAIMS_PER_CONTACT); // bounded
        const got: string[] = [];
        const alice = Signal.box(memory());
        await B.decryptFrom('alice', await alice.encryptTo('bob', { t: 'real contact' }, async () => bundle), async (m: any) => { got.push(m.t); });
        expect(got).toEqual(['real contact']);
        const again = await B.prekeys();
        expect(again.rotated).toBe(false); // volume never forces a rotation
        expect(again.signedPreKey.id).toBe(keys.signedPreKey.id);
    });
    test('claims and per-contact counters are pruned on normal weekly rotation', async () => {
        const bob = memory(), B = Signal.box(bob), keys = await B.prekeys();
        const bundle = { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: null };
        await B.decryptFrom('alice', await Signal.box(memory()).encryptTo('bob', { t: 1 }, async () => bundle), async () => {});
        expect([...bob.map.keys()].filter(key => key.startsWith('claim'))).toHaveLength(2);
        await B.prekeys(Date.now() + 8 * 86400000);
        expect([...bob.map.keys()].filter(key => key.startsWith('claim'))).toHaveLength(2); // still accepted as previous
        await B.prekeys(Date.now() + 16 * 86400000);
        expect([...bob.map.keys()].filter(key => key.startsWith('claim'))).toHaveLength(0);
    });
    test('a duplicate envelope (lost acknowledgement) is rejected without delivering twice or breaking the ratchet', async () => {
        const { A, B, bundleOf } = await people();
        const m1 = await A.encryptTo('bob', { t: 1 }, () => bundleOf(B)), m2 = await A.encryptTo('bob', { t: 2 }, () => bundleOf(B));
        const got: number[] = [];
        for (const envelope of [m1, m1, m2, m2]) await B.decryptFrom('alice', envelope, async (m: any) => { got.push(m.t); }).catch((error: any) => expect(error.message).toContain('Replayed'));
        expect(got).toEqual([1, 2]);
        await A.decryptFrom('bob', await B.encryptTo('alice', { t: 3 }, () => bundleOf(A)), async (m: any) => { got.push(m.t); });
        expect(got).toEqual([1, 2, 3]);
    });
    test('initial messages under a signed prekey older than the previous one are rejected', async () => {
        const { A, B, bundleOf } = await people();
        const old = await A.encryptTo('bob', { t: 'old' }, () => bundleOf(B));
        await B.prekeys(Date.now() + 8 * 86400000); await B.prekeys(Date.now() + 16 * 86400000);
        await expect(B.decryptFrom('alice', old, async () => {})).rejects.toThrow('Unknown signed prekey');
    });
    test('a new identity is flagged on its first message, and a verified contact is blocked until accepted', async () => {
        const { A, B, changes, bundleOf } = await people();
        await A.decryptFrom('bob', await B.encryptTo('alice', { t: 'v1' }, () => bundleOf(A)), async () => {});
        await A.setVerified('bob', true);
        const B2 = Signal.box(memory()), flags: any[] = [];
        await A.decryptFrom('bob', await B2.encryptTo('alice', { t: 'from new device' }, () => bundleOf(A)), async (m: any, info: any) => { flags.push([m.t, info.identityChanged]); });
        expect(flags).toEqual([['from new device', true]]);
        expect(changes).toContain('alice:bob');
        const safety = await A.safety('alice', 'bob', 'bob');
        expect(safety).toMatchObject({ verified: false, changed: true, blocked: true });
        await expect(A.encryptTo('bob', { t: 'x' }, () => bundleOf(B2))).rejects.toThrow('Security code changed');
        await A.acceptChange('bob');
        await B2.decryptFrom('alice', await A.encryptTo('bob', { t: 'ok' }, () => bundleOf(B2)), async (m: any) => { flags.push([m.t]); });
        expect(flags.at(-1)).toEqual(['ok']);
    });
    test('any identity change blocks sending, verified or not, until the user accepts it', async () => {
        const { A, B, bundleOf } = await people();
        await B.decryptFrom('alice', await A.encryptTo('bob', { t: 1 }, () => bundleOf(B)), async () => {});
        // A server swapping in its own key after the session is lost: never encrypt to it unacknowledged.
        const mallory = Signal.box(memory()); const fake = await mallory.prekeys();
        await A.forget('bob');
        await expect(A.encryptTo('bob', { t: 'secret' }, async () => ({ identity: fake.identity, signedPreKey: fake.signedPreKey, oneTimePreKey: null }))).rejects.toThrow('Security code changed');
        expect((await A.safety('alice', 'bob', 'bob')).blocked).toBe(true);
        await A.acceptChange('bob');
        await expect(A.encryptTo('bob', { t: 'after review' }, async () => ({ identity: fake.identity, signedPreKey: fake.signedPreKey, oneTimePreKey: null }))).resolves.toBeTruthy();
    });
    test('a pinned identity survives forgotten sessions and a later initial message from another key is a change', async () => {
        const { alice, A, B, bundleOf } = await people();
        await A.decryptFrom('bob', await B.encryptTo('alice', { t: 1 }, () => bundleOf(A)), async () => {});
        await A.forget('bob'); // sessions only; the pin is kept (contact removal and burn never touch it)
        expect(alice.map.get('peer:bob')).toBeTruthy();
        const impostor = Signal.box(memory()), flags: boolean[] = [];
        await A.decryptFrom('bob', await impostor.encryptTo('alice', { t: 'hi' }, () => bundleOf(A)), async (_m: any, info: any) => { flags.push(info.identityChanged); });
        expect(flags).toEqual([true]);
        expect((await A.safety('alice', 'bob', 'bob')).blocked).toBe(true);
    });
    test('a change to either identity half counts as a new identity', async () => {
        const A = Signal.box(memory()), one = await Signal.generateIdentity(), two = await Signal.generateIdentity();
        await A.notePeer('bob', one.pub);
        expect((await A.notePeer('bob', { dh: one.pub.dh, sign: two.pub.sign })).changed).toBe(true);
        expect((await A.notePeer('bob', { dh: two.pub.dh, sign: two.pub.sign })).changed).toBe(true);
        expect((await A.notePeer('bob', { dh: two.pub.dh, sign: two.pub.sign })).changed).toBe(true); // unchanged record keeps its flag
    });
    test('a handshake with a substituted identity fails and changes nothing', async () => {
        const { A, B, changes, bundleOf } = await people();
        const real = await B.encryptTo('alice', { t: 1 }, () => bundleOf(A));
        const mallory = await Signal.generateIdentity(), packet = JSON.parse(read(Signal.unb64(real)));
        packet.x.ik = mallory.pub;
        await expect(A.decryptFrom('bob', Signal.b64(text(JSON.stringify(packet))), async () => {})).rejects.toThrow();
        expect(changes).toEqual([]);
        expect(await A.peer('bob')).toBeUndefined();
        await A.decryptFrom('bob', real, async () => {});
        expect((await A.peer('bob')).identity).toEqual(B && (await B.identity()).pub);
    });
});

describe('key rotation', () => {
    async function people() {
        const alice = memory(), bob = memory();
        const A = Signal.box(alice), B = Signal.box(bob);
        const bundleOf = async (box: any) => { const keys = await box.prekeys(); return { identity: keys.identity, signedPreKey: keys.signedPreKey, oneTimePreKey: (await box.oneTimePreKeys(1))[0] }; };
        const deliver = async (to: any, from: string, envelope: string) => { const got: any[] = []; await to.decryptFrom(from, envelope, async (message: any) => { got.push(message); }); return got[0]; };
        return { alice, bob, A, B, bundleOf, deliver };
    }
    const sids = (store: any, contact: string) => store.map.get(`sessions:${contact}`)?.order ?? [];
    test('the shorter non-off interval wins; off on both sides means no rotation', () => {
        const day = 86400000;
        expect(Signal.rotationInterval(day, 7 * day)).toBe(day);
        expect(Signal.rotationInterval(0, 30 * day)).toBe(30 * day);
        expect(Signal.rotationInterval(7 * day, 0)).toBe(7 * day);
        expect(Signal.rotationInterval(0, 0)).toBe(0);
        expect(Signal.rotationInterval(12345, 99)).toBe(0); // Unknown values are ignored, never trusted.
    });
    test('rotation opens a fresh X3DH session; in-flight messages on the old one still decrypt, then old chains are dropped', async () => {
        const { alice, bob, A, B, bundleOf, deliver } = await people();
        expect(await deliver(B, 'alice', await A.encryptTo('bob', { n: 1 }, () => bundleOf(B)))).toEqual({ n: 1 });
        expect(await deliver(A, 'bob', await B.encryptTo('alice', { n: 2 }, () => bundleOf(A)))).toEqual({ n: 2 });
        const old = (await A.sessionInfo('bob')).sid;
        const inFlightFromBob = await B.encryptTo('alice', { n: 3 }, () => bundleOf(A)); // Sent on the old session.
        await A.rotate('bob');
        const rotation = await A.encryptTo('bob', { type: 'rotate' }, () => bundleOf(B));
        const fresh = (await A.sessionInfo('bob')).sid;
        expect(fresh).not.toBe(old);
        expect(JSON.parse(atob(rotation.replace(/-/g, '+').replace(/_/g, '/'))).x).toBeTruthy(); // A new X3DH handshake.
        // Bob's message from before the rotation arrives late: it decrypts, and does not undo the rotation.
        expect(await deliver(A, 'bob', inFlightFromBob)).toEqual({ n: 3 });
        expect((await A.sessionInfo('bob')).sid).toBe(fresh);
        // Bob takes the new session and drops his old chain keys, in the same write as the ratchet.
        const got: any[] = [];
        await B.decryptFrom('alice', rotation, async (message: any) => { got.push(message); return { rotate: true }; });
        expect(got).toEqual([{ type: 'rotate' }]);
        expect(sids(bob, 'alice')).toEqual([fresh]);
        // Bob answers on the new session, so alice drops hers too.
        expect(await deliver(A, 'bob', await B.encryptTo('alice', { n: 4 }, () => bundleOf(A)))).toEqual({ n: 4 });
        expect(sids(alice, 'bob')).toEqual([fresh]);
        // A message on the dropped old session can no longer be decrypted.
        await expect(deliver(A, 'bob', inFlightFromBob)).rejects.toMatchObject({ code: 'unknown-session' });
    });
    test('a pending rotation is never undone by a message on an old session: the next send still opens a new session', async () => {
        const { A, B, bundleOf, deliver } = await people();
        await deliver(B, 'alice', await A.encryptTo('bob', { n: 1 }, () => bundleOf(B)));
        await deliver(A, 'bob', await B.encryptTo('alice', { n: 2 }, () => bundleOf(A)));
        const old = (await A.sessionInfo('bob')).sid;
        const late = await B.encryptTo('alice', { n: 3 }, () => bundleOf(A));
        await A.rotate('bob');
        expect(await deliver(A, 'bob', late)).toEqual({ n: 3 }); // Arrives before alice sends again.
        const next = await A.encryptTo('bob', { type: 'rotate' }, () => bundleOf(B));
        expect(JSON.parse(atob(next.replace(/-/g, '+').replace(/_/g, '/'))).x).toBeTruthy();
        expect((await A.sessionInfo('bob')).sid).not.toBe(old);
    });
    test('an identity reset waits for in-flight work and leaves no session of the old identity behind', async () => {
        const { alice, A, B, bundleOf } = await people();
        let release: (value: any) => void = () => {};
        const slowBundle = new Promise(resolve => { release = resolve; });
        const sending = A.encryptTo('bob', { n: 1 }, () => slowBundle); // Holds alice's queue for bob.
        const oldIdentity = (await A.identity()).pub;
        const reset = A.resetIdentity();
        release(await bundleOf(B));
        await sending; await reset;
        expect(alice.map.get('sessions:bob')).toBeUndefined();
        expect((await A.identity()).pub).not.toEqual(oldIdentity);
    });
    test('a reset arriving on an old session is ignored and never makes an old chain the survivor', async () => {
        const { bob, A, B, bundleOf, deliver } = await people();
        await deliver(B, 'alice', await A.encryptTo('bob', { n: 1 }, () => bundleOf(B)));
        await deliver(A, 'bob', await B.encryptTo('alice', { n: 2 }, () => bundleOf(A)));
        const stale = await A.encryptTo('bob', { type: 'rotate' }, () => bundleOf(B)); // On the old session.
        await A.rotate('bob');
        await deliver(B, 'alice', await A.encryptTo('bob', { n: 3 }, () => bundleOf(B))); // Opens the new session.
        const fresh = (await B.sessionInfo('alice')).sid;
        expect(sids(bob, 'alice')).toHaveLength(2);
        await B.decryptFrom('alice', stale, async () => ({ rotate: true }));
        expect(sids(bob, 'alice')).toHaveLength(2); // Nothing pruned.
        expect(sids(bob, 'alice')).toContain(fresh);
    });
    test('session start times are recorded, and rotation never touches the pinned identity', async () => {
        const { A, B, bundleOf, deliver } = await people();
        const before = Date.now();
        await deliver(B, 'alice', await A.encryptTo('bob', { n: 1 }, () => bundleOf(B)));
        expect((await A.sessionInfo('bob')).startedAt).toBeGreaterThanOrEqual(before);
        expect((await B.sessionInfo('alice')).startedAt).toBeGreaterThanOrEqual(before);
        const pinned = await A.peer('bob');
        await A.rotate('bob'); await A.encryptTo('bob', { n: 2 }, () => bundleOf(B));
        expect(await A.peer('bob')).toEqual(pinned);
    });
    test('a new identity for this device drops sessions and prekeys but keeps pinned contacts', async () => {
        const { alice, A, B, bundleOf, deliver } = await people();
        await deliver(B, 'alice', await A.encryptTo('bob', { n: 1 }, () => bundleOf(B)));
        const old = (await A.identity()).pub;
        await A.resetIdentity();
        expect((await A.identity()).pub).not.toEqual(old);
        expect([...alice.map.keys()].some(key => key.startsWith('sessions:'))).toBe(false);
        expect(alice.map.get('peer:bob')).toBeTruthy();
    });
});
