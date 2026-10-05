import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../../packages/signaling/public/verify.js', import.meta.url), 'utf8');
const context: Record<string, any> = { crypto: globalThis.crypto, TextEncoder, DataView, Uint8Array };
context.window = context;
runInNewContext(source, context);
type Result = { code?: string; error?: string };
const Verify = context.Verify as {
    sasCode(prints: string[], nonces: string[]): Promise<string>;
    fingerprints(sdp: string): string;
    attach(peer: unknown, channel: unknown, report: (result: Result) => void): void;
};
const fp = (byte: string) => `sha-256 ${Array(32).fill(byte).join(':')}`;
const nonce = (digit: string) => digit.repeat(64);
const sdp = (print: string) => `v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:${print}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:${print}\r\n`;
const settle = async () => { for (let i = 0; i < 50; i++) await new Promise(resolve => setTimeout(resolve, 0)); };
const description = (local: string, remote: string) => ({ localDescription: { sdp: sdp(local) }, remoteDescription: { sdp: sdp(remote) } });

type End = { readyState: string; closed: boolean; peer?: End; onopen?: () => void; onmessage?: (event: { data: string }) => void; send(data: string): void; close(): void };
/** Two in-memory channel ends; `tamper` may rewrite frames travelling from a to b. */
function link(tamper: (frame: string) => string = frame => frame) {
    const end = (outbound: (frame: string) => string): End => ({
        readyState: 'open', closed: false,
        send(data) { const frame = outbound(data), target = this.peer!; queueMicrotask(() => target.onmessage?.({ data: frame })); },
        close() { this.closed = true; this.readyState = 'closed'; },
    });
    const a = end(tamper), b = end(frame => frame); a.peer = b; b.peer = a;
    return { a, b };
}
async function run(printsA: [string, string], printsB: [string, string], tamper?: (frame: string) => string) {
    const { a, b } = link(tamper), results: Result[] = [];
    Verify.attach(description(...printsA), a, result => { results[0] = result; });
    Verify.attach(description(...printsB), b, result => { results[1] = result; });
    await settle();
    return { results, a, b };
}

describe('call verification code', () => {
    test('is order-independent and formatted as six digits', async () => {
        const code = await Verify.sasCode([fp('AA'), fp('BB')], [nonce('1'), nonce('2')]);
        expect(code).toMatch(/^\d{3} \d{3}$/);
        expect(await Verify.sasCode([fp('BB'), fp('AA')], [nonce('2'), nonce('1')])).toBe(code);
    });
    test('changes when any fingerprint or nonce changes and rejects malformed input', async () => {
        const base = await Verify.sasCode([fp('AA'), fp('BB')], [nonce('1'), nonce('2')]);
        expect(await Verify.sasCode([fp('AA'), fp('BC')], [nonce('1'), nonce('2')])).not.toBe(base);
        expect(await Verify.sasCode([fp('AA'), fp('BB')], [nonce('1'), nonce('3')])).not.toBe(base);
        await expect(Verify.sasCode([fp('AA'), ''], [nonce('1'), nonce('2')])).rejects.toThrow();
        await expect(Verify.sasCode([fp('AA'), fp('BB')], [nonce('1'), 'zz'])).rejects.toThrow();
    });
    test('extracts unique DTLS fingerprints from SDP', () => {
        expect(Verify.fingerprints(sdp(fp('ab')))).toBe(fp('AB'));
        expect(() => Verify.fingerprints('v=0\r\n')).toThrow();
    });
    test('rejects decoy or non-canonical fingerprint lines a browser might parse differently', () => {
        // A relay could pair a canonical decoy with a real line only the browser accepts.
        expect(() => Verify.fingerprints(sdp(fp('AA')) + `a=fingerprint:${fp('BB')}\r\n`)).toThrow();
        expect(() => Verify.fingerprints(`a=fingerprint:${fp('AA')}\r\na=fingerprint:sha-256  ${fp('BB').slice(8)}\r\n`)).toThrow();
        expect(() => Verify.fingerprints(`a=fingerprint:${fp('AA')}\r\na=FINGERPRINT:${fp('BB')}\r\n`)).toThrow();
        expect(() => Verify.fingerprints(`a=fingerprint:sha-1 ${Array(20).fill('AA').join(':')}\r\n`)).toThrow();
    });
    test('fails when the negotiated certificate differs from the signaled fingerprint', async () => {
        const { a, b } = link(), results: Result[] = [];
        const forged = { ...description(fp('AA'), fp('BB')), sctp: { transport: { getRemoteCertificates: () => [new Uint8Array([1, 2, 3]).buffer] } } };
        Verify.attach(forged, a, result => { results[0] = result; });
        Verify.attach(description(fp('BB'), fp('AA')), b, result => { results[1] = result; });
        await settle();
        expect(results[0]?.error).toContain('Verification failed');
    });
    test('two honest peers derive the same code', async () => {
        const { results } = await run([fp('AA'), fp('BB')], [fp('BB'), fp('AA')]);
        expect(results[0]?.code).toMatch(/^\d{3} \d{3}$/);
        expect(results[1]?.code).toBe(results[0]!.code!);
    });
    test('a relay holding its own DTLS keys on each leg produces different codes', async () => {
        // A sees the relay's key 11; B sees 22. Each side hashes a different fingerprint pair.
        const { results } = await run([fp('AA'), fp('11')], [fp('BB'), fp('22')]);
        expect(results[0]?.code).toBeTruthy(); expect(results[1]?.code).toBeTruthy();
        expect(results[0]!.code).not.toBe(results[1]!.code);
    });
    test('a reveal that does not match its commitment fails and closes the channel', async () => {
        const { results, b } = await run([fp('AA'), fp('BB')], [fp('BB'), fp('AA')], frame =>
            JSON.parse(frame).type === 'reveal' ? JSON.stringify({ type: 'reveal', nonce: nonce('f') }) : frame);
        expect(results[1]?.error).toContain('Verification failed');
        expect(b.closed).toBe(true);
    });
    test('malformed, premature or duplicate packets fail verification', async () => {
        const attempt = async (...frames: string[]) => {
            const { b } = link(); const results: Result[] = [];
            Verify.attach(description(fp('BB'), fp('AA')), b, result => { results.push(result); });
            for (const data of frames) b.onmessage!({ data });
            await settle();
            return { results, b };
        };
        for (const bad of ['not json', JSON.stringify({ type: 'commit', hash: 'xyz' }), JSON.stringify({ type: 'reveal', nonce: nonce('1') }),
            JSON.stringify({ type: 'commit', hash: nonce('1'), extra: 1 }), 'x'.repeat(300)]) {
            const { results, b } = await attempt(bad);
            expect(results).toHaveLength(1);
            expect(results[0]!.error).toContain('Verification failed');
            expect(b.closed).toBe(true);
        }
        const duplicate = await attempt(JSON.stringify({ type: 'commit', hash: nonce('1') }), JSON.stringify({ type: 'commit', hash: nonce('2') }));
        expect(duplicate.results[0]?.error).toContain('Verification failed');
    });
});
