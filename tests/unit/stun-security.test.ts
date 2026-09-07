import { describe, expect, test } from 'bun:test';
import { createSocket } from 'node:dgram';
import { bindingResponse, fingerprint } from '../../packages/stun-server/native/protocol';
import { startStunServer } from '../../packages/stun-server/native/server';

const header = () => Buffer.from('000100002112a442b7e7a701bc34d686fa87dfae', 'hex');
function attribute(type: number, bytes = Buffer.alloc(0), padding = 0) {
    const output = Buffer.alloc(4 + Math.ceil(bytes.length / 4) * 4, padding);
    output.writeUInt16BE(type, 0); output.writeUInt16BE(bytes.length, 2); bytes.copy(output, 4);
    return output;
}
function packet(...attributes: Buffer[]) {
    const output = Buffer.concat([header(), ...attributes]);
    output.writeUInt16BE(output.length - 20, 2);
    return output;
}
function parseAttributes(bytes: Buffer) {
    const values = new Map<number, Buffer>();
    for (let offset = 20; offset < bytes.length;) {
        const length = bytes.readUInt16BE(offset + 2);
        values.set(bytes.readUInt16BE(offset), bytes.subarray(offset + 4, offset + 4 + length));
        offset += 4 + Math.ceil(length / 4) * 4;
    }
    return values;
}
function checkResponse(input: Buffer, output: Buffer | null) {
    if (!output) return;
    expect(output.length).toBeLessThanOrEqual(1200);
    // Bounded reflection remains possible: an anonymous UDP responder is not amplification-free.
    expect(output.length).toBeLessThanOrEqual(input.length * 3);
    expect(output.length % 4).toBe(0);
    expect(output.readUInt16BE(2)).toBe(output.length - 20);
    expect(output.subarray(4, 20)).toEqual(input.subarray(4, 20));
    expect([0x0101, 0x0111]).toContain(output.readUInt16BE(0));
    expect(output.readUInt16BE(output.length - 8)).toBe(0x8028);
    expect(output.readUInt32BE(output.length - 4)).toBe(fingerprint(output.subarray(0, -8)));
}

describe('anonymous STUN parser security boundaries', () => {
    test('deterministic malformed datagram corpus cannot throw or produce oversized responses', () => {
        let seed = 0x27d4eb2f;
        function next() { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; }
        const valid = [header(), packet(attribute(0x8022, Buffer.from('software'))), packet(attribute(0x1234)), packet(attribute(0x8028, Buffer.alloc(4)))];
        for (let i = 0; i < 12000; i++) {
            let input: Buffer;
            if (i % 3 === 0) {
                input = Buffer.from(valid[next() % valid.length]);
                for (let j = 0; j < 1 + next() % 4; j++) input[next() % input.length] = next() & 255;
            } else {
                input = Buffer.alloc(next() % 1400);
                for (let j = 0; j < input.length; j++) input[j] = next() & 255;
                if (i % 3 === 1 && input.length >= 20) {
                    header().copy(input); input.writeUInt16BE(input.length - 20, 2);
                }
            }
            const original = Buffer.from(input);
            const response = bindingResponse(input, i % 2 ? '192.0.2.1' : '2001:db8::1', 65535);
            checkResponse(input, response);
            expect(input).toEqual(original);
        }
    });
    test('unknown required attribute lists are bounded, deduplicated and correctly padded', () => {
        for (const count of [1, 2, 3, 295]) {
            const request = packet(...Array.from({ length: count }, (_, i) => attribute(0x1000 + i)));
            const response = bindingResponse(request, '192.0.2.1', 3478)!;
            checkResponse(request, response);
            const attributes = parseAttributes(response);
            expect(attributes.get(0x0009)!.subarray(0, 4)).toEqual(Buffer.from([0, 0, 4, 20]));
            const unknown = attributes.get(0x000a)!;
            expect(unknown.length).toBe(count * 2);
            for (let i = 0; i < count; i++) expect(unknown.readUInt16BE(i * 2)).toBe(0x1000 + i);
        }
        const duplicate = bindingResponse(packet(attribute(0x1234), attribute(0x1234)), '192.0.2.1', 3478)!;
        expect(parseAttributes(duplicate).get(0x000a)).toEqual(Buffer.from([0x12, 0x34]));
    });
    test('optional attributes ignore their values and nonzero alignment padding', () => {
        const request = packet(attribute(0x8022, Buffer.from('x'), 255));
        expect(bindingResponse(request, '192.0.2.1', 3478)).toEqual(bindingResponse(header(), '192.0.2.1', 3478));
    });
    test('authentication attributes never receive anonymous success or an unsigned error', () => {
        for (const type of [0x0006, 0x0008, 0x001c]) {
            for (const value of [Buffer.alloc(0), Buffer.alloc(4), Buffer.alloc(32)]) {
                expect(bindingResponse(packet(attribute(0x1234), attribute(type, value)), '192.0.2.1', 3478)).toBeNull();
            }
        }
    });
    test('fingerprint must be last, have four bytes and cover the full header length', () => {
        const misplaced = packet(attribute(0x8028, Buffer.alloc(4)), attribute(0x8022));
        misplaced.writeUInt32BE(fingerprint(misplaced.subarray(0, 20)), 24);
        expect(bindingResponse(misplaced, '192.0.2.1', 3478)).toBeNull();
        for (const length of [0, 1, 3, 5, 8]) {
            expect(bindingResponse(packet(attribute(0x8028, Buffer.alloc(length))), '192.0.2.1', 3478)).toBeNull();
        }
        const duplicate = packet(attribute(0x8028, Buffer.alloc(4)), attribute(0x8028, Buffer.alloc(4)));
        expect(bindingResponse(duplicate, '192.0.2.1', 3478)).toBeNull();
    });
    test('over-cap, trailing, non-binding and response packets are silently discarded', () => {
        expect(bindingResponse(packet(attribute(0x8022, Buffer.alloc(1180))), '192.0.2.1', 3478)).toBeNull();
        expect(bindingResponse(Buffer.concat([header(), Buffer.alloc(4)]), '192.0.2.1', 3478)).toBeNull();
        for (const type of [0x0011, 0x0101, 0x0111, 0x0003, 0x4001, 0x8001]) {
            const request = header(); request.writeUInt16BE(type);
            expect(bindingResponse(request, '192.0.2.1', 3478)).toBeNull();
        }
    });
    test('real UDP server applies its shared packet budget to a local burst', async () => {
        const server = await startStunServer({ hostname: '127.0.0.1', port: 0, packetsPerSecond: 2 });
        const client = createSocket('udp4');
        const received: Buffer[] = [];
        try {
            await new Promise<void>((resolve, reject) => {
                const timer = setTimeout(resolve, 200);
                client.on('message', message => received.push(message));
                client.once('error', error => { clearTimeout(timer); reject(error); });
                for (let i = 0; i < 20; i++) client.send(header(), server.port, '127.0.0.1');
            });
            expect(received).toHaveLength(2);
            for (const response of received) checkResponse(header(), response);
        } finally { client.close(); server.close(); }
    });
});
