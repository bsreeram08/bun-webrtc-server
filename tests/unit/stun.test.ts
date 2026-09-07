import { describe, expect, test } from 'bun:test';
import { createSocket } from 'node:dgram';
import { bindingResponse, fingerprint } from '../../packages/stun-server/native/protocol';
import { packetBudget, startStunServer } from '../../packages/stun-server/native/server';

const request = () => Buffer.from('000100002112a442b7e7a701bc34d686fa87dfae', 'hex');
function withAttribute(type: number, value: Buffer) {
    const attr = Buffer.alloc(4 + Math.ceil(value.length / 4) * 4);
    attr.writeUInt16BE(type); attr.writeUInt16BE(value.length, 2); value.copy(attr, 4);
    const packet = Buffer.concat([request(), attr]);
    packet.writeUInt16BE(attr.length, 2);
    return packet;
}

describe('STUN discovery', () => {
    test('IPv4 mapped bytes match RFC 5769 and transaction is preserved', () => {
        const response = bindingResponse(request(), '192.0.2.1', 32853)!;
        expect(response.subarray(20, 32).toString('hex')).toBe('002000080001a147e112a643');
        expect(response.readUInt16BE(0)).toBe(0x0101);
        expect(response.subarray(4, 20)).toEqual(request().subarray(4));
        expect(response.readUInt16BE(2)).toBe(response.length - 20);
    });
    test('IPv6 mapped bytes match RFC 5769', () => {
        const response = bindingResponse(request(), '2001:db8:1234:5678:11:2233:4455:6677', 32853)!;
        expect(response.subarray(24, 44).toString('hex')).toBe('0002a1470113a9faa5d3f179bc25f4b5bed2b9d9');
    });
    test('compressed and mapped IPv6', () => {
        expect(bindingResponse(request(), '::1', 1)).toEqual(bindingResponse(request(), '0:0:0:0:0:0:0:1', 1));
        expect(bindingResponse(request(), '::ffff:192.0.2.1', 1)).toEqual(bindingResponse(request(), '0:0:0:0:0:ffff:c000:201', 1));
    });
    test('CRC against the RFC 5769 request vector', () => {
        const vector = Buffer.from('000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2', 'hex');
        expect(fingerprint(vector)).toBe(0xe57a3bcf);
    });
    test('valid fingerprint accepted and corruption dropped', () => {
        const packet = withAttribute(0x8028, Buffer.alloc(4));
        packet.writeUInt32BE(fingerprint(packet.subarray(0, 20)), 24);
        expect(bindingResponse(packet, '127.0.0.1', 1)).not.toBeNull();
        packet[24] ^= 1;
        expect(bindingResponse(packet, '127.0.0.1', 1)).toBeNull();
    });
    test('unknown required attributes receive 420 with original transaction', () => {
        const response = bindingResponse(withAttribute(0x1234, Buffer.alloc(0)), '127.0.0.1', 1)!;
        expect(response.readUInt16BE(0)).toBe(0x0111);
        expect(response.subarray(8, 20)).toEqual(request().subarray(8));
        expect(response.subarray(24, 28)).toEqual(Buffer.from([0, 0, 4, 20]));
    });
    test('malformed, legacy, authenticated, and non-request packets are dropped', () => {
        const malformed = [Buffer.alloc(0), Buffer.alloc(20), request().subarray(0, 19), withAttribute(8, Buffer.alloc(20))];
        const wrongLength = request(); wrongLength.writeUInt16BE(4, 2); malformed.push(wrongLength);
        const indication = request(); indication.writeUInt16BE(0x0011); malformed.push(indication);
        const overflow = withAttribute(0x8022, Buffer.alloc(4)); overflow.writeUInt16BE(12, 22); malformed.push(overflow);
        for (const packet of malformed) expect(bindingResponse(packet, '127.0.0.1', 1)).toBeNull();
    });
    test('packet budget recovers without allocating per-address state', () => {
        let time = 0; const allow = packetBudget(2, () => time);
        expect([allow(), allow(), allow()]).toEqual([true, true, false]);
        time = 1000; expect(allow()).toBe(true);
    });
    for (const [hostname, type] of [['127.0.0.1', 'udp4'], ['::1', 'udp6']] as const) {
        test(`real ${type} socket reports client address and port`, async () => {
            const server = await startStunServer({ hostname, port: 0 });
            const client = createSocket(type);
            try {
                const response = await new Promise<Buffer>((resolve, reject) => {
                    const timer = setTimeout(() => reject(new Error('UDP response timeout')), 2000);
                    client.once('message', (message) => { clearTimeout(timer); resolve(message); });
                    client.once('error', (error) => { clearTimeout(timer); reject(error); });
                    client.send(request(), server.port, hostname);
                });
                expect(response).toEqual(bindingResponse(request(), hostname, client.address().port)!);
            } finally { client.close(); server.close(); }
        });
    }
});
