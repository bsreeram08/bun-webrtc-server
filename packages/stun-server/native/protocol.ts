import { isIP } from 'node:net';

const COOKIE = 0x2112a442;

export function fingerprint(bytes: Uint8Array): number {
    let crc = 0xffffffff;
    for (const byte of bytes) {
        crc ^= byte;
        for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    return (crc ^ 0xffffffff ^ 0x5354554e) >>> 0;
}

function attribute(type: number, value: Buffer): Buffer {
    const result = Buffer.alloc(4 + Math.ceil(value.length / 4) * 4);
    result.writeUInt16BE(type, 0);
    result.writeUInt16BE(value.length, 2);
    value.copy(result, 4);
    return result;
}

function addressBytes(address: string): Buffer {
    const family = isIP(address);
    if (family === 4) return Buffer.from(address.split('.').map(Number));
    if (family !== 6) throw new Error('Invalid source IP');
    let normalized = address.split('%')[0];
    if (normalized.includes('.')) {
        const colon = normalized.lastIndexOf(':');
        const tail = Buffer.from(normalized.slice(colon + 1).split('.').map(Number));
        normalized = normalized.slice(0, colon + 1) + tail.readUInt16BE(0).toString(16) + ':' + tail.readUInt16BE(2).toString(16);
    }
    const [left, right] = normalized.split('::');
    const head = left ? left.split(':') : [];
    const tail = right ? right.split(':') : [];
    const groups = right === undefined ? head : [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
    const bytes = Buffer.alloc(16);
    groups.forEach((group, index) => bytes.writeUInt16BE(parseInt(group, 16), index * 2));
    return bytes;
}

/** Anonymous RFC 8489 Binding discovery only; this is not an ICE or TURN endpoint. */
export function bindingResponse(packet: Buffer, address: string, port: number): Buffer | null {
    // Bound CPU and amplification, and silently discard non-STUN/malformed traffic.
    if (packet.length < 20 || packet.length > 1200 || packet.readUInt16BE(0) !== 1 ||
        packet.readUInt32BE(4) !== COOKIE || packet.readUInt16BE(2) !== packet.length - 20 ||
        packet.readUInt16BE(2) % 4 !== 0) return null;

    const unknown = new Set<number>();
    let authenticated = false;
    for (let offset = 20; offset < packet.length;) {
        if (offset + 4 > packet.length) return null;
        const type = packet.readUInt16BE(offset);
        const length = packet.readUInt16BE(offset + 2);
        const end = offset + 4 + Math.ceil(length / 4) * 4;
        if (end > packet.length) return null;
        if (type === 0x8028) {
            if (length !== 4 || end !== packet.length || packet.readUInt32BE(offset + 4) !== fingerprint(packet.subarray(0, offset))) return null;
        } else if (type === 0x0008 || type === 0x001c || type === 0x0006) {
            authenticated = true;
        } else if (type < 0x8000) unknown.add(type);
        offset = end;
    }
    // Never pretend to verify MESSAGE-INTEGRITY or answer peer connectivity checks.
    if (authenticated) return null;
    let attributes: Buffer[];
    if (unknown.size) {
        const codes = Buffer.alloc(unknown.size * 2);
        [...unknown].sort((a, b) => a - b).forEach((code, index) => codes.writeUInt16BE(code, index * 2));
        attributes = [attribute(0x0009, Buffer.concat([Buffer.from([0, 0, 4, 20]), Buffer.from('Unknown Attribute')])), attribute(0x000a, codes)];
    } else {
        const ip = addressBytes(address);
        const value = Buffer.alloc(4 + ip.length);
        value[1] = ip.length === 4 ? 1 : 2;
        value.writeUInt16BE(port ^ 0x2112, 2);
        for (let index = 0; index < ip.length; index++) value[4 + index] = ip[index] ^ packet[4 + index];
        attributes = [attribute(0x0020, value)];
    }
    const header = Buffer.from(packet.subarray(0, 20));
    header.writeUInt16BE(unknown.size ? 0x0111 : 0x0101, 0);
    header.writeUInt16BE(attributes.reduce((size, attr) => size + attr.length, 8), 2);
    const body = Buffer.concat([header, ...attributes]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(fingerprint(body));
    return Buffer.concat([body, attribute(0x8028, crc)]);
}
