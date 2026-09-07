import { isIP } from 'node:net';

/** Validate the browser transports we support, using TURN's opaque URI syntax (RFC 7065). */
export function validateTurnUrl(value: string): void {
    const match = /^(turns?):(\[[^\]]+\]|[^:\[\]?\s/@#]+)(?::([0-9]{1,5}))?(?:\?transport=(udp|tcp))?$/.exec(value);
    if (!match) throw new Error('Invalid TURN URL');
    const [, scheme, host, port, transport] = match;
    if (port !== undefined && (Number(port) < 1 || Number(port) > 65535)) throw new Error('Invalid TURN URL port');
    // Browser support here covers UDP, TCP and TLS-over-TCP, not TURN-over-DTLS.
    if (scheme === 'turns' && transport === 'udp') throw new Error('TURN over TLS requires TCP transport');
    if (host!.startsWith('[')) {
        if (isIP(host!.slice(1, -1)) !== 6) throw new Error('Invalid TURN URL IPv6 address');
        return;
    }
    if (isIP(host!) === 4) return;
    const hostname = host!.endsWith('.') ? host!.slice(0, -1) : host!;
    if (/^[0-9.]+$/.test(hostname) || hostname.length > 253 || !hostname.split('.').every(label =>
        /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) {
        throw new Error('Invalid TURN URL hostname');
    }
}
