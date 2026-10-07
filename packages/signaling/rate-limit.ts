import { isIP } from 'node:net';

/** Accept proxy identity only behind the explicitly enabled local reverse proxy. */
export function requestSource(remoteAddress: string | undefined, headers: Headers, trustProxy = false): string {
    const address = remoteAddress ?? 'unknown';
    const loopback = address === '::1' || address === '::ffff:127.0.0.1' || (isIP(address) === 4 && address.startsWith('127.'));
    const forwarded = trustProxy && loopback ? headers.get('x-real-ip') : null;
    // Reject lists, ports, whitespace and malformed values; Caddy overwrites this header.
    return forwarded && isIP(forwarded) ? forwarded : address;
}

/** Fixed one-second budgets, with bounded source state reset each window. */
export function requestLimiter(options: {
    perSource?: number;
    global?: number;
    maxSources?: number;
    now?: () => number;
} = {}) {
    const perSource = options.perSource ?? 60;
    const global = options.global ?? 2000;
    const maxSources = options.maxSources ?? 4096;
    for (const value of [perSource, global, maxSources]) {
        if (!Number.isSafeInteger(value) || value < 1) throw new Error('Rate limits must be positive safe integers');
    }
    const now = options.now ?? (() => performance.now());
    let windowStart = now();
    let total = 0;
    const sources = new Map<string, number>();
    return (source: string): boolean => {
        const time = now();
        if (time - windowStart >= 1000) {
            sources.clear(); total = 0; windowStart = time;
        }
        const count = sources.get(source) ?? 0;
        if (count >= perSource || total >= global) return false;
        if (count === 0 && sources.size >= maxSources) return false;
        sources.set(source, count + 1);
        total++;
        return true;
    };
}
