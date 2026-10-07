import { bindingResponse } from './protocol';

/** Fixed global packet budget: bounded memory even with spoofed source addresses. */
export function packetBudget(limit = 1000, now = Date.now) {
    let start = now();
    let count = 0;
    return () => {
        const time = now();
        if (time - start >= 1000) { start = time; count = 0; }
        return ++count <= limit;
    };
}

export async function startStunServer(options: { hostname?: string; port?: number; packetsPerSecond?: number } = {}) {
    const allow = packetBudget(options.packetsPerSecond);
    return Bun.udpSocket({
        hostname: options.hostname ?? '127.0.0.1',
        port: options.port ?? 3478,
        socket: {
            data(socket, packet, port, address) {
                if (!allow()) return;
                const response = bindingResponse(packet, address, port);
                if (response) socket.send(response, port, address);
            },
            error(_socket, error) { console.error('STUN socket error:', error.message); },
        },
    });
}

if (import.meta.main) {
    const rawPort = process.env.STUN_PORT ?? '3478';
    if (!/^\d+$/.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535) throw new Error('STUN_PORT must be 1–65535');
    const socket = await startStunServer({ hostname: process.env.STUN_HOST ?? '127.0.0.1', port: Number(rawPort) });
    console.log(`STUN listening on ${socket.hostname}:${socket.port}`);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => { socket.close(); process.exit(0); });
}
