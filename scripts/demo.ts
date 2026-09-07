import { randomBytes } from 'node:crypto';
import { startSignaling } from '../packages/signaling/server';

// A local-only, single-room demo. Production uses operator-managed credentials.
const adminToken = randomBytes(32).toString('base64url');
const port = 3000;
const origin = `http://localhost:${port}`;
const app = startSignaling({ adminToken, origin, port });
try {
    const response = await fetch(`${origin}/rooms`, { method: 'POST', headers: { Authorization: `Bearer ${adminToken}` } });
    if (!response.ok) throw new Error(`Room creation failed: ${response.status}`);
    const room = await response.json() as { roomId: string; participants: { token: string }[] };
    console.log('Local call demo. Open each private link in a separate browser window:');
    room.participants.forEach((participant, index) => {
        const hash = new URLSearchParams({ roomId: room.roomId, token: participant.token });
        console.log(`Participant ${index + 1}: ${origin}/#${hash}`);
    });
    console.log('Direct connections only. For remote callers, follow docs/deployment.md. Stop with Ctrl+C.');
} catch (error) { await app.stop(); throw error; }
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, async () => { await app.stop(); process.exit(0); });
