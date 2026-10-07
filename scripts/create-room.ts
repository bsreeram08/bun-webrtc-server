// Run on the trusted host; the admin token never goes into a browser or invite URL.
const origin = process.env.PUBLIC_ORIGIN ?? 'http://localhost:3000';
const adminToken = process.env.ADMIN_TOKEN;
if (!adminToken) throw new Error('ADMIN_TOKEN is required');
const url = new URL(origin);
if (url.origin !== origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('Use an HTTPS origin (HTTP allowed only on loopback)');
const response = await fetch(`${origin}/rooms`, {
    method: 'POST', headers: { Authorization: `Bearer ${adminToken}` }, redirect: 'error',
});
if (!response.ok) throw new Error(`Room creation failed: HTTP ${response.status}`);
const room = await response.json() as { roomId: string; expiresAt: number; participants: { token: string }[] };
console.log(`Room expires: ${new Date(room.expiresAt).toISOString()}`);
room.participants.forEach((participant, index) => {
    const invite = new URL(origin);
    invite.hash = new URLSearchParams({ roomId: room.roomId, token: participant.token }).toString();
    console.log(`Participant ${index + 1}: ${invite}`);
});
