import type Elysia from 'elysia';
export function registerWebRtcRoutes(server: Elysia) {
    server.ws('/call', {
        open: (ws) => {
            console.log(ws.id, 'Connected');
        },
        message: (ws, message) => {
            console.log(ws.id, `Sent this message ${message}`);
        },
    });
}
