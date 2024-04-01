import { bearer } from '@elysiajs/bearer';
import type { Server } from '../server';

export function registerAuth0(app: Server) {
    app.server.use(bearer());
}
