import { Server } from '../../server';

export function healthCheckRoute(app: Server) {
    app.server.get('/health-check', ({ set }) => {
        set.headers['content-type'] = 'text/html';
        return '<h1>Healthy</h1>';
    });
}
