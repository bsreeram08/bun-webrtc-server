import { generateID } from '@jetit/id';
import { t, type Elysia } from 'elysia';
import { clientStore, type TClientEvent } from '../../../services';
import { internalLogger } from '../../../tools';
import { verifyBearer } from '../auth.verify';

export function registerWebRtcRoutes(server: Elysia) {
    server.ws('/call/:userId', {
        sendPings: true,
        idleTimeout: 30,
        beforeHandle: ({ set, path, headers }) => {
            const requestId = generateID('HEX');
            set.headers['X-Server-Request-Id'] = requestId;
            const protocols = headers['sec-websocket-protocol'];
            if (!protocols) {
                set.status = 400;
                set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request'`;
                return { error: 'Missing secure protocols' };
            }
            const [bearer, token] = protocols.split(', ');
            if (!bearer) {
                set.status = 400;
                set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request'`;
                return { error: 'Missing bearer header' };
            }
            const tokenVerificationResult = verifyBearer(requestId, token);
            if (tokenVerificationResult.status === 'ERROR') {
                set.status = tokenVerificationResult.data.status;
                set.headers = {
                    ...set.headers,
                    ...tokenVerificationResult.data.headers,
                };
                return tokenVerificationResult.data.data;
            } else console.log(`[${requestId}] Authenticated Successfully`);
        },
        open: async (ws) => {
            const requestId = ws.data.set.headers['X-Server-Request-Id'];
            const logger = internalLogger(requestId);
            const userId = ws.data.params.userId;
            logger.log(`[${userId}] Connected`);
            await clientStore().users().user(userId).connected();
        },
        message: (ws, _message) => {
            const requestId = ws.data.set.headers['X-Server-Request-Id'];
            const logger = internalLogger(requestId);
            const userId = ws.data.params.userId;
            logger.log(`[${userId}] Sent this message ${_message}`);
            const message = <TClientEvent>_message;
        },
        close: async (ws) => {
            const requestId = ws.data.set.headers['X-Server-Request-Id'];
            const logger = internalLogger(requestId);
            const userId = ws.data.params.userId;
            logger.log(`[${userId}] Disconnected`);
            await clientStore().users().user(userId).disconnected();
        },
        error: (ws) => {
            const requestId = ws.set.headers['X-Server-Request-Id'];
            const logger = internalLogger(requestId);
            const userId = (<{ userId: string }>ws.params).userId;
            logger.log(`[${userId}] Errored`);
        },
        params: t.Object({
            userId: t.String(),
        }),
    });
}
