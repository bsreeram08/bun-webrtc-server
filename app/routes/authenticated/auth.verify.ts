import { bearer } from '@elysiajs/bearer';
import type { Elysia, Handler, HTTPMethod } from 'elysia';
import { decode, verify } from 'node-jsonwebtoken';
import { environment } from '../../../environment/environment';

export async function registerAuthenticatedRoute(config: TAuthenticatedRoute, server: Elysia) {
    server.use(bearer()).route(config.method, config.path, config.handler, {
        config: {},
        beforeHandle: async ({ bearer, set }) => {
            if (!bearer) {
                set.status = 400;
                set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                return 'Unauthorized, missing bearer';
            }
            /**
             * Validate the token
             */
            try {
                const decodedToken = decode(bearer);
                if (typeof decodedToken === 'string') {
                    set.status = 400;
                    set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                    return 'Unauthorized, invalid bearer';
                }
                if (decodedToken?.aud !== environment.AUTH0.AUTH0_AUDIENCE) {
                    set.status = 400;
                    set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                    return 'Unauthorized, invalid aud';
                }
                const isExpired = Date.now() >= (decodedToken.exp ?? 0) * 1000;
                if (isExpired) {
                    set.status = 400;
                    set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                    return 'Unauthorized, token expired';
                }
                try {
                    verify(bearer, environment.AUTH0.AUTH0_CERTIFICATE, {
                        algorithms: ['RS256'],
                        audience: environment.AUTH0.AUTH0_AUDIENCE,
                    });
                } catch (e) {
                    set.status = 400;
                    set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                    return 'Unauthorized, invalid bearer';
                }
            } catch (e) {
                set.status = 400;
                set.headers['WWW-Authenticate'] = `Bearer realm='sign', error="invalid_request"`;
                return 'Unauthorized, unknown error';
            }
        },
    });
}

export type TAuthenticatedRoute = {
    path: `/${string}`;
    method: HTTPMethod;
    handler: Handler;
};
