import { bearer } from '@elysiajs/bearer';
import { generateID } from '@jetit/id';
import type { Elysia, Handler, HTTPMethod } from 'elysia';
//@ts-ignore // TS behaving weirdly when the dependency is present
import { decode, verify } from 'node-jsonwebtoken';
import { environment } from '../../../environment/environment';

export async function registerAuthenticatedRoute(config: TAuthenticatedRoute, server: Elysia) {
    server.use(bearer()).route(config.method, config.path, config.handler, {
        config: {},

        beforeHandle: async ({ bearer, set, path }) => {
            const requestId = generateID('HEX');
            set.headers['X-Server-Request-Id'] = requestId;
            console.log(`[${requestId}] Received a new Request for path ${path} `);
            const result = verifyBearer(requestId, bearer);
            if (result.status === 'ERROR') {
                set.status = result.data.status;
                set.headers = { ...result.data.headers, ...set.headers };
                return result.data.data;
            }
        },
    });
}

export type TAuthenticatedRoute = {
    path: `/${string}`;
    method: HTTPMethod;
    handler: Handler;
};

type TRouteVerificationResult =
    | {
          status: 'ERROR';
          data: {
              status: number;
              headers: Record<string, string>;
              data: object;
          };
      }
    | { status: 'SUCCESS' };
export function verifyBearer(requestId: string, bearer?: string): TRouteVerificationResult {
    if (!bearer) {
        console.log(`[${requestId}] No Bearer`);
        return {
            status: 'ERROR',
            data: {
                status: 400,
                headers: {
                    'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                },
                data: { error: 'Unauthorized, missing bearer' },
            },
        };
    }
    /**
     * Validate the token
     */
    try {
        const decodedToken = decode(bearer);
        console.log(`[${requestId}] Decoded Bearer`);
        if (typeof decodedToken === 'string') {
            console.log(`[${requestId}] Decoded to string, invalid bearer`);
            return {
                status: 'ERROR',
                data: {
                    status: 400,
                    headers: {
                        'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                    },
                    data: { error: 'Unauthorized, invalid bearer' },
                },
            };
        }
        if (decodedToken?.aud !== environment.AUTH0.AUTH0_AUDIENCE) {
            console.log(decodedToken);
            console.log(`[${requestId}] Invalid Audience : ${decodedToken?.aud} != ${environment.AUTH0.AUTH0_AUDIENCE}`);
            return {
                status: 'ERROR',
                data: {
                    status: 400,
                    headers: {
                        'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                    },
                    data: { error: 'Unauthorized, invalid aud' },
                },
            };
        }
        const isExpired = Date.now() >= (decodedToken.exp ?? 0) * 1000;
        if (isExpired) {
            console.log(`[${requestId}] Token expired`);
            return {
                status: 'ERROR',
                data: {
                    status: 400,
                    headers: {
                        'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                    },
                    data: { error: 'Unauthorized, token expired' },
                },
            };
        }
        try {
            verify(bearer, environment.AUTH0.AUTH0_CERTIFICATE, {
                algorithms: ['RS256'],
                audience: environment.AUTH0.AUTH0_AUDIENCE,
            });
            console.log(`[${requestId}] Token verified`);
        } catch (e) {
            console.log(`[${requestId}] Token verification failed with error ${e}`);
            return {
                status: 'ERROR',
                data: {
                    status: 400,
                    headers: {
                        'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                    },
                    data: { error: 'Unauthorized, invalid bearer' },
                },
            };
        }
    } catch (e) {
        console.log(`[${requestId}] Token verification failed with error ${e}`);
        return {
            status: 'ERROR',
            data: {
                status: 400,
                headers: {
                    'WWW-Authenticate': `Bearer realm='sign', error="invalid_request"`,
                },
                data: { error: 'Unauthorized, unknown error' },
            },
        };
    }
    return {
        status: 'SUCCESS',
    };
}
