import type Elysia from 'elysia';
import { registerAuthenticatedRoute } from './auth.verify';

export function registerMembersRoute(server: Elysia) {
    registerAuthenticatedRoute(
        {
            handler: () => {},
            method: 'GET',
            path: '/friends',
        },
        server,
    );
}
