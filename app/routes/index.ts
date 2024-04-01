import type { Server } from '../server';
import { registerMembersRoute, registerWebRtcRoutes } from './authenticated';
import { healthCheckRoute } from './unauthenticated';

const authenticatedRoutes = [registerMembersRoute, registerWebRtcRoutes];
const unAuthenticatedRoutes = [healthCheckRoute];
export function registerRoutes(app: Server) {
    /**
     * Register Un-Authenticated Routes
     */
    console.log(`Registering UnAuthenticated Route`);
    unAuthenticatedRoutes.forEach((route, index) => {
        console.log(`${index + 1}) ${route.name}`);
        route(app);
    });

    /**
     * Register Authenticated Routes
     */
    console.log(`Registering Authenticated Route`);
    authenticatedRoutes.forEach((route, index) => {
        console.log(`${index + 1}) ${route.name}`);
        route(app.server);
    });
}
