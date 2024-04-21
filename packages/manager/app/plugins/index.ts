import type { Server } from '../server';
import { registerAuth0 } from './auth0';
import { registerRedisInit } from './redis';

const plugins: Array<(app: Server) => void> = [registerAuth0, registerRedisInit];

export function registerPlugins(app: Server) {
    console.log(`Registering Plugin`);
    plugins.forEach((plugin, i) => {
        console.log(`${i + 1}) ${plugin.name}`);
        plugin(app);
    });
}
