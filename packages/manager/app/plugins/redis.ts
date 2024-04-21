import type { RedisOptions } from 'ioredis';
import { environment } from '../../environment/environment';
import type { Server } from '../server';
import { clientStore, RedisStore } from '../services';

export async function registerRedisInit(app: Server) {
    /**
     * Connect to regular redis
     */
    const options: RedisOptions = {
        host: environment.REDIS.REDIS_HOST,
        port: parseInt(environment.REDIS.REDIS_PORT),
    };
    RedisStore.initializeRedis(options);
    asyncTasks().then();
    process.on('beforeExit', async (code) => {
        console.log(`Passive closing redis on code ${code}`);
        await clientStore().instances().instance(RedisStore.instanceId).remove();
        RedisStore.redis.disconnect(false);
    });
    process.on('exit', async (code) => {
        console.log(`Passive closing redis on code ${code}`);
        await clientStore().instances().instance(RedisStore.instanceId).remove();
        RedisStore.redis.disconnect(false);
    });
    app.server.on('stop', async () => {
        console.log(`Passive closing redis on code`);
        await clientStore().instances().instance(RedisStore.instanceId).remove();
        RedisStore.redis.disconnect(false);
    });
}

async function asyncTasks() {
    await clientStore().instances().instance(RedisStore.instanceId).add();
}
