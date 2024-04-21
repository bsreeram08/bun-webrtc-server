import { generateID } from '@jetit/id';
import { Cluster, Redis, type ClusterNode, type ClusterOptions, type RedisOptions } from 'ioredis';

type TRedis = Redis | Cluster;

export class RedisStore {
    private static redisInstance: Redis | Cluster;

    static initializeRedis(options: RedisOptions) {
        this.redisInstance = new Redis(options);
    }

    static initializeCluster(startupNodes: ClusterNode[], options?: ClusterOptions) {
        this.redisInstance = new Cluster(startupNodes, options);
    }

    static get redis(): TRedis {
        if (!this.redisInstance) throw new Error(`Initialize redis using RedisStore.initializeRedis or RedisStore.initializeCluster first`);
        return this.redisInstance;
    }

    static instanceId: string = generateID('HEX');
}

export function getRedis() {
    return RedisStore.redis;
}
