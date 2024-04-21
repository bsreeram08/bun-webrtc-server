import type { Cluster, Redis } from 'ioredis';

export class StunRedisClient {
    private connection: Redis | Cluster;
    constructor(conn: Redis | Cluster) {
        this.connection = conn;
        /**
         * Implement the reconnection + ping logic later
         */
    }
    get client() {
        return this.connection;
    }

    private userSharedSecretKey = (user: string) => this.keyFramer('users', user, 'secret');
    setSharedSecret(user: string, secret: string) {
        return this.client.set(this.userSharedSecretKey(user), secret);
    }
    getSharedSecret(user: string) {
        return this.client.get(this.userSharedSecretKey(user));
    }
    deleteSharedSecret(user: string) {
        return this.client.del(this.userSharedSecretKey(user));
    }

    private keyFramer(...keys: Array<string>) {
        return keys.join(':');
    }
}
