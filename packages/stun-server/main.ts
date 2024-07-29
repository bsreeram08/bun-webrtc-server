import { Redis } from 'ioredis';
import { StunServer } from './app/server';
import { environment } from './environment/environment';

async function bootstrap() {
    const redisClient = new Redis();
    const udp4Port = parseInt(environment.APP.APP_PORT_UDP4 ?? `3479`);
    const udp6Port = parseInt(environment.APP.APP_PORT_UDP6 ?? `3478`);

    if (udp4Port) {
        const serverUDP4 = new StunServer('udp4', redisClient);
        serverUDP4.start(udp4Port);
    }

    if (udp6Port) {
        const serverUDP6 = new StunServer('udp6', redisClient);
        serverUDP6.start(udp6Port);
    }
}

bootstrap().then().catch();
