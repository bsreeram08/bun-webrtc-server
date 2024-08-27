import { Redis } from 'ioredis';
import { StunServer } from './app/server';
import { TurnServer } from './app/turn-server';
import { environment } from './environment/environment';

async function bootstrap() {
    const redisClient = new Redis();
    const udp4Port = parseInt(environment.APP.APP_PORT_UDP4 ?? `3479`);
    const udp6Port = parseInt(environment.APP.APP_PORT_UDP6 ?? `3478`);

    const udp4PortTurn = parseInt(environment.APP.APP_PORT_UDP4_TURN ?? `3476`);
    const udp6PortTurn = parseInt(environment.APP.APP_PORT_UDP6_TURN ?? `3475`);

    if (udp4Port) {
        const serverUDP4 = new StunServer('udp4', redisClient);
        serverUDP4.start(udp4Port);
    }

    if (udp6Port) {
        const serverUDP6 = new StunServer('udp6', redisClient);
        serverUDP6.start(udp6Port);
    }

    if (udp4PortTurn) {
        const serverUDP4Turn = new TurnServer('udp4', redisClient);
        serverUDP4Turn.start(udp4PortTurn);
    }

    if (udp6PortTurn) {
        const serverUDP6Turn = new TurnServer('udp6', redisClient);
        serverUDP6Turn.start(udp6PortTurn);
    }
}

bootstrap().then().catch();
