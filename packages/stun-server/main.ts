import { Redis } from 'ioredis';
import { StunServer } from './app/server';

async function bootstrap() {
    const server = new StunServer('udp4', new Redis());
    server.start(5995);
}

bootstrap().then().catch();
