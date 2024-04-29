import { Redis } from 'ioredis';
import { StunServer } from './app/server';
import { environment } from './environment/environment';

async function bootstrap() {
    const server = new StunServer('udp4', new Redis());
    server.start(parseInt(environment.APP.APP_PORT ?? '5995'));
}

bootstrap().then().catch();
