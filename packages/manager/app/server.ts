import Elysia from 'elysia';

export class Server {
    private app: Elysia = new Elysia();
    get server(): Elysia {
        return this.app;
    }
}
