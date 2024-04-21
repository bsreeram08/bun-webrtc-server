import { Server } from './app';
import { registerPlugins } from './app/plugins';
import { registerRoutes } from './app/routes';
import { environment, missingEnvironment } from './environment/environment';

async function bootstrap() {
    /**
     * Validate Environment Variables
     */
    if (missingEnvironment.mandatory.length > 0) {
        throw new Error(`Missing mandatory environment variables : ${missingEnvironment.mandatory.join(', ')}`);
    }
    const app = new Server();
    registerPlugins(app);
    registerRoutes(app);
    const port = environment.APP.PORT ?? 8080;
    app.server.listen({
        port: port,
    });
    console.log(`Listening to PORT : http://0.0.0.0:${port}`);
}

bootstrap().then().catch();
