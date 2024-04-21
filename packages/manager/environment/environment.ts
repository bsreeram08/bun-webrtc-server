import { getEnvironmentVariables } from '@libs/utils';
import 'dotenv';

const _environment = getEnvironmentVariables({
    AUTH0: {
        optional: [],
        required: ['AUTH0_AUTH_DOMAIN', 'AUTH0_AUDIENCE', 'AUTH0_CERTIFICATE'],
    },
    APP: {
        optional: ['PORT'],
        required: [],
    },
    REDIS: {
        required: ['REDIS_HOST', 'REDIS_PORT'],
        optional: [],
    },
});

export const environment = _environment.variables;
export const missingEnvironment = {
    mandatory: _environment.missingMandatory,
    optional: _environment.missingOptional,
};
