import { getEnvironmentVariables } from '@libs/utils';
import 'dotenv';

const _environment = getEnvironmentVariables({
    REDIS: {
        required: ['REDIS_HOST', 'REDIS_PORT'],
        optional: [],
    },
    STUN: {
        required: [],
        optional: ['ALTERNATE_IP', 'ALTERNATE_PORT'],
    },
    APP: {
        required: [],
        optional: ['APP_PORT_UDP4', 'APP_PORT_UDP6'],
    },
});

export const environment = _environment.variables;
export const missingEnvironment = {
    mandatory: _environment.missingMandatory,
    optional: _environment.missingOptional,
};
