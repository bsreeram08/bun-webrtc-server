import type { Prettify, UnionOfArrayValues } from '@libs/types';
import { deepFreeze } from './deep-freeze';

type ENABLED_SERVICES = 'GCLOUD' | 'PRISMA' | 'REDIS' | 'REDIS_CLUSTER' | 'RABBITMQ';

type REQUIRED_VALUES<T = string, U = string> = {
    required: Array<T>;
    optional: Array<U>;
};
type ENABLED_SERVICES_MAP = {
    [Key in ENABLED_SERVICES]: REQUIRED_VALUES;
};

type TCheckEnv = Prettify<Partial<ENABLED_SERVICES_MAP> & { [Key: string]: REQUIRED_VALUES }>;

type TResponse<T extends TCheckEnv> = {
    [K in keyof T]: Partial<{ [Key in UnionOfArrayValues<T[K]['optional']>]: string }> & { [Key in UnionOfArrayValues<T[K]['required']>]: string };
};

export function getEnvironmentVariables<const T extends TCheckEnv>(
    options: T,
    throwError = false,
): { variables: TResponse<T>; missingMandatory: Array<string>; missingOptional: Array<string> } {
    const keys: Array<keyof T> = Object.keys(options);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const env: any = {};
    const missingMandatory: Array<string> = [];
    const missingOptional: Array<string> = [];
    keys.forEach((key) => {
        env[key] = {};
        const category = options[key];
        const { optional, required } = category;
        required.forEach((variable) => {
            const value = process.env[variable];
            if (!value) missingMandatory.push(`${String(key)}.${variable}`);
            else env[key][variable] = value;
        });

        optional.forEach((variable) => {
            const value = process.env[variable];
            if (!value) missingOptional.push(`${String(key)}.${variable}`);
            else env[key][variable] = value;
        });
    });
    if (throwError && missingMandatory.length > 0) {
        throw new Error(`Missing environment variables [${JSON.stringify({ missingMandatory, missingOptional })}]`);
    }
    return { variables: deepFreeze(env), missingMandatory, missingOptional };
}
