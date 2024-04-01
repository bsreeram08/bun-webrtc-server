// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function deepFreeze(object: any) {
    const propNames = Object.getOwnPropertyNames(object);

    for (const name of propNames) {
        const value = object[name];

        if (value && typeof value === 'object') {
            deepFreeze(value);
        }
    }

    return Object.freeze(object);
}
