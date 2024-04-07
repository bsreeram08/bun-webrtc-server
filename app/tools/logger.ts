export const internalLogger = (requestId: string) => ({
    log: (message: string) => console.log(`[${requestId}] ${message}`),
    warn: (message: string) => console.warn(`[${requestId}] ${message}`),
    error: (message: string) => console.error(`[${requestId}] ${message}`),
});

export type TInternalLogger = ReturnType<typeof internalLogger>;
