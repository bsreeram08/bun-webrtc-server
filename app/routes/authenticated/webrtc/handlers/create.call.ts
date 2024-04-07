import type { TClientEvent } from '../../../../services';
import type { TInternalLogger } from '../../../../tools';
import type { TWebRtcEventHandler } from './types';

export const createCallHandler = async function (requestId: string, event: TClientEvent<'createCall'>, logger: TInternalLogger) {
    return {
        eventName: 'createCallResponse',
        event: {
            name: '',
            description: '',
            callId: '',
        },
    };
} satisfies TWebRtcEventHandler<'createCall'>;
