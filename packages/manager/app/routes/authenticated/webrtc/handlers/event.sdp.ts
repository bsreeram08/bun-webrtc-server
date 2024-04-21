import type { TClientEvent } from '../../../../services';
import type { TInternalLogger } from '../../../../tools';
import type { TWebRtcEventHandler } from './types';

export const eventSdpHandler = async function (requestId: string, event: TClientEvent<'eSdp'>, logger: TInternalLogger) {
    return {
        eventName: 'createCallResponse',
        event: {
            name: '',
            description: '',
            callId: '',
        },
    };
} satisfies TWebRtcEventHandler<'eSdp'>;
