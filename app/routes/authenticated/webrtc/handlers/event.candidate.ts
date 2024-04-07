import type { TClientEvent } from '../../../../services';
import type { TInternalLogger } from '../../../../tools';
import type { TWebRtcEventHandler } from './types';

export const eventCandidateHandler = async function (requestId: string, event: TClientEvent<'eCandidate'>, logger: TInternalLogger) {
    return {
        eventName: 'createCallResponse',
        event: {
            name: '',
            description: '',
            callId: '',
        },
    };
} satisfies TWebRtcEventHandler<'eCandidate'>;
