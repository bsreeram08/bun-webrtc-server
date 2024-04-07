import type { TClientEvent } from '../../../../services';
import type { TInternalLogger } from '../../../../tools';
import type { TWebRtcEventHandler } from './types';

export const answerCallHandler = async function (requestId: string, event: TClientEvent<'answerCall'>, logger: TInternalLogger) {
    logger.log(`Received answer call event`);
    /**
     * Call Answered by the client
     * 1. Check if the call exists
     *      Call has a list of participant IDs
     * 2. Add the participant as the call attendee
     *      tore the offer SDP for the caller
     * 3. Find all sdp peers and send the SDP protocol
     * 4. For every SDP protocol acknowledged send Candidate
     */

    return {
        eventName: 'createCallResponse',
        event: {
            name: '',
            description: '',
            callId: '',
        },
    };
} satisfies TWebRtcEventHandler<'answerCall'>;
