import type { TClientEvent, TClientEventResponse, TClientMessageType } from '../../../services';
import { internalLogger } from '../../../tools';
import { answerCallHandler, createCallHandler, eventCandidateHandler, eventSdpHandler, type TWebRtcEventHandler } from './handlers';

const handlers = {
    createCall: async function (requestId, event, logger) {
        return createCallHandler(requestId, event, logger);
    },
    eSdp: async function (requestId, event, logger) {
        return eventSdpHandler(requestId, event, logger);
    },
    eCandidate: async function (requestId, event, logger) {
        return eventCandidateHandler(requestId, event, logger);
    },
    answerCall: async function (requestId, event, logger) {
        return answerCallHandler(requestId, event, logger);
    },
} as const satisfies { [Key in TClientMessageType]: TWebRtcEventHandler<Key> };
export async function handleMessage(requestId: string, event: TClientEvent): Promise<TClientEventResponse> {
    const { eventName } = event;
    const handler = handlers[eventName];
    const logger = internalLogger(requestId);
    if (!handler) {
        logger.log(`No handler for the event ${eventName}`);
        return {
            eventName: 'error',
            event: {
                codes: [],
                message: `Invalid event ${eventName}.`,
            },
        };
    }

    return handler(requestId, <never>event, logger);
}

/**
 * WebRTC Signaling Flow:
 *
 * 1. Client creates a call
 *    - Call has a list of participant IDs
 *
 * 2. Caller creates an offer SDP
 *    - Store the offer SDP for the caller
 *
 * 3. Notify all participants of the call
 *    - Check if each participant is already in another call
 *      - If so, then notify the caller that the participant is busy
 *
 * 4. Each participant who accepts the call creates an answer SDP
 *    - Store the answer SDP for each participant
 *
 * 5. Send each participant's answer SDP to the caller
 *
 * 6. Caller and participants start exchanging ICE candidates
 *    - Each peer (caller and participants) generates their own ICE candidates
 *    - Store the ICE candidates for each peer
 *    - Send the ICE candidates to the corresponding peers
 *      - Caller sends its ICE candidates to each participant
 *      - Each participant sends their ICE candidates to the caller
 *
 * 7. WebRTC connection is established once the offer, answer, and ICE candidates are exchanged and processed by the peers
 *
 * Message types handled by the WebSocket server:
 *
 * - 'offer': Sent by the caller to initiate the call. Store the offer SDP and notify the participants.
 * - 'answer': Sent by each participant who accepts the call. Store the answer SDP and send it to the caller.
 * - 'candidate': Sent by each peer to exchange ICE candidates. Store the candidate information and forward it to the corresponding peer(s).
 *
 * Note:
 * - Handle the case when a participant rejects the call or is busy in another call. Notify the caller accordingly.
 * - The WebRTC signaling process may vary slightly depending on the specific implementation and the client-side library being used.
 *   Adapt the flow based on your specific requirements and the WebRTC library you are using on the client-side.
 */
