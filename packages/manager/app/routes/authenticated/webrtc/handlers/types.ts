import type { TClientEvent, TClientEventResponse, TClientMessageType } from '../../../../services';
import type { TInternalLogger } from '../../../../tools';

export type TWebRtcEventHandler<T extends TClientMessageType> = (
    requestId: string,
    clientEvent: TClientEvent<T>,
    logger: TInternalLogger,
) => Promise<TClientEventResponse>;
