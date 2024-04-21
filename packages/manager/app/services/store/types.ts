export type TClientMessageType = keyof TClientMessageTypeMap;

export type TClientMessageTypeMap = {
    eSdp: TWebRtcSdp;
    eCandidate: {
        callId: string;
        candidate: TWebRtcCandidate;
    };
    createCall: {
        name: string;
        description?: string;
        offer: TWebRtcSdp['sdp'];
    };
    answerCall: TWebRtcSdp;
};
export type TClientEvent<T extends TClientMessageType = TClientMessageType> = {
    userId: string;
    event: TClientMessageTypeMap[T];
    eventName: T;
};

export type TWebRtcCandidate = {
    type: 'candidate';
    candidate: string;
    sdpMid: 'audio';
    sdpMLineIndex: number;
};

export type TWebRtcSdp = { sdp: string; callId: string };

export type TClientResponseMessageTypeMap = {
    createCallResponse: {
        name: string;
        description: string;
        callId: string;
    };
    addAttendee: {
        callId: string;
        name: string;
        attendee: TAttendee;
    };
    notifyCall: {
        callId: string;
        name: string;
        description: string;
        attendees: Array<TAttendee>;
    };
    error: {
        message: string;
        codes: Array<number>;
    };
};
export type TClientResponseMessageType = keyof TClientResponseMessageTypeMap;
export type TClientEventResponse<T extends TClientResponseMessageType = TClientResponseMessageType> = {
    eventName: T;
    event: TClientResponseMessageTypeMap[T];
};

export type TAttendee = {
    attendeeId: string;
    data: {
        sdp: string;
        candidate: TWebRtcCandidate;
    };
};
