import type { ValueOf } from '@libs/types';

export const EStunErrorCodes = {
    INVALID_STUN_MESSAGE_TYPE: 'STUN_00001',
    INVALID_STUN_MESSAGE_SHORT: 'STUN_00002',
    INVALID_STUN_MESSAGE_LENGTH: 'STUN_00003',
    INVALID_STUN_MESSAGE_VALIDATION: 'STUN_00004',
    STUN_SERVER_ERROR: 'STUN_00005',
    BAD_REQUEST: 'STUN_00006',
    UNAUTHORIZED: 'STUN_00007',
    UNKNOWN_ATTRIBUTE: 'STUN_00008',
    STALE_NONCE: 'STUN_00009',
    SERVER_ERROR: 'STUN_00010',
    ALLOCATION_MISMATCH: 'STUN_00011',
} as const;

const stunErrorMessage = {
    STUN_00001: 'Invalid/Unsupported STUN message type',
    STUN_00002: 'Invalid STUN message: message too short',
    STUN_00003: 'Invalid STUN message: invalid message length',
    STUN_00004: 'Invalid STUN message: validation failed',
    STUN_00005: 'STUN: Server Error',
    STUN_00006: 'STUN: Bad Request',
    STUN_00007: 'STUN: Unauthorized',
    STUN_00008: 'STUN: Unknown Attribute',
    STUN_00009: 'STUN: Stale Nonce',
    STUN_00010: 'STUN: Server Error',
    STUN_00011: 'STUN: Allocation Mismatch',
} as const satisfies Record<TStunErrorCodes, string>;

export type TStunErrorCodes = ValueOf<typeof EStunErrorCodes>;
export class StunError extends Error {
    stunError: boolean = true;
    constructor(
        message: string,
        private codes: Array<TStunErrorCodes>,
    ) {
        super(message);
    }

    static fromCode(code: TStunErrorCodes, ...codes: Array<TStunErrorCodes>) {
        codes.push(code);
        return new StunError(stunErrorMessage[code], codes);
    }

    get errorCodes() {
        return this.codes;
    }

    toString() {
        return `STUN_ERROR: ${this.message} [${this.codes.join(',')}]`;
    }

    static isStunError(value: any): value is StunError {
        return typeof value === 'object' && !!value && value['stunError'] === true ? true : false;
    }
}
