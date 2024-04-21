import * as v from 'valibot';

export enum EMessageType {
    BINDING_REQUEST = 0x0001,
    BINDING_RESPONSE = 0x0101,
    BINDING_ERROR_RESPONSE = 0x0111,
    SHARED_SECRET_REQUEST = 0x0002,
    SHARED_SECRET_RESPONSE = 0x0102,
    SHARED_SECRET_ERROR_RESPONSE = 0x0112,
}

export const VStunMessageType = v.enum_(EMessageType);

export enum EAttributeType {
    MappedAddress = 0x0001,
    ResponseAddress = 0x0002,
    ChangeRequest = 0x0003,
    SourceAddress = 0x0004,
    ChangedAddress = 0x0005,
    Username = 0x0006,
    Password = 0x0007,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000a,
    ReflectedFrom = 0x000b,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028,
}

export const VStunAttributeType = v.enum_(EAttributeType);
