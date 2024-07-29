import * as v from 'valibot';
import { EAttributeType, VStunMessageType } from './enums';

export const VStunHeader = v.object({
    type: VStunMessageType,
    length: v.number([v.integer(), v.minValue(0), v.maxValue(65535)]),
    transactionId: v.string([v.length(32)]),
});

export const VStunAddress = v.object({
    family: v.union([v.literal(1), v.literal(2)]),
    port: v.number([v.integer(), v.minValue(0), v.maxValue(65535)]),
    address: v.string([v.ip()]),
});

export const VStunChangeRequest = v.object({
    type: v.literal(EAttributeType.ChangeRequest),
    length: v.literal(4),
    value: v.object({
        changeIp: v.boolean(),
        changePort: v.boolean(),
    }),
});

export const VStunXorMappedAddress = v.object({
    type: v.literal(EAttributeType.XorMappedAddress),
    length: v.literal(8),
    value: v.object({
        family: v.union([v.literal(1), v.literal(2)]),
        xorPort: v.number([v.integer(), v.minValue(0), v.maxValue(65535)]),
        xorAddress: v.string([v.ip()]),
    }),
});

const createAddressAttribute = (type: EAttributeType) =>
    v.object({
        type: v.literal(type),
        length: v.literal(8),
        value: v.object({
            family: v.union([v.literal(1), v.literal(2)]),
            port: v.number([v.integer(), v.minValue(0), v.maxValue(65535)]),
            address: v.string([v.ip()]),
        }),
    });

const createStringAttribute = (type: EAttributeType, maxLength: number) =>
    v.object({
        type: v.literal(type),
        length: v.number([v.integer(), v.minValue(0), v.maxValue(maxLength)]),
        value: v.string([v.minLength(1), v.maxLength(maxLength)]),
    });

export const VStunMappedAddress = createAddressAttribute(EAttributeType.MappedAddress);
export const VStunSourceAddress = createAddressAttribute(EAttributeType.SourceAddress);
export const VStunChangedAddress = createAddressAttribute(EAttributeType.ChangedAddress);
export const VStunReflectedFrom = createAddressAttribute(EAttributeType.ReflectedFrom);
export const VStunAlternateServer = createAddressAttribute(EAttributeType.AlternateServer);

export const VStunUsername = createStringAttribute(EAttributeType.Username, 513);
export const VStunPassword = createStringAttribute(EAttributeType.Password, 763);
export const VStunRealm = createStringAttribute(EAttributeType.Realm, 763);
export const VStunNonce = createStringAttribute(EAttributeType.Nonce, 763);
export const VStunSoftware = createStringAttribute(EAttributeType.Software, 763);

export const VStunMessageIntegrity = v.object({
    type: v.literal(EAttributeType.MessageIntegrity),
    length: v.literal(20),
    value: v.string([v.length(40), v.regex(/^[0-9a-fA-F]{40}$/)]),
});

export const VStunErrorCode = v.object({
    type: v.literal(EAttributeType.ErrorCode),
    length: v.number([v.integer(), v.minValue(4)]),
    value: v.object({
        errorClass: v.number([v.integer(), v.minValue(3), v.maxValue(6)]),
        number: v.number([v.integer(), v.minValue(0), v.maxValue(99)]),
        reason: v.string(),
    }),
});

export const VStunUnknownAttributes = v.object({
    type: v.literal(EAttributeType.UnknownAttributes),
    length: v.number([v.integer(), v.multipleOf(2)]),
    value: v.array(v.number([v.integer(), v.minValue(0), v.maxValue(0xffff)])),
});

export const VStunFingerprint = v.object({
    type: v.literal(EAttributeType.Fingerprint),
    length: v.literal(4),
    value: v.number([v.integer(), v.minValue(0), v.maxValue(0xffffffff)]),
});

export const VStunAttribute = v.union([
    VStunMappedAddress,
    VStunChangeRequest,
    VStunXorMappedAddress,
    VStunSourceAddress,
    VStunChangedAddress,
    VStunUsername,
    VStunPassword,
    VStunMessageIntegrity,
    VStunErrorCode,
    VStunUnknownAttributes,
    VStunReflectedFrom,
    VStunRealm,
    VStunNonce,
    VStunSoftware,
    VStunAlternateServer,
    VStunFingerprint,
]);

export const VStunMessage = v.object({
    header: VStunHeader,
    attributes: v.array(VStunAttribute),
});

export type TStunMessage = v.Output<typeof VStunMessage>;
export type TStunHeader = v.Output<typeof VStunHeader>;
export type TStunAttribute = v.Output<typeof VStunAttribute>;
export type TStunAddress = v.Output<typeof VStunAddress>;
export type TStunMappedAddress = v.Output<typeof VStunMappedAddress>;
export type TStunChangeRequest = v.Output<typeof VStunChangeRequest>;
export type TStunXorMappedAddress = v.Output<typeof VStunXorMappedAddress>;
export type TStunSourceAddress = v.Output<typeof VStunSourceAddress>;
export type TStunChangedAddress = v.Output<typeof VStunChangedAddress>;
export type TStunUsername = v.Output<typeof VStunUsername>;
export type TStunPassword = v.Output<typeof VStunPassword>;
export type TStunMessageIntegrity = v.Output<typeof VStunMessageIntegrity>;
export type TStunErrorCode = v.Output<typeof VStunErrorCode>;
export type TStunUnknownAttributes = v.Output<typeof VStunUnknownAttributes>;
export type TStunReflectedFrom = v.Output<typeof VStunReflectedFrom>;
export type TStunRealm = v.Output<typeof VStunRealm>;
export type TStunNonce = v.Output<typeof VStunNonce>;
export type TStunSoftware = v.Output<typeof VStunSoftware>;
export type TStunAlternateServer = v.Output<typeof VStunAlternateServer>;
export type TStunFingerprint = v.Output<typeof VStunFingerprint>;

export type TStunAttributeValue = TStunAttribute['value'];
