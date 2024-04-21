import * as v from 'valibot';
import { VStunAttributeType } from './enums';

export const VStunHeader = v.object({
    type: v.number(),
    length: v.number(),
    transactionId: v.string(),
});

export const VStunAttribute = v.object({
    type: v.enum_(VStunAttributeType.enum),
    length: v.number(),
    value: v.string(),
});

export const VStunMessage = v.object({
    header: VStunHeader,
    attributes: v.array(VStunAttribute),
});

export const VStunAddress = v.object({
    family: v.number(),
    port: v.number(),
    address: v.string(),
});

export const VStunChangeRequest = v.object({
    changeIp: v.boolean(),
    changePort: v.boolean(),
});

export const VStunErrorCode = v.object({
    code: v.number(),
    reason: v.string(),
});

export type TStunMessage = v.Input<typeof VStunMessage>;
export type TStunAttribute = v.Input<typeof VStunAttribute>;
export type TStunAddress = v.Input<typeof VStunAddress>;
export type TStunHeader = v.Input<typeof VStunHeader>;
