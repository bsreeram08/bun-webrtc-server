import * as crypto from 'crypto';
import * as dgram from 'dgram';
import type { Cluster, Redis } from 'ioredis';
import * as nanoid from 'nanoid';
import * as v from 'valibot';
import { environment } from '../environment/environment';
import {
    EAttributeType,
    EMessageType,
    EStunErrorCodes,
    StunError,
    VStunMessage,
    type TStunAddress,
    type TStunAttribute,
    type TStunChangeRequest,
    type TStunErrorCode,
    type TStunHeader,
    type TStunMessage,
} from '../types';

import { StunRedisClient } from './redis';

export class StunServer {
    private server: dgram.Socket;
    private redis: StunRedisClient;

    constructor(
        private socketType: 'udp4' | 'udp6',
        redisConnection: Redis | Cluster,
    ) {
        this.server = dgram.createSocket(socketType);
        this.redis = new StunRedisClient(redisConnection);

        this.registerHandler();
    }

    private registerHandler() {
        this.server.on('message', this.handleMessage.bind(this));
    }

    private sendResponse(buffer: Buffer, port: number, ip: string) {
        console.log(`[${this.socketType}] [STUN] [SEND] [${ip}:${port}]`);
        this.server.send(Uint8Array.from(buffer), port, ip);
    }

    private async handleMessage(message: Buffer, rinfo: dgram.RemoteInfo) {
        try {
            const stunMessage = this.parseMessage(message);
            console.log(`[${this.socketType}] [STUN] [RECV] ${stunMessage.header.type}`);
            switch (stunMessage.header.type) {
                case EMessageType.BINDING_REQUEST:
                    await this.handleBindingRequest(stunMessage, rinfo);
                    break;
                case EMessageType.SHARED_SECRET_REQUEST:
                    this.handleSharedSecretRequest(stunMessage, rinfo);
                    break;
                default:
                    throw StunError.fromCode(EStunErrorCodes.INVALID_STUN_MESSAGE_TYPE);
            }
        } catch (error) {
            console.error('Error processing STUN message:', error);
            if (StunError.isStunError(error)) {
                this.sendErrorResponse(rinfo, error.errorCodes.join(','), error.message);
            } else {
                console.error('Unexpected error:', error);
            }
        }
    }

    private parseMessage(message: Buffer): TStunMessage {
        if (message.length < 20) {
            throw StunError.fromCode(EStunErrorCodes.INVALID_STUN_MESSAGE_SHORT);
        }
        const header: TStunHeader = {
            type: message.readUInt16BE(0),
            length: message.readUInt16BE(2),
            transactionId: message.subarray(4, 20).toString('hex'),
        };
        if (header.length !== message.length - 20) {
            throw StunError.fromCode(EStunErrorCodes.INVALID_STUN_MESSAGE_LENGTH);
        }
        const attributes: Array<TStunAttribute> = [];
        let offset = 20;

        while (offset < message.length) {
            if (offset + 4 > message.length) {
                throw new Error('Invalid STUN message: incomplete attribute header');
            }
            const type = message.readUInt16BE(offset);
            const length = message.readUInt16BE(offset + 2);
            const value = message.subarray(offset + 4, offset + 4 + length);

            if (offset + 4 + length > message.length) {
                throw new Error('Invalid STUN message: attribute length exceeds message boundary');
            }

            const attributeValue = message.subarray(offset + 4, offset + 4 + length);

            attributes.push(this.parseAttribute(type, length, value));

            offset += 4 + length;
            offset += (4 - (offset % 4)) % 4; // Padding to align to 4-byte boundary
        }

        const stunMessage: TStunMessage = {
            header,
            attributes,
        };

        // Validate the parsed STUN message against the VStunMessage schema
        const validationResult = v.safeParse(VStunMessage, stunMessage);
        if (!validationResult.success) {
            console.log(`[${this.socketType}] [STUN] [VALIDATION] ${JSON.stringify({ validationResult })}`);
            throw StunError.fromCode(EStunErrorCodes.INVALID_STUN_MESSAGE_VALIDATION);
        }

        return stunMessage;
    }

    private parseAttribute(type: number, length: number, value: Buffer): TStunAttribute {
        switch (type) {
            case EAttributeType.ChangeRequest:
                return this.parseChangeRequest(type, length, value);
            // Add cases for other attribute types
            default:
                return {
                    type,
                    length,
                    value: value.toString('hex'),
                };
        }
    }

    private parseChangeRequest(type: number, length: number, value: Buffer): TStunChangeRequest {
        return {
            type,
            length: <4>length,
            value: {
                changeIp: (value.readUInt32BE(0) & 0x04) !== 0,
                changePort: (value.readUInt32BE(0) & 0x02) !== 0,
            },
        };
    }

    private async handleBindingRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        const transactionId = message.header.transactionId;
        let changeRequest: TStunChangeRequest | undefined;
        let username: string | undefined;
        let hasMessageIntegrity = false;

        for (const attribute of message.attributes) {
            switch (attribute.type) {
                case EAttributeType.ChangeRequest:
                    changeRequest = attribute as TStunChangeRequest;
                    break;
                case EAttributeType.Username:
                    username = <string>attribute.value;
                    break;
                case EAttributeType.MessageIntegrity:
                    hasMessageIntegrity = true;
                    break;
            }
        }

        let sourceAddress = rinfo.address;
        let sourcePort = rinfo.port;

        if (changeRequest) {
            if (changeRequest.value.changeIp) {
                sourceAddress = environment.STUN.ALTERNATE_IP ?? sourceAddress;
            }
            if (changeRequest.value.changePort) {
                sourcePort = parseInt(environment.STUN.ALTERNATE_PORT ?? sourcePort.toString());
            }
        }

        const response: TStunMessage = {
            header: {
                type: EMessageType.BINDING_RESPONSE,
                length: 0,
                transactionId: transactionId,
            },
            attributes: [
                {
                    type: EAttributeType.XorMappedAddress,
                    length: 8,
                    value: this.encodeXorMappedAddress(rinfo.address, rinfo.port, transactionId),
                },
                {
                    type: EAttributeType.MappedAddress,
                    length: 8,
                    value: this.encodeAddress(rinfo.address, rinfo.port),
                },
                {
                    type: EAttributeType.SourceAddress,
                    length: 8,
                    value: this.encodeAddress(sourceAddress, sourcePort),
                },
                {
                    type: EAttributeType.ChangedAddress,
                    length: 8,
                    value: this.encodeAddress(environment.STUN.ALTERNATE_IP ?? '0.0.0.0', parseInt(environment.STUN.ALTERNATE_PORT ?? '3479')),
                },
                {
                    type: EAttributeType.Software,
                    length: 21,
                    value: Buffer.from('STUN server by Sreeram').toString('hex'),
                },
            ],
        };

        if (hasMessageIntegrity && username) {
            const sharedSecret = await this.redis.getSharedSecret(username);
            if (sharedSecret) {
                const messageIntegrity = this.calculateMessageIntegrity(response, sharedSecret);
                response.attributes.push({
                    type: EAttributeType.MessageIntegrity,
                    length: 20,
                    value: messageIntegrity,
                });
            }
        }

        const responseBuffer = this.serializeMessage(response);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }

    private async handleSharedSecretRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        try {
            const sharedSecret = nanoid.nanoid(32);
            const username = `user-${nanoid.nanoid(10)}`;

            await this.redis.setSharedSecret(username, sharedSecret);

            const response: TStunMessage = {
                header: {
                    type: EMessageType.SHARED_SECRET_RESPONSE,
                    length: 0,
                    transactionId: message.header.transactionId,
                },
                attributes: [
                    {
                        type: EAttributeType.Username,
                        length: username.length,
                        value: Buffer.from(username).toString('hex'),
                    },
                    {
                        type: EAttributeType.Password,
                        length: sharedSecret.length,
                        value: Buffer.from(sharedSecret).toString('hex'),
                    },
                ],
            };

            const responseBuffer = this.serializeMessage(response);
            this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
        } catch (error) {
            console.error('Error processing Shared Secret Request:', error);
            await this.sendErrorResponse(rinfo, EStunErrorCodes.STUN_SERVER_ERROR, 'Server Error');
        }
    }

    private sendErrorResponse(rinfo: dgram.RemoteInfo, code: string, reason: string) {
        const errorCode = parseInt(code.split('_').pop() ?? '500', 10);
        const errorClass = Math.floor(errorCode / 100);
        const errorNumber = errorCode % 100;
        const errorBuffer = new Uint8Array(Buffer.from([0, 0, errorClass, errorNumber]));
        const reasonBuffer = new Uint8Array(Buffer.from(reason));
        const errorMessage: TStunMessage = {
            header: {
                type: EMessageType.BINDING_ERROR_RESPONSE,
                length: 0,
                transactionId: crypto.randomBytes(16).toString('hex'),
            },
            attributes: [
                {
                    type: EAttributeType.ErrorCode,
                    length: 4 + reason.length,
                    value: Buffer.from(new Uint8Array([...errorBuffer, ...reasonBuffer])).toString('hex'),
                },
            ],
        };

        const responseBuffer = this.serializeMessage(errorMessage);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }

    private serializeMessage(message: TStunMessage): Buffer {
        let attributesLength = 0;
        const attributeBuffers: Buffer[] = [];

        for (const attr of message.attributes) {
            let attrBuff: Buffer;

            if (typeof attr.value === 'string') {
                attrBuff = Buffer.from(attr.value, 'hex');
            } else if (typeof attr.value === 'number') {
                attrBuff = Buffer.alloc(4);
                attrBuff.writeUInt32BE(attr.value);
            } else if (Array.isArray(attr.value)) {
                attrBuff = Buffer.from(attr.value);
            } else if (typeof attr.value === 'object') {
                // Handle specific attribute types
                switch (attr.type) {
                    case EAttributeType.MappedAddress:
                    case EAttributeType.XorMappedAddress:
                        attrBuff = this.encodeAddressAttribute(<TStunAddress>attr.value);
                        break;
                    case EAttributeType.ErrorCode:
                        attrBuff = this.encodeErrorCodeAttribute(<TStunErrorCode['value']>attr.value);
                        break;
                    case EAttributeType.ChangeRequest:
                        attrBuff = this.encodeChangeRequestAttribute(<TStunChangeRequest['value']>attr.value);
                        break;
                    default:
                        throw new Error(`Unsupported attribute type: ${attr.type}`);
                }
            } else {
                throw new Error(`Unsupported attribute value type for attribute: ${attr.type}`);
            }

            const paddedLength = Math.ceil(attrBuff.length / 4) * 4;
            const paddedBuff = Buffer.alloc(paddedLength);
            attrBuff.copy(paddedBuff);

            const attrHeader = Buffer.alloc(4);
            attrHeader.writeUInt16BE(attr.type, 0);
            attrHeader.writeUInt16BE(attrBuff.length, 2);

            attributeBuffers.push(attrHeader, paddedBuff);
            attributesLength += 4 + paddedLength;
        }

        const header = Buffer.alloc(20);
        header.writeUInt16BE(message.header.type, 0);
        header.writeUInt16BE(attributesLength, 2);
        Buffer.from(message.header.transactionId, 'hex').copy(header, 4);

        return Buffer.concat([header, ...attributeBuffers]);
    }

    private encodeAddressAttribute(value: TStunAddress): Buffer {
        const buff = Buffer.alloc(8);
        buff.writeUInt8(0, 0); // Reserved
        buff.writeUInt8(value.family, 1);
        buff.writeUInt16BE(value.port, 2);
        value.address.split('.').forEach((octet, index) => {
            buff.writeUInt8(parseInt(octet, 10), 4 + index);
        });
        return buff;
    }

    private encodeErrorCodeAttribute(value: TStunErrorCode['value']): Buffer {
        const reasonBuff = Buffer.from(value.reason);
        const buff = Buffer.alloc(4 + reasonBuff.length);
        buff.writeUInt16BE(0, 0); // Reserved
        buff.writeUInt8(value.errorClass, 2);
        buff.writeUInt8(value.number, 3);
        reasonBuff.copy(new Uint8Array(buff), 4);
        return buff;
    }

    private encodeChangeRequestAttribute(value: TStunChangeRequest['value']): Buffer {
        const buff = Buffer.alloc(4);
        let flags = 0;
        if (value.changeIp) flags |= 0x04;
        if (value.changePort) flags |= 0x02;
        buff.writeUInt32BE(flags);
        return buff;
    }

    private encodeAddress(address: string, port: number): string {
        const buff = Buffer.alloc(8);
        const parts = address.split('.');

        buff.writeUInt8(0, 0); // Reserved
        buff.writeUInt8(1, 1); // Family (IPv4)
        buff.writeUInt16BE(port, 2);
        for (let i = 0; i < 4; i++) {
            buff.writeUInt8(parseInt(parts[i], 10), 4 + i);
        }

        return buff.toString('hex');
    }

    private decodeAddress(value: string): { address: string; port: number } {
        // Decode the IP address and port from a STUN address attribute value
        const buff = Buffer.from(value, 'hex');

        if (buff.length !== 8) {
            throw new Error('Invalid address attribute value');
        }

        const family = buff.readUInt16BE(0);

        if (family !== 0x0001) {
            throw new Error('Unsupported address family');
        }

        const port = buff.readUInt16BE(2);
        const address = `${buff.readUInt8(4)}.${buff.readUInt8(5)}.${buff.readUInt8(6)}.${buff.readUInt8(7)}`;

        return { address, port };
    }

    private encodeXorMappedAddress(address: string, port: number, transactionId: string): string {
        const buff = Buffer.alloc(8);
        const parts = address.split('.');

        buff.writeUInt8(0, 0); // Reserved
        buff.writeUInt8(1, 1); // Family (IPv4)
        buff.writeUInt16BE(port ^ 0x2112, 2); // XOR the port with the first 16 bits of the magic cookie

        const magicCookie = Buffer.from('2112A442', 'hex');
        for (let i = 0; i < 4; i++) {
            buff.writeUInt8(parseInt(parts[i], 10) ^ magicCookie[i], 4 + i);
        }

        return buff.toString('hex');
    }

    private calculateMessageIntegrity(message: TStunMessage, key: string): string {
        // Create a copy of the message to modify for integrity calculation
        const integrityCopy = JSON.parse(JSON.stringify(message));

        // Remove any existing MESSAGE-INTEGRITY attribute
        integrityCopy.attributes = integrityCopy.attributes.filter((attr: TStunAttribute) => attr.type !== EAttributeType.MessageIntegrity);

        // Set the message length to include the MESSAGE-INTEGRITY attribute
        integrityCopy.header.length = this.calculateMessageLength(integrityCopy) + 24;

        // Serialize the modified message
        const serializedMessage = this.serializeMessage(integrityCopy);

        // Calculate the HMAC-SHA1
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(new Uint8Array(serializedMessage));
        return hmac.digest('hex');
    }

    private calculateMessageLength(message: TStunMessage): number {
        return message.attributes.reduce((length, attr) => length + 4 + attr.length, 0);
    }

    start(port: number) {
        this.server.bind(port, '0.0.0.0', () => {
            console.log(`[${this.socketType}] STUN server listening on port ${port}`);
        });
    }
}
