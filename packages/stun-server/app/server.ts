import * as crypto from 'crypto';
import * as dgram from 'dgram';
import { Cluster, Redis } from 'ioredis';
import * as nanoid from 'nanoid';
import * as v from 'valibot';
import { environment } from '../environment/environment';
import {
    EAttributeType,
    EMessageType,
    EStunErrorCodes,
    StunError,
    VStunMessage,
    type TStunAttribute,
    type TStunHeader,
    type TStunMessage,
} from '../types';
import { StunRedisClient } from './redis';

export class StunServer {
    private server: dgram.Socket;
    private redis: StunRedisClient;

    constructor(socketType: 'udp4' | 'udp6', redisConnection: Redis | Cluster) {
        this.server = dgram.createSocket(socketType);
        this.redis = new StunRedisClient(redisConnection);

        this.registerHandler();
    }

    private registerHandler() {
        this.server.on('message', this.handleMessage);
    }

    private handleMessage(message: Buffer, rinfo: dgram.RemoteInfo) {
        try {
            const stunMessage = this.parseMessage(message);
            switch (stunMessage.header.type) {
                case EMessageType.BINDING_REQUEST:
                    this.handleBindingRequest(stunMessage, rinfo);
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
            transactionId: message.slice(4, 20).toString('hex'),
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

            const attributeType = message.readUInt16BE(offset);
            const attributeLength = message.readUInt16BE(offset + 2);

            if (offset + 4 + attributeLength > message.length) {
                throw new Error('Invalid STUN message: attribute length exceeds message boundary');
            }

            const attributeValue = message.slice(offset + 4, offset + 4 + attributeLength);

            attributes.push({
                type: attributeType,
                length: attributeLength,
                value: attributeValue.toString('hex'),
            });

            offset += 4 + attributeLength;
            offset += (4 - (offset % 4)) % 4; // Padding to align to 4-byte boundary
        }

        const stunMessage: TStunMessage = {
            header,
            attributes,
        };

        // Validate the parsed STUN message against the VStunMessage schema
        const validationResult = v.safeParse(VStunMessage, stunMessage);
        if (!validationResult.success) {
            throw StunError.fromCode(EStunErrorCodes.INVALID_STUN_MESSAGE_VALIDATION);
        }

        return stunMessage;
    }

    private handleBindingRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        const transactionId = message.header.transactionId;
        const changeRequest = message.attributes.find((attr) => attr.type === EAttributeType.ChangeRequest);
        const responseAddress = message.attributes.find((attr) => attr.type === EAttributeType.ResponseAddress);

        // Determine the source address and port for the response
        let sourceAddress = rinfo.address;
        let sourcePort = rinfo.port;

        if (changeRequest) {
            const changeRequestValue = Buffer.from(changeRequest.value, 'hex').readUInt32BE(0);
            const changeIP = (changeRequestValue & 0x04) !== 0;
            const changePort = (changeRequestValue & 0x02) !== 0;

            if (changeIP) {
                sourceAddress = environment.STUN.ALTERNATE_IP ?? '';
            }

            if (changePort) {
                sourcePort = parseInt(environment.STUN.ALTERNATE_PORT ?? '0');
            }
        }

        // Create the Binding Response message
        const response: TStunMessage = {
            header: {
                type: EMessageType.BINDING_RESPONSE,
                length: 0,
                transactionId: transactionId,
            },
            attributes: [
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
                    value: this.encodeAddress(environment.STUN.ALTERNATE_IP ?? '', parseInt(environment.STUN.ALTERNATE_PORT ?? '0')),
                },
            ],
        };

        // Add the XOR-MAPPED-ADDRESS attribute if required
        if (message.attributes.some((attr) => attr.type === EAttributeType.Software && attr.value.includes('RFC 5389'))) {
            const xorMappedAddress = this.encodeXorMappedAddress(rinfo.address, rinfo.port, transactionId);
            response.attributes.push({
                type: EAttributeType.XorMappedAddress,
                length: xorMappedAddress.length,
                value: xorMappedAddress,
            });
        }

        // Add the MESSAGE-INTEGRITY attribute if message integrity is enabled
        if (message.attributes.some((attr) => attr.type === EAttributeType.Username)) {
            const username = message.attributes.find((attr) => attr.type === EAttributeType.Username)?.value;
            const sharedSecret = this.redis.getSharedSecret(`${username}`);

            if (sharedSecret) {
                const messageIntegrity = this.calculateMessageIntegrity(response, `${sharedSecret}`);
                response.attributes.push({
                    type: EAttributeType.MessageIntegrity,
                    length: messageIntegrity.length,
                    value: messageIntegrity,
                });
            }
        }

        // Serialize the response message
        const responseBuffer = this.serializeMessage(response);

        // Send the Binding Response
        const destinationAddress = responseAddress ? this.decodeAddress(responseAddress.value).address : rinfo.address;
        const destinationPort = responseAddress ? this.decodeAddress(responseAddress.value).port : rinfo.port;
        this.server.send(responseBuffer, destinationPort, destinationAddress);
    }

    private handleSharedSecretRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        try {
            // Generate a new shared secret
            const sharedSecret = nanoid.nanoid(32);

            // Create a unique username for the shared secret
            const username = `user-${nanoid.nanoid(10)}`;

            // Store the shared secret associated with the username
            this.redis.setSharedSecret(username, sharedSecret);

            // Create the Shared Secret Response message
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
                        value: username,
                    },
                    {
                        type: EAttributeType.Password,
                        length: sharedSecret.length,
                        value: sharedSecret,
                    },
                ],
            };

            // Serialize the response message
            const responseBuffer = this.serializeMessage(response);

            // Send the Shared Secret Response
            this.server.send(responseBuffer, rinfo.port, rinfo.address);
        } catch (error) {
            console.error('Error processing Shared Secret Request:', error);
            // Send an error response if needed
            this.sendErrorResponse(rinfo, EStunErrorCodes.STUN_SERVER_ERROR, 'Server Error');
        }
    }

    private sendErrorResponse(rinfo: dgram.RemoteInfo, code: string, reason: string) {
        // Construct an error response message
        const errorMessage: TStunMessage = {
            header: {
                type: EMessageType.BINDING_ERROR_RESPONSE,
                length: 0,
                transactionId: '',
            },
            attributes: [
                {
                    type: EAttributeType.ErrorCode,
                    length: reason.length,
                    value: `${code}: ${reason}`,
                },
            ],
        };

        // Serialize the error response message
        const responseBuffer = this.serializeMessage(errorMessage);

        // Send the error response back to the client
        this.server.send(responseBuffer, rinfo.port, rinfo.address);
    }

    private serializeMessage(message: TStunMessage): Buffer {
        // Calculate the total length of the message
        const totalLength =
            20 +
            message.attributes.reduce((length, attribute) => {
                return length + 4 + attribute.value.length + ((4 - (attribute.value.length % 4)) % 4);
            }, 0);

        // Create a buffer to hold the serialized message
        const buffer = Buffer.alloc(totalLength);

        // Write the message header
        buffer.writeUInt16BE(message.header.type, 0);
        buffer.writeUInt16BE(totalLength - 20, 2);
        Buffer.from(message.header.transactionId, 'hex').copy(buffer, 4);

        // Write the message attributes
        let offset = 20;
        for (const attribute of message.attributes) {
            buffer.writeUInt16BE(attribute.type, offset);
            buffer.writeUInt16BE(attribute.value.length, offset + 2);
            Buffer.from(attribute.value, 'hex').copy(buffer, offset + 4);

            offset += 4 + attribute.value.length;
            offset += (4 - (offset % 4)) % 4; // Padding to align to 4-byte boundary
        }

        return buffer;
    }

    private encodeAddress(address: string, port: number): string {
        // Encode the IP address and port into a STUN address attribute value
        const buff = Buffer.alloc(8);
        const parts = address.split('.');

        buff.writeUInt16BE(0x0001, 0); // Address family (IPv4)
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

        buff.writeUInt16BE(0x0001, 0); // Address family (IPv4)
        buff.writeUInt16BE(port ^ 0x2112, 2); // XOR the port with 0x2112

        const magicCookie = Buffer.from('2112A442', 'hex');
        const transactionIdBuffer = Buffer.from(transactionId, 'hex');

        for (let i = 0; i < 4; i++) {
            buff.writeUInt8(parseInt(parts[i], 10) ^ magicCookie.readUInt8(i), 4 + i);
        }

        return buff.toString('hex');
    }

    private calculateMessageIntegrity(message: TStunMessage, key: string): string {
        const serializedMessage = this.serializeMessage(message);
        const hmac = crypto.createHmac('sha1', key);
        hmac.update(serializedMessage);
        return hmac.digest('hex');
    }

    start(port: number) {
        this.server.bind(port, () => {
            console.log(`STUN server listening on port ${port}`);
        });
    }
}
