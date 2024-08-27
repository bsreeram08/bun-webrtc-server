import * as crypto from 'crypto';
import * as dgram from 'dgram';
import type { Cluster, Redis } from 'ioredis';
import { EAttributeType, EMessageType, EStunErrorCodes, StunError, messageTypeNameMap, type TStunMessage } from '../types';
import { StunServer } from './server'; // Assuming the StunServer is in this file

export class TurnServer extends StunServer {
    private allocations: Map<string, Allocation>;
    private permissions: Map<string, Set<string>>;

    constructor(socketType: 'udp4' | 'udp6', redisConnection: Redis | Cluster) {
        super(socketType, redisConnection);
        this.allocations = new Map();
        this.permissions = new Map();
    }

    protected override registerHandler() {
        super.registerHandler();
        this.server.on('message', this.handleTurnMessage.bind(this));
    }

    private async handleTurnMessage(message: Buffer, rinfo: dgram.RemoteInfo) {
        try {
            const turnMessage = this.parseMessage(message);
            console.log(`[${this.socketType}] [TURN] [RECV] ${messageTypeNameMap[turnMessage.header.type]}`);

            switch (turnMessage.header.type) {
                case EMessageType.ALLOCATE_REQUEST:
                    await this.handleAllocateRequest(turnMessage, rinfo);
                    break;
                case EMessageType.REFRESH_REQUEST:
                    await this.handleRefreshRequest(turnMessage, rinfo);
                    break;
                case EMessageType.CREATE_PERMISSION_REQUEST:
                    await this.handleCreatePermissionRequest(turnMessage, rinfo);
                    break;
                case EMessageType.CHANNEL_BIND_REQUEST:
                    await this.handleChannelBindRequest(turnMessage, rinfo);
                    break;
                case EMessageType.SEND_INDICATION:
                    await this.handleSendIndication(turnMessage, rinfo);
                    break;
                default:
                    await super.handleMessage(message, rinfo);
            }
        } catch (error) {
            console.error('Error processing TURN message:', error);
            if (StunError.isStunError(error)) {
                this.sendErrorResponse(rinfo, error.errorCodes.join(','), error.message);
            } else {
                console.error('Unexpected error:', error);
            }
        }
    }

    private async handleAllocateRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        // Check if the client is authenticated
        const username = this.getAttribute(message, EAttributeType.Username);
        const realm = this.getAttribute(message, EAttributeType.Realm);
        const nonce = this.getAttribute(message, EAttributeType.Nonce);

        if (!username || !realm || !nonce) {
            return this.sendAllocateErrorResponse(rinfo, EStunErrorCodes.UNAUTHORIZED, 'Missing credentials');
        }

        // Verify the message integrity
        const key = await this.getSharedSecret(username);
        if (!this.verifyMessageIntegrity(message, <never>key)) {
            return this.sendAllocateErrorResponse(rinfo, EStunErrorCodes.UNAUTHORIZED, 'Invalid credentials');
        }

        // Create a new allocation
        const relayAddress = this.createRelayAddress();
        const lifetime = this.getAttribute(message, EAttributeType.Lifetime) || 600; // Default to 10 minutes

        const allocation: Allocation = {
            clientAddress: rinfo.address,
            clientPort: rinfo.port,
            relayAddress: relayAddress,
            relayPort: this.getAvailablePort(),
            lifetime: lifetime,
            username: username,
        };

        this.allocations.set(`${rinfo.address}:${rinfo.port}`, allocation);

        // Send success response
        const response: TStunMessage = {
            header: {
                type: EMessageType.ALLOCATE_RESPONSE,
                length: 0,
                transactionId: message.header.transactionId,
            },
            attributes: [
                {
                    type: EAttributeType.XorRelayedAddress,
                    length: 8,
                    value: this.encodeXorMappedAddress(relayAddress, allocation.relayPort, message.header.transactionId),
                },
                {
                    type: EAttributeType.Lifetime,
                    length: 4,
                    value: lifetime,
                },
            ],
        };

        const responseBuffer = this.serializeMessage(response);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }

    private async handleRefreshRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        const username = this.getAttribute(message, EAttributeType.Username);
        const key = await this.getSharedSecret(username);
        if (!this.verifyMessageIntegrity(message, <never>key)) {
            return this.sendErrorResponse(rinfo, EStunErrorCodes.UNAUTHORIZED, 'Invalid credentials');
        }

        const allocationKey = `${rinfo.address}:${rinfo.port}`;
        const allocation = this.allocations.get(allocationKey);

        if (!allocation) {
            return this.sendErrorResponse(rinfo, EStunErrorCodes.ALLOCATION_MISMATCH, 'No allocation found');
        }

        const lifetime = this.getAttribute(message, EAttributeType.Lifetime) || 600;

        if (lifetime === 0) {
            this.allocations.delete(allocationKey);
        } else {
            allocation.lifetime = lifetime;
        }

        const response: TStunMessage = {
            header: {
                type: EMessageType.REFRESH_RESPONSE,
                length: 0,
                transactionId: message.header.transactionId,
            },
            attributes: [
                {
                    type: EAttributeType.Lifetime,
                    length: 4,
                    value: lifetime,
                },
            ],
        };

        const responseBuffer = this.serializeMessage(response);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }

    private async handleCreatePermissionRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        const username = this.getAttribute(message, EAttributeType.Username);
        const key = await this.getSharedSecret(username);
        if (!this.verifyMessageIntegrity(message, <never>key)) {
            return this.sendErrorResponse(rinfo, EStunErrorCodes.UNAUTHORIZED, 'Invalid credentials');
        }

        const peerAddress = this.getAttribute(message, EAttributeType.XorPeerAddress);
        if (!peerAddress) {
            return this.sendErrorResponse(rinfo, EStunErrorCodes.BAD_REQUEST, 'Missing peer address');
        }

        const allocationKey = `${rinfo.address}:${rinfo.port}`;
        if (!this.allocations.has(allocationKey)) {
            return this.sendErrorResponse(rinfo, EStunErrorCodes.ALLOCATION_MISMATCH, 'No allocation found');
        }

        if (!this.permissions.has(allocationKey)) {
            this.permissions.set(allocationKey, new Set());
        }
        this.permissions.get(allocationKey)!.add(peerAddress);

        const response: TStunMessage = {
            header: {
                type: EMessageType.CREATE_PERMISSION_RESPONSE,
                length: 0,
                transactionId: message.header.transactionId,
            },
            attributes: [],
        };

        const responseBuffer = this.serializeMessage(response);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }

    private async handleChannelBindRequest(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        // Implementation for channel bind request
        // This is a placeholder and should be implemented based on your specific requirements
        console.log('Channel Bind Request not yet implemented');
    }

    private async handleSendIndication(message: TStunMessage, rinfo: dgram.RemoteInfo) {
        const data = this.getAttribute(message, EAttributeType.Data);
        const peerAddress = this.getAttribute(message, EAttributeType.XorPeerAddress);

        if (!data || !peerAddress) {
            return; // Silently discard as per RFC 5766
        }

        const allocationKey = `${rinfo.address}:${rinfo.port}`;
        const allocation = this.allocations.get(allocationKey);

        if (!allocation) {
            return; // Silently discard
        }

        const permissions = this.permissions.get(allocationKey);
        if (!permissions || !permissions.has(peerAddress)) {
            return; // No permission to send to this peer
        }

        // Send the data to the peer
        const { address, port } = this.decodeAddress(peerAddress);
        this.server.send(<never>Buffer.from(data, 'hex'), port, address);
    }

    private getAttribute(message: TStunMessage, type: EAttributeType): any {
        const attribute = message.attributes.find((attr) => attr.type === type);
        return attribute ? attribute.value : undefined;
    }

    private createRelayAddress(): string {
        // This should return an available IP address from your relay address pool
        // For simplicity, we're returning a placeholder
        return '192.0.2.1';
    }

    private getAvailablePort(): number {
        // This should return an available port
        // For simplicity, we're returning a placeholder
        return 49152; // First port in the Dynamic and/or Private Port range
    }

    private async getSharedSecret(username: string): Promise<string | null> {
        return this.redis.getSharedSecret(username);
    }

    private verifyMessageIntegrity(message: TStunMessage, key: string): boolean {
        const integrityAttribute = message.attributes.find((attr) => attr.type === EAttributeType.MessageIntegrity);
        if (!integrityAttribute) return false;

        const calculatedIntegrity = this.calculateMessageIntegrity(message, key);
        return calculatedIntegrity === integrityAttribute.value;
    }

    private sendAllocateErrorResponse(rinfo: dgram.RemoteInfo, code: string, reason: string) {
        const errorMessage: TStunMessage = {
            header: {
                type: EMessageType.ALLOCATE_ERROR_RESPONSE,
                length: 0,
                transactionId: crypto.randomBytes(16).toString('hex'),
            },
            attributes: [
                {
                    type: EAttributeType.ErrorCode,
                    length: 4 + reason.length,
                    value: {
                        errorClass: Math.floor(parseInt(code) / 100),
                        number: parseInt(code) % 100,
                        reason: reason,
                    },
                },
            ],
        };

        const responseBuffer = this.serializeMessage(errorMessage);
        this.sendResponse(responseBuffer, rinfo.port, rinfo.address);
    }
}

interface Allocation {
    clientAddress: string;
    clientPort: number;
    relayAddress: string;
    relayPort: number;
    lifetime: number;
    username: string;
}
