import crypto from 'crypto';
import dgram from 'dgram';

export function sendStunBindingRequest(context, events, done) {
    const socketType = context.vars.socketType || 'udp4';
    const client = dgram.createSocket(socketType);
    const transactionId = crypto.randomBytes(16);

    const message = Buffer.alloc(20);
    message.writeUInt16BE(0x0001, 0); // Binding request
    message.writeUInt16BE(0, 2); // Message length (no attributes)
    transactionId.copy(message, 4);

    // Extract target information from the context
    const targetUrl = new URL(context.vars.target);
    const targetHost = socketType === 'udp6' ? '::1' : '127.0.0.1';
    const targetPort = parseInt(targetUrl.port, 10);

    client.send(message, targetPort, targetHost, (err) => {
        if (err) {
            console.error(`Error sending message (${socketType}):`, err);
            events.emit('error', err);
            client.close();
            return done(err);
        }
        console.log(`Sent STUN request to ${targetHost}:${targetPort} using ${socketType}`);
    });

    client.once('message', (msg, rinfo) => {
        console.log(`Received STUN response from ${rinfo.address}:${rinfo.port} using ${socketType}`);
        context.vars.stunResponse = msg;
        client.close();
        done();
    });

    // Set a timeout in case we don't receive a response
    setTimeout(() => {
        if (!context.vars.stunResponse) {
            client.close();
            const err = new Error(`STUN response timeout (${socketType})`);
            console.error(err.message);
            events.emit('error', err);
            done(err);
        }
    }, 5000);
}

export function validateStunResponse(context, events, done) {
    const response = context.vars.stunResponse;

    if (!response) {
        const err = new Error('No STUN response received');
        events.emit('error', err);
        return done(err);
    }

    // Basic validation of STUN response
    const messageType = response.readUInt16BE(0);
    const messageLength = response.readUInt16BE(2);

    if (messageType !== 0x0101) {
        // Binding Success Response
        const err = new Error(`Unexpected STUN message type: ${messageType}`);
        events.emit('error', err);
        return done(err);
    }

    if (messageLength < 8) {
        // At least XOR-MAPPED-ADDRESS should be present
        const err = new Error(`STUN response too short: ${messageLength} bytes`);
        events.emit('error', err);
        return done(err);
    }

    // You can add more detailed validation here

    done();
}
