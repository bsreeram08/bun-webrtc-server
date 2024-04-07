import { getRedis, RedisStore } from '../redis.service';
import type { TWebRtcCandidate } from './types';

function user(userId: string) {
    const redis = getRedis();
    const usersKey = rootKeyFramer('users');
    const key = rootKeyFramer('users', userId);
    return {
        connected: async function () {
            const connectedToKey = rootKeyFramer(key, 'connectedTo');
            await redis.sadd(usersKey, userId);
            await instance(RedisStore.instanceId).users().user(userId).add();
            return redis.set(connectedToKey, RedisStore.instanceId);
        },
        disconnected: async function () {
            const connectedToKey = rootKeyFramer(key, 'connectedTo');
            await redis.srem(usersKey, userId);
            await instance(RedisStore.instanceId).users().user(userId).remove();
            return redis.del(connectedToKey, RedisStore.instanceId);
        },
        connectedTo: function () {
            const connectedToKey = rootKeyFramer(key, 'connectedTo');
            return redis.get(connectedToKey);
        },
    };
}

function users() {
    const redis = getRedis();
    const key = rootKeyFramer('users');
    return {
        active: function () {
            return redis.scard(key);
        },
        user,
    };
}

function instance(instanceId: string) {
    const redis = getRedis();
    const instancesKey = rootKeyFramer('connected', 'instances');
    const key = rootKeyFramer('connected', 'instances', instanceId);
    return {
        add: function () {
            return redis.sadd(instancesKey, instanceId);
        },
        remove: function () {
            return redis.srem(instancesKey, instanceId);
        },
        users: function () {
            const usersKey = rootKeyFramer(key, 'users');
            return {
                count: function () {
                    return redis.scard(usersKey);
                },
                fetch: async function (start = 0, count?: number) {
                    return redis.sscan(usersKey, start, 'COUNT', count ?? (await redis.scard(usersKey)));
                },
                user: function (userId: string) {
                    return {
                        add: function () {
                            return redis.sadd(usersKey, userId);
                        },
                        remove: function () {
                            return redis.srem(usersKey, userId);
                        },
                    };
                },
            };
        },
    };
}

function instances() {
    const redis = getRedis();
    const key = rootKeyFramer('connected', 'instances');
    return {
        length: function () {
            return redis.scard(key);
        },
        get: async function (start = 0, count?: number) {
            return redis.sscan(key, start, 'COUNT', count ?? (await redis.scard(key)));
        },
        instance,
    };
}

function call(callId: string) {
    const redis = getRedis();
    const key = rootKeyFramer('calls', callId);
    return {
        attendee: function (attendeeId: string) {
            const attendeesKey = rootKeyFramer('calls', callId, 'attendees');
            return {
                add: function () {
                    return redis.sadd(attendeesKey, attendeeId);
                },
                remove: function () {
                    return redis.srem(attendeesKey, attendeeId);
                },
                size: function () {
                    return redis.scard(attendeesKey);
                },
                sdp: function () {
                    const sdpKey = rootKeyFramer('calls', callId, 'attendees', attendeeId, 'sdp');
                    return {
                        add: function (sdp: string) {
                            return redis.set(sdpKey, sdp);
                        },
                        get: function () {
                            return redis.get(sdpKey);
                        },
                    };
                },
                candidate: function () {
                    const sdpKey = rootKeyFramer('calls', callId, 'attendees', attendeeId, 'candidate');
                    return {
                        add: function (candidate: TWebRtcCandidate) {
                            return redis.set(sdpKey, JSON.stringify(candidate));
                        },
                        get: async function () {
                            const candidate = await redis.get(sdpKey);
                            if (!candidate) return;
                            return JSON.parse(candidate);
                        },
                    };
                },
            };
        },
        participants: async function (start = 0, count?: number) {
            const attendeesKey = rootKeyFramer('calls', callId, 'attendees');
            return redis.sscan(attendeesKey, start, 'COUNT', count ?? (await redis.scard(attendeesKey)));
        },
    };
}

function rootKeyFramer(key: string, ...keys: Array<string>) {
    let rootKey = `srb:webrtc:${key}`;
    if (keys.length != 0) {
        keys.forEach((v) => {
            rootKey = `${rootKey}:${v}`;
        });
    }
    return rootKey;
}

/**
 * Exports the Redis Packed function
 * @returns TClientStore
 */
export function clientStore() {
    return {
        users,
        instances,
        call,
    };
}

export type TClientStore = ReturnType<typeof clientStore>;
