import 'dart:convert';

/// Messages from the room signaling socket (`/rooms/:id/socket`), exactly as
/// packages/signaling/server.ts sends them. Anything else is rejected by
/// [RoomMessage.parse] returning null, and the caller ends negotiation.
sealed class RoomMessage {
  const RoomMessage();

  static final _token = RegExp(r'^[A-Za-z0-9_-]{43}$');

  static RoomMessage? parse(Object? raw) {
    if (raw is! String || raw.length > 70000) return null;
    Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      return null;
    }
    if (decoded is! Map<String, dynamic>) return null;
    final m = decoded;
    switch (m['type']) {
      case 'welcome':
        // The server retires the invitation on every accepted connection; keep only the fresh credential.
        final token = m['token'], polite = m['polite'];
        if (token is! String || !_token.hasMatch(token) || polite is! bool) return null;
        return Welcome(polite: polite, token: token);
      case 'ready':
        final sessionId = m['sessionId'];
        return sessionId is String && _token.hasMatch(sessionId) ? Ready(sessionId) : null;
      case 'peer-left':
        return const PeerLeft();
      case 'error':
        return RoomError(m['error'] is String ? m['error'] as String : 'error');
      case 'description':
        final d = m['description'], sessionId = m['sessionId'];
        if (d is! Map || sessionId is! String || d['sdp'] is! String || !const ['offer', 'answer'].contains(d['type'])) return null;
        return Description(type: d['type'] as String, sdp: d['sdp'] as String, sessionId: sessionId);
      case 'candidate':
        final c = m['candidate'], sessionId = m['sessionId'];
        if (sessionId is! String) return null;
        if (c == null) return Candidate(sessionId: sessionId);
        if (c is! Map || c['candidate'] is! String) return null;
        final index = c['sdpMLineIndex'];
        return Candidate(
          sessionId: sessionId,
          candidate: c['candidate'] as String,
          sdpMid: c['sdpMid'] as String?,
          sdpMLineIndex: index is int ? index : null,
          usernameFragment: c['usernameFragment'] as String?,
        );
      default:
        return null;
    }
  }
}

class Welcome extends RoomMessage {
  const Welcome({required this.polite, required this.token});
  final bool polite;
  final String token;
}

class Ready extends RoomMessage {
  const Ready(this.sessionId);
  final String sessionId;
}

class PeerLeft extends RoomMessage {
  const PeerLeft();
}

class RoomError extends RoomMessage {
  const RoomError(this.error);
  final String error;
}

class Description extends RoomMessage {
  const Description({required this.type, required this.sdp, required this.sessionId});
  final String type;
  final String sdp;
  final String sessionId;
}

class Candidate extends RoomMessage {
  const Candidate({required this.sessionId, this.candidate, this.sdpMid, this.sdpMLineIndex, this.usernameFragment});
  final String sessionId;

  /// Null means end of candidates.
  final String? candidate;
  final String? sdpMid;
  final int? sdpMLineIndex;
  final String? usernameFragment;
}

/// Outgoing frames, bound to the current pairing by [sessionId].
String describeFrame(String type, String sdp, String sessionId) =>
    jsonEncode({'type': 'description', 'description': {'type': type, 'sdp': sdp}, 'sessionId': sessionId});

String candidateFrame(Map<String, Object?>? candidate, String sessionId) =>
    jsonEncode({'type': 'candidate', 'candidate': candidate, 'sessionId': sessionId});

/// Verify-v1 data channel packets: `{type: commit, hash}` and `{type: reveal, nonce}`.
Map<String, String>? parseVerifyPacket(Object? raw) {
  if (raw is! String || raw.length > 256) return null;
  try {
    final decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic> || decoded.length != 2) return null;
    if (decoded['type'] == 'commit' && decoded['hash'] is String) return {'type': 'commit', 'value': decoded['hash'] as String};
    if (decoded['type'] == 'reveal' && decoded['nonce'] is String) return {'type': 'reveal', 'value': decoded['nonce'] as String};
  } catch (_) {}
  return null;
}

/// Whether a candidate belongs to the current remote ICE generation.
bool matchesGeneration(String? remoteSdp, String? usernameFragment) =>
    usernameFragment == null || (remoteSdp?.split('\r\n').contains('a=ice-ufrag:$usernameFragment') ?? false);
