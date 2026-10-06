import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Server-to-client account events over `/api/events`.
sealed class AccountEvent {
  const AccountEvent();

  /// Unknown or malformed events are ignored (returns null), like the web client.
  static AccountEvent? parse(Object? raw) {
    if (raw is! String) return null;
    Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      return null;
    }
    if (decoded is! Map<String, dynamic>) return null;
    final m = decoded;
    try {
      return switch (m['type']) {
        'hello' => Hello((m['online'] as List).cast<String>()),
        'presence' => Presence(m['id'] as String, m['online'] as bool),
        'contacts' => const ContactsChanged(),
        'keys' => KeysChanged(m['id'] as String),
        'ended' => Ended(m['roomId'] as String),
        'incoming' => Incoming(
          fromId: (m['from'] as Map)['id'] as String,
          fromUsername: (m['from'] as Map)['username'] as String,
          kind: m['kind'] as String,
          roomId: m['roomId'] as String,
          token: m['token'] as String,
        ),
        'envelope' => EnvelopeEvent(
          id: m['id'] as String,
          fromId: (m['from'] as Map)['id'] as String,
          fromUsername: (m['from'] as Map)['username'] as String,
          envelope: m['envelope'] as String,
          createdAt: m['createdAt'] as int,
        ),
        _ => null,
      };
    } catch (_) {
      return null;
    }
  }
}

class Hello extends AccountEvent {
  const Hello(this.online);
  final List<String> online;
}

class Presence extends AccountEvent {
  const Presence(this.id, this.online);
  final String id;
  final bool online;
}

class ContactsChanged extends AccountEvent {
  const ContactsChanged();
}

class KeysChanged extends AccountEvent {
  const KeysChanged(this.id);
  final String id;
}

class Ended extends AccountEvent {
  const Ended(this.roomId);
  final String roomId;
}

class Incoming extends AccountEvent {
  const Incoming({required this.fromId, required this.fromUsername, required this.kind, required this.roomId, required this.token});
  final String fromId;
  final String fromUsername;

  /// chat, voice or video.
  final String kind;
  final String roomId;
  final String token;
}

class EnvelopeEvent extends AccountEvent {
  const EnvelopeEvent({required this.id, required this.fromId, required this.fromUsername, required this.envelope, required this.createdAt});
  final String id;
  final String fromId;
  final String fromUsername;
  final String envelope;
  final int createdAt;
}

/// Signed out by the server (code 4401): stop reconnecting.
class SignedOutEvent extends AccountEvent {
  const SignedOutEvent();
}

/// The always-on account connection, reconnecting with capped backoff.
class EventsClient {
  EventsClient({required this.url, required this.token});

  final Uri url;
  final String token;
  final _events = StreamController<AccountEvent>.broadcast();
  WebSocket? _socket;
  Timer? _retry;
  int _attempt = 0;
  bool _closed = false;

  Stream<AccountEvent> get events => _events.stream;
  bool get connected => _socket?.readyState == WebSocket.open;

  Future<void> connect() async {
    if (_closed || _socket != null) return;
    try {
      final socket = await WebSocket.connect(url.toString(), headers: {'Authorization': 'Bearer $token'}).timeout(const Duration(seconds: 10));
      if (_closed) {
        await socket.close();
        return;
      }
      _socket = socket;
      _attempt = 0;
      socket.listen(
        (data) {
          final event = AccountEvent.parse(data);
          if (event != null) _events.add(event);
        },
        onDone: () {
          _socket = null;
          if (socket.closeCode == 4401) {
            _closed = true;
            _events.add(const SignedOutEvent());
          } else {
            _schedule();
          }
        },
        cancelOnError: true,
      );
    } catch (_) {
      _socket = null;
      _schedule();
    }
  }

  void _schedule() {
    if (_closed) return;
    _retry?.cancel();
    final delay = Duration(milliseconds: (1000 * (1 << _attempt.clamp(0, 4))).clamp(1000, 15000));
    _attempt++;
    _retry = Timer(delay, connect);
  }

  /// The only client messages the server accepts: envelope acks and "ringing".
  void ack(String id) => _send({'type': 'ack', 'id': id});
  void ringing(String roomId) => _send({'type': 'ringing', 'roomId': roomId});

  void _send(Map<String, Object?> message) {
    if (connected) _socket!.add(jsonEncode(message));
  }

  Future<void> close() async {
    _closed = true;
    _retry?.cancel();
    await _socket?.close();
    _socket = null;
    await _events.close();
  }
}
