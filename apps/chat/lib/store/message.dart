import 'dart:convert';

/// Delivery state, as in the web client: queued (on this device), sent (on
/// the server), delivered (the peer's device stored it), uncertain (restored).
enum MessageStatus { queued, sent, delivered, uncertain }

enum Direction { incoming, outgoing }

/// One stored message. Only content and delivery metadata are ever stored:
/// never tokens, keys or UI state (same rule as chat-store.js).
class ChatMessage {
  const ChatMessage({
    required this.id,
    required this.conversationId,
    required this.direction,
    required this.text,
    required this.createdAt,
    required this.status,
    this.expiresAt,
  });

  final String id;
  final String conversationId;
  final Direction direction;
  final String text;
  final int createdAt;
  final MessageStatus status;
  final int? expiresAt;

  bool get outgoing => direction == Direction.outgoing;
  bool expired(int now) => expiresAt != null && expiresAt! <= now;

  ChatMessage withStatus(MessageStatus next) => ChatMessage(
    id: id,
    conversationId: conversationId,
    direction: direction,
    text: text,
    createdAt: createdAt,
    status: next,
    expiresAt: expiresAt,
  );

  /// Everything except status: a reused id with different content is a conflict.
  bool sameContent(ChatMessage other) =>
      id == other.id &&
      conversationId == other.conversationId &&
      direction == other.direction &&
      text == other.text &&
      createdAt == other.createdAt &&
      expiresAt == other.expiresAt;

  Map<String, Object?> toRow() => {
    'conversation_id': conversationId,
    'id': id,
    'direction': direction.name,
    'text': text,
    'created_at': createdAt,
    'status': status.name,
    'expires_at': expiresAt,
  };

  static ChatMessage fromRow(Map<String, Object?> row) => validate(
    ChatMessage(
      id: row['id']! as String,
      conversationId: row['conversation_id']! as String,
      direction: Direction.values.byName(row['direction']! as String),
      text: row['text']! as String,
      createdAt: row['created_at']! as int,
      status: MessageStatus.values.byName(row['status']! as String),
      expiresAt: row['expires_at'] as int?,
    ),
  );
}

class StoreException implements Exception {
  const StoreException(this.message, {this.code});
  final String message;

  /// Deterministic rejections carry a code so an envelope is acknowledged and
  /// discarded instead of retried forever: invalid, conflict, conversation-full, full.
  final String? code;
  @override
  String toString() => message;
}

const maxMessages = 2000;
const maxPerConversation = 500;
const clockSkewMs = 300000;
const maxAgeMs = 30 * 86400000;
const maxTextBytes = 4096;
const _maxDate = 8640000000000000;
const _maxSafeInt = 9007199254740991;

final uuidPattern = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', caseSensitive: false);
final conversationPattern = RegExp(r'^[A-Za-z0-9_-]{43}$');

/// The same rules every record in chat-store.js meets. Returns the canonical
/// record (lowercase id) or throws [StoreException] with code `invalid`.
ChatMessage validate(ChatMessage message) {
  final expiresAt = message.expiresAt;
  final ok =
      uuidPattern.hasMatch(message.id) &&
      conversationPattern.hasMatch(message.conversationId) &&
      message.text.isNotEmpty &&
      utf8.encode(message.text).length <= maxTextBytes &&
      message.createdAt >= 0 &&
      message.createdAt <= _maxDate &&
      message.createdAt <= _maxSafeInt &&
      (expiresAt == null ||
          (expiresAt > message.createdAt &&
              expiresAt <= (message.createdAt + maxAgeMs < _maxDate ? message.createdAt + maxAgeMs : _maxDate)));
  if (!ok) throw const StoreException('Invalid chat message.', code: 'invalid');
  return ChatMessage(
    id: message.id.toLowerCase(),
    conversationId: message.conversationId,
    direction: message.direction,
    text: message.text,
    createdAt: message.createdAt,
    status: message.status,
    expiresAt: expiresAt,
  );
}
