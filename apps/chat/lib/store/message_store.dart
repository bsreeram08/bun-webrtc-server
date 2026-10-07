import 'dart:async';

import 'package:sqflite/sqflite.dart';

import 'message.dart';

enum ReceiveResult { stored, duplicate, expired }

/// Device-local message history (SQLite). Port of chat-store.js: the same
/// validation, the 2,000-message device cap and the 500-incoming-per-conversation
/// cap, idempotent receive, and burn by conversation. Expired disappearing
/// messages are deleted whenever the store is read.
class MessageStore {
  MessageStore(this._db, {int Function()? now}) : _now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  final Database _db;
  final int Function() _now;
  final _changes = StreamController<String?>.broadcast();

  /// Emits the conversation id that changed (null: everything).
  Stream<String?> get changes => _changes.stream;

  static Future<MessageStore> open(DatabaseFactory factory, String path, {int Function()? now}) async {
    final db = await factory.openDatabase(
      path,
      options: OpenDatabaseOptions(
        version: 1,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE messages (
              conversation_id TEXT NOT NULL, id TEXT NOT NULL, direction TEXT NOT NULL, text TEXT NOT NULL,
              created_at INTEGER NOT NULL, status TEXT NOT NULL, expires_at INTEGER,
              PRIMARY KEY (conversation_id, id))''');
          await db.execute('CREATE INDEX messages_by_time ON messages (conversation_id, created_at)');
        },
      ),
    );
    return MessageStore(db, now: now);
  }

  Future<void> close() async {
    await _changes.close();
    await _db.close();
  }

  Future<void> _sweep(DatabaseExecutor tx, int now) =>
      tx.delete('messages', where: 'expires_at IS NOT NULL AND expires_at <= ?', whereArgs: [now]);

  Future<ChatMessage?> _get(DatabaseExecutor tx, String conversationId, String id) async {
    final rows = await tx.query('messages', where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, id], limit: 1);
    return rows.isEmpty ? null : ChatMessage.fromRow(rows.single);
  }

  Future<int> _count(DatabaseExecutor tx, [String? where, List<Object?>? args]) async =>
      Sqflite.firstIntValue(await tx.rawQuery('SELECT COUNT(*) FROM messages${where == null ? '' : ' WHERE $where'}', args)) ?? 0;

  /// Stores an outgoing message (or a status update of the same record).
  Future<ChatMessage> put(ChatMessage value) async {
    final message = validate(value);
    final result = await _db.transaction((tx) async {
      final now = _now();
      await _sweep(tx, now);
      if (message.expired(now)) throw const StoreException('This disappearing message has expired.');
      final previous = await _get(tx, message.conversationId, message.id);
      if (previous == null && await _count(tx) >= maxMessages) {
        throw const StoreException('This device holds 2,000 messages. Clear chat history before adding more.', code: 'full');
      }
      if (previous != null && !previous.sameContent(message)) {
        throw const StoreException('A duplicate message has conflicting content or expiration.', code: 'conflict');
      }
      final next = previous?.status == MessageStatus.delivered ? message.withStatus(MessageStatus.delivered) : message;
      await tx.insert('messages', next.toRow(), conflictAlgorithm: ConflictAlgorithm.replace);
      return next;
    });
    _changes.add(message.conversationId);
    return result;
  }

  /// Stores one decrypted incoming payload, idempotent by id. Deterministic
  /// rejections are coded (see [StoreException.code]); nothing is ever evicted.
  Future<ReceiveResult> receive(String conversationId, Map<String, Object?> payload) async {
    final now = _now();
    ChatMessage message;
    try {
      final expiresAt = payload['expiresAt'];
      message = validate(
        ChatMessage(
          id: payload['id']! as String,
          conversationId: conversationId,
          direction: Direction.incoming,
          text: payload['text']! as String,
          createdAt: payload['createdAt']! as int,
          status: MessageStatus.delivered,
          expiresAt: expiresAt as int?,
        ),
      );
    } on StoreException {
      rethrow;
    } catch (_) {
      throw const StoreException('Invalid incoming message.', code: 'invalid');
    }
    if (message.createdAt > now + clockSkewMs) throw const StoreException('Incoming message is dated in the future.', code: 'invalid');
    if (message.expired(now)) return ReceiveResult.expired;
    final result = await _db.transaction((tx) async {
      await _sweep(tx, now);
      final previous = await _get(tx, conversationId, message.id);
      if (previous != null) {
        if (!previous.sameContent(message)) throw const StoreException('A message identifier was reused with different content.', code: 'conflict');
        return ReceiveResult.duplicate;
      }
      if (await _count(tx, "conversation_id = ? AND direction = 'incoming'", [conversationId]) >= maxPerConversation) {
        throw const StoreException('This conversation holds 500 incoming messages.', code: 'conversation-full');
      }
      if (await _count(tx) >= maxMessages) {
        throw const StoreException('This device holds 2,000 messages. Clear chat history to receive more.', code: 'full');
      }
      await tx.insert('messages', message.toRow());
      return ReceiveResult.stored;
    });
    if (result == ReceiveResult.stored) _changes.add(conversationId);
    return result;
  }

  /// A late receipt or send completion never recreates cleared content, never
  /// downgrades `delivered`, and never turns restored history back into a queue.
  Future<bool> setStatus(String conversationId, String id, MessageStatus status) async {
    final changed = await _db.transaction((tx) async {
      final previous = await _get(tx, conversationId, id.toLowerCase());
      if (previous == null) return false;
      if (previous.status == MessageStatus.uncertain && (status == MessageStatus.queued || status == MessageStatus.sent)) return false;
      final next = previous.status == MessageStatus.delivered ? MessageStatus.delivered : status;
      if (next == previous.status) return false;
      await tx.update('messages', {'status': next.name}, where: 'conversation_id = ? AND id = ?', whereArgs: [conversationId, previous.id]);
      return true;
    });
    if (changed) _changes.add(conversationId);
    return changed;
  }

  /// Oldest first.
  Future<List<ChatMessage>> list(String conversationId) async {
    final now = _now();
    await _sweep(_db, now);
    final rows = await _db.query('messages', where: 'conversation_id = ?', whereArgs: [conversationId], orderBy: 'created_at, id');
    return rows.map(ChatMessage.fromRow).toList();
  }

  Future<List<ChatMessage>> queued() async {
    final rows = await _db.query('messages', where: "direction = 'outgoing' AND status = 'queued'", orderBy: 'created_at, id');
    return rows.map(ChatMessage.fromRow).where((m) => !m.expired(_now())).toList();
  }

  /// The newest message of each conversation, for the chat list.
  Future<Map<String, ChatMessage>> latest() async {
    await _sweep(_db, _now());
    final rows = await _db.rawQuery(
      'SELECT m.* FROM messages m JOIN (SELECT conversation_id, MAX(created_at) AS t FROM messages GROUP BY conversation_id) l '
      'ON m.conversation_id = l.conversation_id AND m.created_at = l.t ORDER BY m.id',
    );
    return {for (final row in rows) row['conversation_id']! as String: ChatMessage.fromRow(row)};
  }

  Future<void> removeConversation(String conversationId) async {
    if (!conversationPattern.hasMatch(conversationId)) throw const StoreException('Invalid conversation.');
    await _db.delete('messages', where: 'conversation_id = ?', whereArgs: [conversationId]);
    _changes.add(conversationId);
  }

  Future<void> clear() async {
    await _db.delete('messages');
    _changes.add(null);
  }
}
