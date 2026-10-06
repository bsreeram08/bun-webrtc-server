import 'dart:async';
import 'dart:convert';

import 'package:uuid/uuid.dart';

import '../core/api.dart';
import '../core/events.dart';
import '../core/pair_id.dart';
import '../crypto/chat_crypto.dart';
import '../store/disposition.dart';
import '../store/message.dart';
import '../store/message_store.dart';

/// End-to-end encrypted contact messaging over the server mailbox. Port of the
/// web client's account.js receive/send path: decrypt, validate, store, then
/// acknowledge and commit the ratchet; encrypted delivery receipts; burn; and a
/// queue that sends oldest first and pauses on a changed security code.
/// Per-account rotation settings on this device (web: localStorage `rotation-*`).
abstract class RotationPrefs {
  int get mine;
  set mine(int value);
  int peer(String contactId);
  void setPeer(String contactId, int value);
  String? told(String contactId);
  void setTold(String contactId, String value);
  void clearTold();
}

class MemoryRotationPrefs implements RotationPrefs {
  @override
  int mine = 0;
  final Map<String, int> peers = {};
  final Map<String, String> _told = {};
  @override
  int peer(String contactId) => peers[contactId] ?? 0;
  @override
  void setPeer(String contactId, int value) => peers[contactId] = value;
  @override
  String? told(String contactId) => _told[contactId];
  @override
  void setTold(String contactId, String value) => _told[contactId] = value;
  @override
  void clearTold() => _told.clear();
}

class Messenger {
  Messenger({
    required this.api,
    required this.crypto,
    required this.store,
    required this.me,
    required this.contactById,
    required this.mutualContacts,
    required this.ack,
    this.viewing,
    RotationPrefs? rotation,
  }) : rotation = rotation ?? MemoryRotationPrefs();

  /// Chat key rotation settings (account.js `rotation-*`).
  final RotationPrefs rotation;

  final Api api;
  final ChatCrypto crypto;
  final MessageStore store;
  final User me;
  final Contact? Function(String id) contactById;
  final List<Contact> Function() mutualContacts;
  final void Function(String envelopeId) ack;

  /// The contact id currently on screen, if any (no unread count for it).
  final String? Function()? viewing;

  final _notices = StreamController<String>.broadcast();
  final _unread = StreamController<Map<String, int>>.broadcast();
  final _identity = StreamController<String>.broadcast();
  final Map<String, int> unread = {};
  final Map<String, int> _attempts = {};
  final Set<String> flagged = {};
  Future<void> _inbound = Future.value();
  bool _flushing = false, _flushAgain = false, _disposed = false;
  Timer? _retryTimer;

  Stream<String> get notices => _notices.stream;
  Stream<Map<String, int>> get unreadChanges => _unread.stream;

  /// A contact's security code changed (contact id).
  Stream<String> get identityChanges => _identity.stream;

  String conversationWith(String contactId) => pairId(me.id, contactId);

  // ---------- Keys and the active device ----------
  /// Whether this device holds the account's published identity. Only the active device
  /// uploads keys, sends envelopes, and processes or acknowledges incoming envelopes:
  /// they belong to the active device, and acknowledging them here would delete them.
  bool active = false;
  final _activeChanges = StreamController<bool>.broadcast();
  Stream<bool> get activeChanges => _activeChanges.stream;

  void _setActive(bool value) {
    if (active == value) return;
    active = value;
    _activeChanges.add(value);
  }

  /// Compares the server's published identity with ours before uploading anything.
  /// Re-run on sign-in, on reconnect and on a `keys` event for our own id.
  Future<bool> checkActive() async {
    final count = await api.keyCount();
    final mine = await crypto.identity();
    final published = count.identity == null ? null : Identity.fromJson(count.identity!);
    if (published != null && published != mine) {
      _setActive(false);
      return false;
    }
    final upload = await crypto.preparePrekeys(DateTime.now(), oneTimeOnServer: published == null ? 0 : count.oneTimePreKeys);
    final spkId = upload.signedPreKey['id'];
    if (published == null || upload.oneTimePreKeys != null || upload.rotated || count.signedPreKeyId != spkId) await api.uploadKeys(upload.toJson());
    _setActive(true);
    unawaited(flush());
    return true;
  }

  /// Only on the user's tap: publish this device's identity, signed prekey and 100 fresh
  /// one-time prekeys. This device becomes active; contacts see a security-code change.
  Future<void> takeOver() async {
    final upload = await crypto.preparePrekeys(DateTime.now(), oneTimeOnServer: 0);
    await api.uploadKeys(upload.toJson());
    _setActive(true);
    unawaited(flush());
  }

  // ---------- Receiving ----------
  /// Envelopes are processed strictly in order, one at a time.
  Future<void> receive(EnvelopeEvent event) => _inbound = _inbound.then((_) => _receive(event)).catchError((_) {});

  Future<void> _receive(EnvelopeEvent event) async {
    // Inactive: neither process nor acknowledge; the active device will.
    if (!active) return;
    final conversationId = conversationWith(event.fromId);
    String? failureCode;
    var failed = false;
    String? receipt;
    var burned = false, rotated = false;
    try {
      Identity? published;
      final decrypted = await crypto.decryptFrom(event.fromId, event.envelope);
      if (decrypted.identity != null) {
        // Defence in depth only: the pinned identity inside the crypto core is the trust boundary.
        try {
          published = Identity.fromJson(await api.publishedIdentity(event.fromUsername));
        } on ApiException catch (error) {
          throw CryptoException(error.message, code: error.status == 403 ? 'mismatch' : 'storage');
        }
        if (published != decrypted.identity) throw const CryptoException('Identity mismatch', code: 'mismatch');
      }
      final payload = _checkPayload(decrypted.plaintextJson);
      final safety = await crypto.safety(me.username, event.fromId, event.fromUsername);
      final untrusted = decrypted.identityChanged || (safety?.blocked ?? false);
      if (decrypted.identityChanged) _identity.add(event.fromId);
      // An unaccepted new identity may deliver (flagged) messages, but may not burn history or fake receipts.
      if (!untrusted || payload['type'] == 'message') {
        switch (payload['type']) {
          case 'rotate':
            // The core keeps only the peer's new session, in the same write as the ratchet (commit below).
            rotated = true;
          case 'policy':
            _rememberPeerRotation(event.fromId, payload['rotateEveryMs'] as int);
          case 'receipt':
            await store.setStatus(conversationId, payload['id'] as String, MessageStatus.delivered);
          case 'burn':
            await store.removeConversation(conversationId);
            burned = true;
          default:
            if (await store.receive(conversationId, payload) == ReceiveResult.stored) {
              if (untrusted) flagged.add((payload['id'] as String).toLowerCase());
              if (viewing?.call() != event.fromId) unread[event.fromId] = (unread[event.fromId] ?? 0) + 1;
              receipt = payload['id'] as String;
            }
        }
      }
      await crypto.commit(decrypted.commitId, rotate: rotated);
    } on CryptoException catch (error) {
      failed = true;
      failureCode = error.code;
    } on StoreException catch (error) {
      failed = true;
      failureCode = error.code ?? 'storage';
    } catch (_) {
      failed = true;
    }
    final tries = (_attempts[event.id] ?? 0) + 1;
    final outcome = inboundDisposition(hasError: failed, code: failureCode, attempts: tries);
    if (!outcome.ack) {
      _attempts[event.id] = tries;
      _notices.add('Could not save an incoming message yet. Retrying…');
      return;
    }
    _attempts.remove(event.id);
    ack(event.id);
    final notice = noticeText(outcome.notice, event.fromUsername);
    if (notice != null) _notices.add(notice);
    if (rotated && !failed) {
      _notices.add('🔄 Secure session reset by ${event.fromUsername}');
      final contact = contactById(event.fromId);
      // Our policy rides on the new session, which also lets the peer drop its old chains.
      if (contact != null) unawaited(_tellPolicy(contact).catchError((_) {}));
    }
    if (burned) {
      unread.remove(event.fromId);
      _notices.add('${event.fromUsername} burned your conversation. It was deleted on this device.');
    }
    _unread.add(Map.of(unread));
    final contact = contactById(event.fromId);
    if (receipt != null && contact != null) {
      unawaited(_sendControl(contact, {'v': 1, 'type': 'receipt', 'id': receipt}).catchError((_) {}));
    }
  }

  /// Shape only; content is validated by [MessageStore.receive].
  Map<String, Object?> _checkPayload(String json) {
    Object? decoded;
    try {
      decoded = jsonDecode(json);
    } catch (_) {
      throw const CryptoException('Invalid message', code: 'invalid');
    }
    if (decoded is! Map<String, dynamic> || decoded['v'] != 1 || decoded['id'] is! String || !uuidPattern.hasMatch(decoded['id'] as String)) {
      throw const CryptoException('Invalid message', code: 'invalid');
    }
    final type = decoded['type'], size = decoded.length;
    final ok = ((type == 'receipt' || type == 'burn') && size == 3) ||
        (type == 'message' && size == 6) ||
        (type == 'rotate' && size == 4 && (decoded['reason'] == 'manual' || decoded['reason'] == 'scheduled')) ||
        (type == 'policy' && size == 4 && decoded['rotateEveryMs'] is int && (decoded['rotateEveryMs'] as int) >= 0);
    if (!ok) throw const CryptoException('Invalid message', code: 'invalid');
    return decoded;
  }

  void markRead(String contactId) {
    if (unread.remove(contactId) != null) _unread.add(Map.of(unread));
  }

  // ---------- Sending ----------
  /// Stores a new outgoing message as queued and starts delivery.
  Future<ChatMessage> send(Contact contact, String text, {Duration? disappearAfter}) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final message = await store.put(
      ChatMessage(
        id: const Uuid().v4(),
        conversationId: conversationWith(contact.id!),
        direction: Direction.outgoing,
        text: text,
        createdAt: now,
        status: MessageStatus.queued,
        expiresAt: disappearAfter == null ? null : now + disappearAfter.inMilliseconds,
      ),
    );
    unawaited(flush());
    return message;
  }

  Future<void> _sendControl(Contact contact, Map<String, Object?> payload) async {
    final json = jsonEncode(payload);
    var result = await crypto.encryptTo(contact.id!, json);
    if (result is NeedsBundle) result = await crypto.encryptTo(contact.id!, json, bundleJson: await api.bundleJson(contact.username));
    switch (result) {
      case Encrypted(:final envelope):
        await api.postEnvelope(contact.username, envelope);
      case IdentityBlocked():
        throw const CryptoException('Security code changed. Review it before sending.', code: 'identity-blocked');
      case NeedsBundle():
        throw const CryptoException('Could not start an encrypted session.');
    }
  }

  /// Sends every queued message, oldest first, keeping each contact's order.
  Future<void> flush() async {
    if (!active || _disposed) return; // Messages stay queued here until this device is made active.
    if (_flushing) {
      _flushAgain = true;
      return;
    }
    _flushing = true;
    _flushAgain = false;
    _retryTimer?.cancel();
    var retryLater = false;
    try {
      final queued = await store.queued();
      for (final contact in mutualContacts()) {
        final conversationId = conversationWith(contact.id!);
        var prepared = false;
        for (final record in queued.where((m) => m.conversationId == conversationId)) {
          try {
            if (!prepared) {
              await _rotateIfDue(contact);
              await _tellPolicy(contact);
              prepared = true;
            }
            await _sendControl(contact, {
              'v': 1,
              'type': 'message',
              'id': record.id,
              'text': record.text,
              'createdAt': record.createdAt,
              'expiresAt': record.expiresAt,
            });
            await store.setStatus(conversationId, record.id, MessageStatus.sent);
          } catch (error) {
            if (error is CryptoException && error.code == 'identity-blocked') {
              _identity.add(contact.id!);
            } else {
              retryLater = true;
            }
            break; // Keep this contact's order; try the next contact.
          }
        }
      }
    } catch (_) {
      retryLater = true; // Storage unavailable: try again later, never lose the queue.
    } finally {
      _flushing = false;
      if (_disposed) {
        // Signed out: nothing more to send from this session.
      } else if (_flushAgain) {
        unawaited(flush());
      } else if (retryLater) {
        _retryTimer = Timer(const Duration(seconds: 15), flush);
      }
    }
  }

  /// Deletes the conversation here and asks the contact's device to do the same.
  Future<void> burn(Contact contact) async {
    if (!active) throw const CryptoException('Encrypted messaging for this account is active on another device or browser.');
    await _sendControl(contact, {'v': 1, 'type': 'burn', 'id': const Uuid().v4()});
    await store.removeConversation(conversationWith(contact.id!));
    unread.remove(contact.id);
    _unread.add(Map.of(unread));
  }

  // ---------- Chat key rotation ----------
  // Sessions (ratchets) rotate; identities do not rotate on a timer — that would make security-code
  // changes routine and teach people to ignore them. Each side picks an interval; a chat uses the shorter.
  final Map<String, List<int>> _policyChanges = {};

  /// A contact's interval: only known choices, and at most ten changes a minute from any contact.
  void _rememberPeerRotation(String contactId, int value) {
    if (!rotationChoices.contains(value) || rotation.peer(contactId) == value) return;
    final now = DateTime.now().millisecondsSinceEpoch;
    final changes = (_policyChanges[contactId] ?? []).where((t) => now - t < 60000).toList();
    if (changes.length >= 10) return;
    _policyChanges[contactId] = [...changes, now];
    rotation.setPeer(contactId, value);
  }

  int effectiveRotation(String contactId) => rotationInterval(rotation.mine, rotation.peer(contactId));

  /// Starts fresh session keys with a new handshake; the security code is untouched.
  Future<void> resetSession(Contact contact, {String reason = 'manual'}) async {
    if (!active) throw const CryptoException('Encrypted messaging for this account is active on another device or browser.');
    await crypto.rotate(contact.id!);
    await _sendControl(contact, {'v': 1, 'type': 'rotate', 'id': const Uuid().v4(), 'reason': reason});
    _notices.add(reason == 'manual' ? '🔄 Secure session reset by you' : '🔄 Keys rotated on schedule');
    await _tellPolicy(contact);
  }

  Future<void> _rotateIfDue(Contact contact) async {
    final interval = effectiveRotation(contact.id!);
    if (interval == 0) return;
    final info = await crypto.sessionInfo(contact.id!);
    if (info != null && DateTime.now().millisecondsSinceEpoch - info.startedAt >= interval) {
      await resetSession(contact, reason: 'scheduled');
    }
  }

  /// Tells a contact our interval once per session, and again whenever it changes.
  Future<void> _tellPolicy(Contact contact, {bool force = false}) async {
    final mine = rotation.mine;
    final info = await crypto.sessionInfo(contact.id!);
    if (!force && info != null && rotation.told(contact.id!) == '$mine|${info.sid}') return;
    await _sendControl(contact, {'v': 1, 'type': 'policy', 'id': const Uuid().v4(), 'rotateEveryMs': mine});
    final after = await crypto.sessionInfo(contact.id!);
    rotation.setTold(contact.id!, '$mine|${after?.sid}');
  }

  /// Settings → Security: this device's interval (0 = off); contacts with a session hear about it.
  Future<void> setMyRotation(int value) async {
    if (!rotationChoices.contains(value)) return;
    rotation.mine = value;
    if (!active) return;
    for (final contact in mutualContacts()) {
      if (await crypto.sessionInfo(contact.id!) != null) unawaited(_tellPolicy(contact, force: true).catchError((_) {}));
    }
  }

  /// Settings → Security: new identity keys for this device (explicit only). Contacts see a code change.
  Future<void> regenerateIdentity() async {
    await crypto.resetIdentity();
    rotation.clearTold();
    await takeOver();
  }

  Future<void> dispose() async {
    _disposed = true;
    _retryTimer?.cancel();
    await _notices.close();
    await _unread.close();
    await _identity.close();
    await _activeChanges.close();
  }
}
