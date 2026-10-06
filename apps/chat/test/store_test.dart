import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/pair_id.dart';
import 'package:private_chat/store/disposition.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

void main() {
  sqfliteFfiInit();
  late MessageStore store;
  var now = 1_700_000_000_000;
  final a = pairId('me', 'alice'), b = pairId('me', 'bob');

  setUp(() async {
    now = 1_700_000_000_000;
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath, now: () => now);
  });
  tearDown(() => store.close());

  Map<String, Object?> payload({String? id, String text = 'hi', int? createdAt, int? expiresAt}) =>
      {'id': id ?? const Uuid().v4(), 'text': text, 'createdAt': createdAt ?? now, 'expiresAt': expiresAt};

  ChatMessage outgoing(String conversation, {MessageStatus status = MessageStatus.queued}) => ChatMessage(
    id: const Uuid().v4(),
    conversationId: conversation,
    direction: Direction.outgoing,
    text: 'out',
    createdAt: now,
    status: status,
  );

  test('pair ids match the web client byte for byte', () {
    // Computed with packages/signaling/public/account.js pairId('alice-id', 'bob-id').
    expect(pairId('alice-id', 'bob-id'), 'dChfd14K4ur8IscmUwp33zHqWJXMk3nspofSVemJzf0');
    expect(pairId('bob-id', 'alice-id'), pairId('alice-id', 'bob-id'));
  });

  group('validation (same rules as chat-store.js)', () {
    test('rejects malformed ids, empty or oversized text, bad expiry and future dates', () async {
      for (final bad in [
        payload(id: 'not-a-uuid'),
        payload(text: ''),
        payload(text: 'x' * 4097),
        payload(text: 'é' * 2049), // 4098 UTF-8 bytes
        payload(expiresAt: now - 1),
        payload(expiresAt: now + 31 * 86400000),
        payload(createdAt: now + 300001),
        {'id': const Uuid().v4(), 'text': 5, 'createdAt': now, 'expiresAt': null},
      ]) {
        await expectLater(store.receive(a, bad), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'invalid')), reason: '$bad');
      }
      expect(await store.list(a), isEmpty);
    });
    test('accepts the limits exactly and lowercases ids', () async {
      final id = const Uuid().v4().toUpperCase();
      expect(await store.receive(a, payload(id: id, text: 'x' * 4096, createdAt: now + 300000, expiresAt: now + 300000 + 30 * 86400000)), ReceiveResult.stored);
      expect((await store.list(a)).single.id, id.toLowerCase());
    });
  });

  test('receive is idempotent by id and a reused id with other content is a conflict', () async {
    final p = payload();
    expect(await store.receive(a, p), ReceiveResult.stored);
    expect(await store.receive(a, p), ReceiveResult.duplicate);
    await expectLater(store.receive(a, {...p, 'text': 'changed'}), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'conflict')));
    expect(await store.list(a), hasLength(1));
  });

  test('one contact can fill only its own 500-message share; others still arrive', () async {
    for (var i = 0; i < maxPerConversation; i++) {
      await store.receive(a, payload());
    }
    await expectLater(store.receive(a, payload()), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'conversation-full')));
    expect(await store.receive(b, payload()), ReceiveResult.stored);
  });

  test('the device holds at most 2,000 messages and evicts nothing', () async {
    for (var c = 0; c < 4; c++) {
      final conversation = pairId('me', 'c$c');
      for (var i = 0; i < maxPerConversation; i++) {
        await store.receive(conversation, payload());
      }
    }
    await expectLater(store.receive(a, payload()), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'full')));
    await expectLater(store.put(outgoing(a)), throwsA(isA<StoreException>().having((e) => e.code, 'code', 'full')));
  });

  test('status updates never downgrade delivered, never resurrect, never re-queue restored history', () async {
    final m = await store.put(outgoing(a));
    expect(await store.setStatus(a, m.id, MessageStatus.sent), isTrue);
    expect(await store.setStatus(a, m.id, MessageStatus.delivered), isTrue);
    expect(await store.setStatus(a, m.id, MessageStatus.sent), isFalse);
    expect((await store.list(a)).single.status, MessageStatus.delivered);
    final restored = await store.put(outgoing(a, status: MessageStatus.uncertain));
    expect(await store.setStatus(a, restored.id, MessageStatus.queued), isFalse);
    await store.removeConversation(a);
    expect(await store.setStatus(a, m.id, MessageStatus.delivered), isFalse);
    expect(await store.list(a), isEmpty);
  });

  test('disappearing messages are deleted once expired; burn removes only one conversation', () async {
    await store.receive(a, payload(expiresAt: now + 1000));
    await store.receive(b, payload());
    now += 1001;
    expect(await store.list(a), isEmpty);
    expect(await store.receive(a, payload(createdAt: now - 5000, expiresAt: now - 1)), ReceiveResult.expired);
    await store.receive(a, payload());
    await store.removeConversation(a);
    expect(await store.list(a), isEmpty);
    expect(await store.list(b), hasLength(1));
  });

  test('latest() returns the newest message per conversation for the chat list', () async {
    await store.receive(a, payload(text: 'old', createdAt: now - 10));
    await store.receive(a, payload(text: 'new'));
    final latest = await store.latest();
    expect(latest[a]!.text, 'new');
  });

  group('inbound disposition (fails closed, like ChatStore.inboundDisposition)', () {
    test('success and permanent outcomes are acknowledged at once', () {
      expect(inboundDisposition(hasError: false, attempts: 1), const Disposition(ack: true));
      expect(inboundDisposition(hasError: true, code: 'replay', attempts: 1), const Disposition(ack: true));
      for (final (code, notice) in [
        ('full', 'storage-full'),
        ('conversation-full', 'conversation-full'),
        ('invalid', 'invalid'),
        ('conflict', 'invalid'),
        ('mismatch', 'invalid'),
        ('malformed', 'undecryptable'),
        ('auth', 'undecryptable'),
        ('skip-limit', 'undecryptable'),
        ('unknown-session', 'undecryptable'),
        ('unknown-spk', 'undecryptable'),
        ('claim-limit', 'undecryptable'),
      ]) {
        expect(inboundDisposition(hasError: true, code: code, attempts: 1), Disposition(ack: true, notice: notice), reason: code);
      }
    });
    test('storage, uncoded and unknown errors retry, then give up with a notice', () {
      for (final code in ['storage', null, 'something-new']) {
        expect(inboundDisposition(hasError: true, code: code, attempts: 1), const Disposition(ack: false, notice: 'retrying'));
        expect(inboundDisposition(hasError: true, code: code, attempts: 2), const Disposition(ack: false, notice: 'retrying'));
        expect(inboundDisposition(hasError: true, code: code, attempts: 3), const Disposition(ack: true, notice: 'gave-up'));
      }
    });
  });
}
