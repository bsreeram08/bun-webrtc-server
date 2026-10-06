import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/fake_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:uuid/uuid.dart';

/// Messenger against a fake server (MockClient), the Fake crypto and a real store.
void main() {
  sqfliteFfiInit();
  const me = User(id: 'me-id', username: 'me');
  const alice = Contact(id: 'alice-id', username: 'alice', state: ContactState.mutual, online: true);
  const aliceIdentity = Identity(dh: 'alice-dh', sign: 'alice-sign');
  late MessageStore store;
  late Messenger messenger;
  late FakeChatCrypto mine, theirs;
  late List<String> acks, notices;
  late List<Map<String, dynamic>> posted;
  // Payload types of what was posted (FakeChatCrypto envelopes are readable JSON). A session's first send also
  // carries the rotation policy, as on the web, so assertions look at message payloads.
  List<String> postedTypes() => [
    for (final item in posted)
      (jsonDecode(jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(item['envelope'] as String))))['p'] as String) as Map)['type'] as String,
  ];
  late List<http.Request> requests;
  var published = aliceIdentity;
  Map<String, dynamic>? serverIdentity;
  late List<Map<String, dynamic>> uploads;

  setUp(() async {
    published = aliceIdentity;
    serverIdentity = {'dh': 'me-dh', 'sign': 'me-sign'};
    uploads = [];
    acks = [];
    notices = [];
    posted = [];
    requests = [];
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
    mine = FakeChatCrypto(me: const Identity(dh: 'me-dh', sign: 'me-sign'));
    theirs = FakeChatCrypto(me: aliceIdentity);
    final client = MockClient((request) async {
      requests.add(request);
      expect(request.headers['authorization'], 'Bearer t0ken');
      expect(request.headers.containsKey('origin'), isFalse, reason: 'bearer requests must not send an Origin');
      if (request.url.path == '/api/keys/alice/identity') return http.Response(jsonEncode({'userId': 'alice-id', 'identity': published.toJson()}), 200);
      if (request.url.path == '/api/keys/alice') return http.Response(jsonEncode({'userId': 'alice-id', 'identity': published.toJson(), 'signedPreKey': {'id': 1}}), 200);
      if (request.url.path == '/api/keys/count') {
        return http.Response(jsonEncode({'oneTimePreKeys': 50, 'signedPreKeyId': 1, 'identity': serverIdentity}), 200);
      }
      if (request.url.path == '/api/keys' && request.method == 'PUT') {
        uploads.add(jsonDecode(request.body) as Map<String, dynamic>);
        return http.Response('{}', 200);
      }
      if (request.url.path == '/api/messages') {
        posted.add(jsonDecode(request.body) as Map<String, dynamic>);
        return http.Response(jsonEncode({'id': 'm', 'createdAt': 1}), 201);
      }
      return http.Response('{"error":"nope"}', 404);
    });
    final api = Api(baseUrl: 'https://calls.example', client: client, clientName: 'ios')..token = 't0ken';
    messenger = Messenger(
      api: api,
      crypto: mine,
      store: store,
      me: me,
      contactById: (id) => id == alice.id ? alice : null,
      mutualContacts: () => [alice],
      ack: acks.add,
    );
    messenger.notices.listen(notices.add);
    expect(await messenger.checkActive(), isTrue, reason: 'this device holds the published identity');
  });
  tearDown(() async {
    await messenger.dispose();
    await store.close();
  });

  Future<String> envelopeFrom(FakeChatCrypto sender, Map<String, Object?> payload) async =>
      ((await sender.encryptTo('me-id', jsonEncode(payload), bundleJson: jsonEncode({'identity': {'dh': 'me-dh', 'sign': 'me-sign'}}))) as Encrypted).envelope;

  Map<String, Object?> message(String text) => {'v': 1, 'type': 'message', 'id': const Uuid().v4(), 'text': text, 'createdAt': DateTime.now().millisecondsSinceEpoch, 'expiresAt': null};

  Future<void> deliver(String envelope, {String id = 'env1'}) =>
      messenger.receive(EnvelopeEvent(id: id, fromId: 'alice-id', fromUsername: 'alice', envelope: envelope, createdAt: 1));

  test('an incoming message is stored, acknowledged, committed and answered with an encrypted receipt', () async {
    final payload = message('hello');
    await deliver(await envelopeFrom(theirs, payload));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    final stored = await store.list(messenger.conversationWith('alice-id'));
    expect(stored.single.text, 'hello');
    expect(acks, ['env1']);
    expect(mine.committed, hasLength(1));
    expect(messenger.unread['alice-id'], 1);
    final receipt = jsonDecode(jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(posted.single['envelope'] as String))))['p'] as String);
    expect(receipt, {'v': 1, 'type': 'receipt', 'id': payload['id']});
  });

  test('a duplicate envelope is acknowledged without showing the message twice', () async {
    final envelope = await envelopeFrom(theirs, message('once'));
    await deliver(envelope);
    await deliver(envelope, id: 'env2');
    expect(await store.list(messenger.conversationWith('alice-id')), hasLength(1));
    expect(acks, ['env1', 'env2']);
  });

  test('invalid payloads and undecryptable envelopes are acknowledged with a notice, never retried forever', () async {
    await deliver(await envelopeFrom(theirs, {...message('x'), 'extra': true}));
    await deliver('!!not-an-envelope!!', id: 'env2');
    await Future<void>.delayed(Duration.zero);
    expect(acks, ['env1', 'env2']);
    expect(notices, [contains('invalid'), contains('could not be decrypted')]);
  });

  test('an identity that differs from the published one is discarded', () async {
    published = const Identity(dh: 'other', sign: 'other');
    await deliver(await envelopeFrom(theirs, message('spoofed')));
    expect(await store.list(messenger.conversationWith('alice-id')), isEmpty);
    expect(acks, ['env1']);
  });

  test('a changed identity may deliver flagged messages but not burn history or fake receipts; sending pauses', () async {
    await deliver(await envelopeFrom(theirs, message('first')));
    final impostor = FakeChatCrypto(me: const Identity(dh: 'new-dh', sign: 'new-sign'));
    published = const Identity(dh: 'new-dh', sign: 'new-sign');
    final burn = {'v': 1, 'type': 'burn', 'id': const Uuid().v4()};
    await deliver(await envelopeFrom(impostor, burn), id: 'env2');
    final conversation = messenger.conversationWith('alice-id');
    expect((await store.list(conversation)).single.text, 'first', reason: 'burn from an unaccepted identity is ignored');
    await deliver(await envelopeFrom(impostor, message('flagged')), id: 'env3');
    final flaggedMessage = (await store.list(conversation)).last;
    expect(flaggedMessage.text, 'flagged');
    expect(messenger.flagged, contains(flaggedMessage.id));
    posted.clear();
    await messenger.send(alice, 'paused');
    await messenger.flush();
    expect(posted, isEmpty, reason: 'nothing is encrypted to an unaccepted identity');
    expect((await store.list(conversation)).last.status, MessageStatus.queued);
    await mine.acceptChange('alice-id');
    await messenger.flush();
    expect(postedTypes().where((t) => t == 'message'), hasLength(1));
    expect((await store.list(conversation)).last.status, MessageStatus.sent);
  });

  test('a storage failure is retried, then given up with a notice', () async {
    await store.close();
    final envelope = await envelopeFrom(theirs, message('lost?'));
    for (var i = 1; i <= 3; i++) {
      await deliver(envelope, id: 'env');
      expect(acks, i < 3 ? isEmpty : ['env']);
    }
    await Future<void>.delayed(Duration.zero);
    expect(notices.last, contains('could not be saved after several tries'));
    store = await MessageStore.open(databaseFactoryFfi, inMemoryDatabasePath);
  });

  test('burn deletes locally and sends an encrypted burn request', () async {
    await deliver(await envelopeFrom(theirs, message('bye')));
    await Future<void>.delayed(const Duration(milliseconds: 50)); // the receipt is sent in the background
    posted.clear();
    await messenger.burn(alice);
    expect(await store.list(messenger.conversationWith('alice-id')), isEmpty);
    final inner = jsonDecode(jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(posted.single['envelope'] as String))))['p'] as String);
    expect(inner['type'], 'burn');
  });

  group('active device', () {
    test('another device holding the published identity makes this one inactive: no upload, no send, no ack', () async {
      serverIdentity = {'dh': 'other-device-dh', 'sign': 'other-device-sign'};
      expect(await messenger.checkActive(), isFalse);
      expect(messenger.active, isFalse);
      expect(uploads, isEmpty, reason: 'never overwrite the active device keys');
      final envelope = await envelopeFrom(theirs, message('for the other device'));
      await deliver(envelope);
      expect(acks, isEmpty, reason: 'acking would delete the active device copy');
      expect(await store.list(messenger.conversationWith('alice-id')), isEmpty);
      posted.clear();
      await messenger.send(alice, 'waits here');
      await messenger.flush();
      expect(posted, isEmpty);
      expect((await store.list(messenger.conversationWith('alice-id'))).single.status, MessageStatus.queued);
    });

    test('Use this device instead uploads a full key set and resumes sending', () async {
      serverIdentity = {'dh': 'other-device-dh', 'sign': 'other-device-sign'};
      await messenger.checkActive();
      await messenger.send(alice, 'queued while inactive');
      await messenger.takeOver();
      expect(messenger.active, isTrue);
      expect(uploads.single['identity'], {'dh': 'me-dh', 'sign': 'me-sign'});
      expect(uploads.single['oneTimePreKeys'], hasLength(100));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(postedTypes().where((t) => t == 'message'), hasLength(1));
    });

    test('a first device with no published identity becomes active and uploads', () async {
      serverIdentity = null;
      expect(await messenger.checkActive(), isTrue);
      expect(uploads.single['oneTimePreKeys'], hasLength(100));
    });
  });

  group('chat key rotation (account.js parity)', () {
    Map<String, Object?> rotateFrom(String reason) => {'v': 1, 'type': 'rotate', 'id': const Uuid().v4(), 'reason': reason};
    Map<String, Object?> policy(int ms) => {'v': 1, 'type': 'policy', 'id': const Uuid().v4(), 'rotateEveryMs': ms};

    test("a peer's reset commits with rotate (the core keeps only the new session) and answers with our policy", () async {
      await deliver(await envelopeFrom(theirs, message('hi')));
      posted.clear();
      await deliver(await envelopeFrom(theirs, rotateFrom('manual')), id: 'env2');
      expect(mine.rotateCommits, hasLength(1));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(notices, contains('🔄 Secure session reset by alice'));
      expect(postedTypes(), contains('policy'));
      expect(acks, contains('env2'));
    });

    test('an unaccepted new identity can neither reset the session nor set a policy', () async {
      await deliver(await envelopeFrom(theirs, message('first')));
      final impostor = FakeChatCrypto(me: const Identity(dh: 'new-dh', sign: 'new-sign'));
      published = const Identity(dh: 'new-dh', sign: 'new-sign');
      await deliver(await envelopeFrom(impostor, rotateFrom('manual')), id: 'env2');
      await deliver(await envelopeFrom(impostor, policy(86400000)), id: 'env3');
      expect(mine.rotateCommits, isEmpty);
      expect(messenger.rotation.peer('alice-id'), 0);
    });

    test('the shorter non-off interval wins, unknown values are ignored, and policy changes are rate-limited', () async {
      expect(rotationInterval(86400000, 604800000), 86400000);
      expect(rotationInterval(0, 2592000000), 2592000000);
      expect(rotationInterval(12345, 0), 0);
      await deliver(await envelopeFrom(theirs, policy(604800000)));
      expect(messenger.rotation.peer('alice-id'), 604800000);
      await deliver(await envelopeFrom(theirs, policy(12345)), id: 'env2');
      expect(messenger.rotation.peer('alice-id'), 604800000, reason: 'unknown values are never trusted');
      await messenger.setMyRotation(86400000);
      expect(messenger.effectiveRotation('alice-id'), 86400000, reason: 'mine is shorter');
    });

    test('a due session rotates before the next message, and a manual reset sends a rotate payload', () async {
      await messenger.setMyRotation(86400000);
      mine.sessions['alice-id'] = SessionInfo(sid: 'old', startedAt: DateTime.now().millisecondsSinceEpoch - 2 * 86400000);
      await messenger.send(alice, 'after a day');
      await Future<void>.delayed(const Duration(milliseconds: 50)); // send() starts the flush.
      expect(mine.rotations, ['alice-id']);
      expect(postedTypes().indexOf('rotate'), lessThan(postedTypes().indexOf('message')), reason: 'rotate first, then the message on the new session');
      posted.clear();
      await messenger.resetSession(alice);
      expect(postedTypes().first, 'rotate');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(notices, contains('🔄 Secure session reset by you'));
    });

    test('regenerating the identity uploads a full key set under a new identity', () async {
      final before = await mine.identity();
      await messenger.regenerateIdentity();
      expect(uploads.last['identity'], isNot(before.toJson()));
      expect(uploads.last['oneTimePreKeys'], hasLength(100));
    });
  });
}
