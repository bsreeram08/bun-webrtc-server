// The app's half of the cross-client proof: the real Rust core (RustChatCrypto over flutter_rust_bridge),
// the real Messenger, store, API client and events socket, against a local server while the real web
// client (Chromium) is the other party. Driven by tests/cross-client/run.ts, which sets the CROSS_* env
// vars and plays the web side; steps are synchronised through files in CROSS_DIR. Skipped otherwise.
import 'dart:async';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/core/api.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';
import 'package:private_chat/messaging/messenger.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/store/message_store.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  final env = Platform.environment;
  final base = env['CROSS_BASE'];
  test('the app and the web client talk end to end through the server', () async {
    final dir = env['CROSS_DIR']!;
    Future<void> signal(String step, [String body = '']) => File('$dir/app-$step').writeAsString(body);
    Future<String> waitFor(String step, {Duration timeout = const Duration(seconds: 60)}) async {
      final file = File('$dir/web-$step');
      final until = DateTime.now().add(timeout);
      while (!file.existsSync()) {
        if (DateTime.now().isAfter(until)) throw TimeoutException('web never reached $step');
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      return file.readAsString();
    }

    Future<void> until(Future<bool> Function() condition, String what, {Duration timeout = const Duration(seconds: 45)}) async {
      final end = DateTime.now().add(timeout);
      while (!await condition()) {
        if (DateTime.now().isAfter(end)) throw TimeoutException('app: $what');
        await Future<void>.delayed(const Duration(milliseconds: 150));
      }
    }

    sqfliteFfiInit();
    final me = User(id: env['CROSS_ME_ID']!, username: env['CROSS_ME_NAME']!);
    final web = Contact(id: env['CROSS_PEER_ID']!, username: env['CROSS_PEER_NAME']!, state: ContactState.mutual, online: true);
    final api = Api(baseUrl: base!, clientName: 'ios')..token = env['CROSS_TOKEN']!;
    final crypto = RustChatCrypto(
      directory: () async => dir,
      storeKeys: MemoryStoreKeys(7),
      externalLibrary: ExternalLibrary.open(env['CROSS_DYLIB']!),
    );
    await crypto.init('keys-app');
    final store = await MessageStore.open(databaseFactoryFfi, '$dir/messages-app.db');
    final events = EventsClient(url: Uri.parse(base.replaceFirst('http', 'ws')).replace(path: '/api/events'), token: api.token!);
    final notices = <String>[];
    late Messenger messenger;
    messenger = Messenger(
      api: api,
      crypto: crypto,
      store: store,
      me: me,
      contactById: (id) => id == web.id ? web : null,
      mutualContacts: () => [web],
      ack: events.ack,
    );
    messenger.notices.listen(notices.add);
    events.events.listen((event) {
      if (event is EnvelopeEvent) messenger.receive(event);
    });
    await events.connect();
    final conversation = messenger.conversationWith(web.id!);
    Future<List<ChatMessage>> messages() => store.list(conversation);
    Future<bool> has(String text) async => (await messages()).any((m) => m.text == text);

    // 1. Keys: this device is the active one for the account.
    expect(await messenger.checkActive(), isTrue);
    await signal('ready');

    // 2. Web → app: the web client opens the session (X3DH from signal.js, decrypted by the Rust core).
    await waitFor('sent-1');
    await until(() => has('hello from web'), 'web message decrypted');

    // 3. App → web on the established session, with an encrypted receipt back (✓✓).
    await messenger.send(web, 'hello from app');
    await until(() async => (await messages()).any((m) => m.text == 'hello from app' && m.status == MessageStatus.delivered), 'receipt from web');
    await signal('sent-2');

    // 4. Safety numbers: the web compares its 60 digits with ours.
    final safety = await crypto.safety(me.username, web.id!, web.username);
    await signal('safety', safety!.number);
    final verdict = await waitFor('safety-checked');
    expect(verdict, 'match');

    // 5. The app resets the secure session; the web keeps only the new one and messaging continues.
    await messenger.resetSession(web);
    await messenger.send(web, 'after app reset');
    await until(() async => (await messages()).any((m) => m.text == 'after app reset' && m.status == MessageStatus.delivered), 'post-reset message delivered');
    await signal('reset-1');

    // 6. The web resets the session; the Rust core accepts the new session and drops the old one.
    await waitFor('reset-2');
    await until(() => has('after web reset'), 'message after the web reset');
    await until(() async => notices.any((n) => n.contains('Secure session reset by ${web.username}')), 'reset notice');
    await messenger.send(web, 'reply on the new keys');
    await until(() async => (await messages()).any((m) => m.text == 'reply on the new keys' && m.status == MessageStatus.delivered), 'reply after web reset delivered');
    await signal('reset-2-ok');

    // 7. Active-device rule: the web opened a second browser for its account (inactive). Our next message
    // must still reach the original web device, never be consumed by the inactive one.
    await waitFor('second-device');
    await messenger.send(web, 'for the active web device');
    await signal('sent-3');

    // 8. Burn from the web deletes this conversation here.
    await waitFor('burned');
    await until(() async => (await messages()).isEmpty, 'conversation burned');
    await signal('done');
    await events.close();
  }, skip: base == null ? 'run through tests/cross-client/run.ts' : false, timeout: const Timeout(Duration(minutes: 5)));
}
