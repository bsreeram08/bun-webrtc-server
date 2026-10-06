// Screenshot / UI demo: the real app against an in-process fake server, fake
// passkeys and seeded local history. No network, no keys, no media.
//   flutter run -t lib/demo/main_demo.dart --dart-define=DEMO_SCREEN=list
// DEMO_SCREEN: signin | list | chat | chat-fsociety | safety | incoming | call
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sqflite/sqflite.dart';

import '../app/app_controller.dart';
import '../calls/call_controller.dart';
import '../core/api.dart';
import '../core/events.dart';
import '../core/pair_id.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/fake_chat_crypto.dart';
import '../main.dart';
import '../store/message.dart';
import '../store/message_store.dart';
import '../theme/theme_prefs.dart';
import '../ui/call_screen.dart';
import '../ui/safety_sheet.dart';

// Also readable at launch: `SIMCTL_CHILD_DEMO_SCREEN=chat xcrun simctl launch ...`.
final screen = Platform.environment['DEMO_SCREEN'] ?? const String.fromEnvironment('DEMO_SCREEN', defaultValue: 'list');

class _Tokens implements TokenStore {
  _Tokens(this.token);
  String? token;
  @override
  Future<String?> read() async => token;
  @override
  Future<void> write(String? value) async => token = value;
}

class _Passkeys implements PasskeyClient {
  @override
  Future<Map<String, dynamic>> authenticate(Map<String, dynamic> options) async => {'id': 'demo'};
  @override
  Future<Map<String, dynamic>> register(Map<String, dynamic> options) async => {'id': 'demo'};
}

final _identity = {'dh': 'alice-dh', 'sign': 'alice-sign'};

http.Client _server() => MockClient((request) async {
  final path = request.url.path;
  Object body = const {};
  if (path == '/api/me') body = {'user': {'id': 'me-id', 'username': 'sreeram'}};
  if (path == '/api/contacts') {
    body = {
      'contacts': [
        {'id': 'alice-id', 'username': 'alice', 'state': 'mutual', 'online': true},
        {'id': 'bob-id', 'username': 'bob', 'state': 'mutual', 'online': false},
        {'id': 'eve-id', 'username': 'elliot', 'state': 'mutual', 'online': true},
        {'id': 'carol-id', 'username': 'carol', 'state': 'incoming', 'online': false},
        {'id': null, 'username': 'darlene', 'state': 'outgoing', 'online': false},
      ],
    };
  }
  if (path == '/api/keys/count') body = {'oneTimePreKeys': 80, 'signedPreKeyId': 1, 'identity': {'dh': 'fake-dh', 'sign': 'fake-sign'}};
  final who = RegExp(r'^/api/keys/([a-z]+)/identity$').firstMatch(path)?.group(1);
  if (who != null) body = {'userId': '$who-id', 'identity': who == 'alice' ? _identity : {'dh': '$who-dh', 'sign': '$who-sign'}};
  if (path == '/api/version') body = {'api': 1, 'minClient': {'native': 1}};
  return http.Response(jsonEncode(body), 200);
});

Future<void> _seed(MessageStore store) async {
  final now = DateTime.now().millisecondsSinceEpoch;
  final alice = pairId('me-id', 'alice-id'), bob = pairId('me-id', 'bob-id'), elliot = pairId('me-id', 'eve-id');
  var n = 0;
  String id() => '00000000-0000-4000-8000-${(++n).toString().padLeft(12, '0')}';
  Future<void> add(String c, Direction d, String text, int ago, MessageStatus s, {int? expires}) => store.put(
    ChatMessage(id: id(), conversationId: c, direction: d, text: text, createdAt: now - ago, status: s, expiresAt: expires == null ? null : now + expires),
  );
  await add(alice, Direction.incoming, 'did the new build land?', 600000, MessageStatus.delivered);
  await add(alice, Direction.outgoing, 'yep — native app, same encryption as the web one', 540000, MessageStatus.delivered);
  await add(alice, Direction.incoming, 'and the calls?', 480000, MessageStatus.delivered);
  await add(alice, Direction.outgoing, 'CallKit on iPhone, full-screen ring on Android', 420000, MessageStatus.delivered);
  await add(alice, Direction.incoming, 'nice. this one disappears in an hour 👀', 300000, MessageStatus.delivered, expires: 3600000);
  await add(alice, Direction.outgoing, 'compare the security code before we go further', 120000, MessageStatus.sent);
  await add(alice, Direction.outgoing, 'sending while you are offline queues on my phone', 30000, MessageStatus.queued);
  await add(bob, Direction.incoming, 'call me when you are free', 7200000, MessageStatus.delivered);
  await add(bob, Direction.incoming, 'it rings even if the app is closed?', 7100000, MessageStatus.delivered);
  await add(elliot, Direction.incoming, 'hello friend.', 86400000, MessageStatus.delivered);
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final crypto = FakeChatCrypto();
  await crypto.notePeer('alice-id', Identity.fromJson(_identity));
  final container = ProviderContainer(
    overrides: [
      apiProvider.overrideWithValue(Api(baseUrl: 'https://demo.invalid', client: _server(), clientName: 'ios')),
      passkeysProvider.overrideWithValue(_Passkeys()),
      pushEnabledProvider.overrideWithValue(false),
      tokenStoreProvider.overrideWithValue(_Tokens(screen == 'signin' ? null : 'demo-token')),
      cryptoProvider.overrideWithValue(crypto),
      storeOpenerProvider.overrideWithValue((_) async {
        final store = await MessageStore.open(databaseFactory, inMemoryDatabasePath);
        await _seed(store);
        return store;
      }),
    ],
  );
  if (screen == 'call') {
    runApp(UncontrolledProviderScope(container: container, child: const _CallDemo()));
    return;
  }
  runApp(UncontrolledProviderScope(container: container, child: const PrivateChatApp()));
  // Wait for sign-in, then go to the requested screen.
  for (var i = 0; i < 100 && container.read(appProvider).phase != AuthPhase.signedIn && screen != 'signin'; i++) {
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  final app = container.read(appProvider.notifier);
  app.handleEvent(const Presence('alice-id', true));
  // Two encrypted (fake) envelopes from bob arrive over the events connection: unread badge 2.
  final bob = FakeChatCrypto(me: const Identity(dh: 'bob-dh', sign: 'bob-sign'));
  for (final text in ['also: dinner friday?', 'ping me when you see this']) {
    final payload = jsonEncode({'v': 1, 'type': 'message', 'id': '00000000-0000-4000-9000-${text.length.toString().padLeft(12, '0')}', 'text': text, 'createdAt': DateTime.now().millisecondsSinceEpoch, 'expiresAt': null});
    final sealed = await bob.encryptTo('me-id', payload, bundleJson: jsonEncode({'identity': {'dh': 'x', 'sign': 'y'}}));
    app.handleEvent(EnvelopeEvent(id: 'e${text.length}', fromId: 'bob-id', fromUsername: 'bob', envelope: (sealed as Encrypted).envelope, createdAt: 0));
  }
  await Future<void>.delayed(const Duration(milliseconds: 400));
  final router = container.read(routerProvider);
  final chat = pairId('me-id', 'alice-id');
  switch (screen) {
    case 'chat' || 'safety':
      container.read(themePrefsProvider.notifier).setChat(chat, const ThemeChoice(wallpaper: 'dots'));
      router.push('/chat/alice-id');
    case 'chat-fsociety':
      container.read(themePrefsProvider.notifier).setChat(chat, const ThemeChoice(preset: 'fsociety'));
      router.push('/chat/alice-id');
    case 'incoming':
      router.push('/chat/alice-id');
      await Future<void>.delayed(const Duration(milliseconds: 600));
      app.handleEvent(Incoming(fromId: 'alice-id', fromUsername: 'alice', kind: 'video', roomId: 'r' * 43, token: 't' * 43));
  }
  if (screen == 'safety') {
    await Future<void>.delayed(const Duration(milliseconds: 900));
    final context = router.routerDelegate.navigatorKey.currentContext;
    final safety = await crypto.safety('sreeram', 'alice-id', 'alice');
    if (context != null && context.mounted && safety != null) unawaited(showSafetySheet(context, 'alice', safety));
  }
}

class _CallDemo extends ConsumerWidget {
  const _CallDemo();
  @override
  Widget build(BuildContext context, WidgetRef ref) => MaterialApp(
    debugShowCheckedModeBanner: false,
    theme: ref.watch(themePrefsProvider).tokens().material(),
    home: CallView(
      peerName: 'alice',
      status: 'Connected — your call is live.',
      verify: VerifyState.ok,
      verifyCode: '482 193',
      verifyLabel: 'Same code on their screen? No one is listening in.',
      muted: true,
      cameraOff: true,
      speaker: true,
      onMute: () {},
      onCamera: () {},
      onSpeaker: () {},
      onEnd: () {},
    ),
  );
}
