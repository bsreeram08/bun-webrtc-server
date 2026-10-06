import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/theme/tokens.dart';
import 'package:private_chat/ui/conversation_view.dart';
import 'package:private_chat/ui/incoming_call.dart';
import 'package:private_chat/ui/widgets/ticks.dart';

final tokens = ChatTokens.resolve('midnight');
const conversation = 'dChfd14K4ur8IscmUwp33zHqWJXMk3nspofSVemJzf0';

ChatMessage msg(String id, MessageStatus status, {bool outgoing = true}) => ChatMessage(
  id: id,
  conversationId: conversation,
  direction: outgoing ? Direction.outgoing : Direction.incoming,
  text: 'message $id',
  createdAt: 1700000000000,
  status: status,
);

String uuid(int n) => '00000000-0000-4000-8000-${n.toString().padLeft(12, '0')}';

Widget host(Widget child) => MaterialApp(theme: tokens.material(), home: Scaffold(body: child));

void main() {
  group('conversation', () {
    Widget view(List<ChatMessage> messages, {bool blocked = false, Future<void> Function(String, Duration?)? onSend}) => host(
      ConversationView(tokens: tokens, wallpaper: 'dots', messages: messages, peerName: 'alice', blocked: blocked, onSend: onSend ?? (_, _) async {}),
    );

    testWidgets('ticks animate only when a status changes, never for history on open', (tester) async {
      final history = [msg(uuid(1), MessageStatus.delivered), msg(uuid(2), MessageStatus.sent)];
      await tester.pumpWidget(view(history));
      await tester.pumpAndSettle();
      List<TicksState> ticks() => tester.stateList<TicksState>(find.byType(Ticks)).toList();
      expect(ticks().map((t) => t.animations), [0, 0], reason: 'opening a conversation draws history still');
      expect(ticks().every((t) => t.draw.value == 1), isTrue);

      // A receipt arrives for message 2: only its ticks animate, in place (keyed by id).
      final before = tester.state<TicksState>(find.descendant(of: find.byKey(ValueKey(uuid(2))), matching: find.byType(Ticks)));
      await tester.pumpWidget(view([history[0], msg(uuid(2), MessageStatus.delivered)]));
      await tester.pump(const Duration(milliseconds: 50));
      final after = tester.state<TicksState>(find.descendant(of: find.byKey(ValueKey(uuid(2))), matching: find.byType(Ticks)));
      expect(identical(before, after), isTrue, reason: 'the row is updated in place, not rebuilt');
      expect(after.animations, 1);
      expect(after.draw.isAnimating, isTrue);
      final unchanged = tester.state<TicksState>(find.descendant(of: find.byKey(ValueKey(uuid(1))), matching: find.byType(Ticks)));
      expect(unchanged.animations, 0);
      await tester.pumpAndSettle();
    });

    testWidgets('reduced motion: status changes do not animate', (tester) async {
      Widget reduced(MessageStatus s) => MediaQuery(data: const MediaQueryData(disableAnimations: true), child: view([msg(uuid(1), s)]));
      await tester.pumpWidget(reduced(MessageStatus.sent));
      await tester.pumpWidget(reduced(MessageStatus.delivered));
      expect(tester.state<TicksState>(find.byType(Ticks)).animations, 0);
    });

    testWidgets('a changed security code shows the banner and blocks sending until reviewed', (tester) async {
      final sent = <String>[];
      await tester.pumpWidget(view(const [], blocked: true, onSend: (text, _) async => sent.add(text)));
      expect(find.byKey(const Key('key-banner')), findsOneWidget);
      expect(find.textContaining('Sending is paused'), findsOneWidget);
      await tester.enterText(find.byKey(const Key('composer')), 'secret');
      await tester.tap(find.byKey(const Key('send')));
      await tester.testTextInput.receiveAction(TextInputAction.done);
      await tester.pump();
      expect(sent, isEmpty);
      expect(tester.widget<IconButton>(find.byKey(const Key('send'))).onPressed, isNull);

      await tester.pumpWidget(view(const [], onSend: (text, _) async => sent.add(text)));
      expect(find.byKey(const Key('key-banner')), findsNothing);
      await tester.enterText(find.byKey(const Key('composer')), 'hello');
      await tester.tap(find.byKey(const Key('send')));
      await tester.pump();
      expect(sent, ['hello']);
      expect(tester.widget<TextField>(find.byKey(const Key('composer'))).controller!.text, isEmpty, reason: 'cleared at once, focus kept');
      await tester.pumpAndSettle();
    });
  });

  group('incoming call', () {
    testWidgets('a video call offers Decline / Audio only / Video and starts nothing until a tap', (tester) async {
      final events = <String>[];
      await tester.pumpWidget(
        host(IncomingCallCard(caller: 'alice', video: true, onDecline: () => events.add('decline'), onAccept: ({required audioOnly}) => events.add(audioOnly ? 'audio' : 'video'))),
      );
      await tester.pump(const Duration(seconds: 3));
      expect(find.text('Incoming video call'), findsOneWidget);
      expect(find.text('Decline'), findsOneWidget);
      expect(find.text('Audio only'), findsOneWidget);
      expect(find.text('Video'), findsOneWidget);
      expect(events, isEmpty, reason: 'ringing alone never accepts or captures media');
      await tester.tap(find.byKey(const Key('accept-audio')));
      await tester.tap(find.byKey(const Key('accept')));
      await tester.tap(find.byKey(const Key('decline')));
      expect(events, ['audio', 'video', 'decline']);
    });

    testWidgets('a voice call offers Decline / Accept only', (tester) async {
      await tester.pumpWidget(host(IncomingCallCard(caller: 'bob', video: false, onDecline: () {}, onAccept: ({required audioOnly}) {})));
      expect(find.text('Incoming voice call'), findsOneWidget);
      expect(find.text('Accept'), findsOneWidget);
      expect(find.byKey(const Key('accept-audio')), findsNothing);
    });
  });
}
