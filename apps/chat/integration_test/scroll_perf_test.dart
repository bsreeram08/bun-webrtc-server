import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:private_chat/store/message.dart';
import 'package:private_chat/theme/tokens.dart';
import 'package:private_chat/ui/conversation_view.dart';

/// Scrolls a conversation of 2,000 messages and records frame build/raster times:
/// flutter drive --profile -d macos --driver=test_driver/perf_driver.dart --target=integration_test/scroll_perf_test.dart
void main() {
  final binding = IntegrationTestWidgetsFlutterBinding.ensureInitialized()
    ..framePolicy = LiveTestWidgetsFlutterBindingFramePolicy.fullyLive;
  testWidgets('2,000-message conversation scrolls smoothly', (tester) async {
    final tokens = ChatTokens.resolve('midnight');
    final start = DateTime(2026).millisecondsSinceEpoch;
    final messages = [
      for (var i = 0; i < 2000; i++)
        ChatMessage(
          id: '00000000-0000-4000-8000-${i.toString().padLeft(12, '0')}',
          conversationId: 'dChfd14K4ur8IscmUwp33zHqWJXMk3nspofSVemJzf0',
          direction: i.isEven ? Direction.outgoing : Direction.incoming,
          text: i % 7 == 0 ? 'A longer message that wraps onto a second line to vary row heights, #$i' : 'Message $i',
          createdAt: start + i * 1000,
          status: MessageStatus.values[i % 3],
        ),
    ];
    await tester.pumpWidget(
      MaterialApp(
        theme: tokens.material(),
        home: Scaffold(body: ConversationView(tokens: tokens, wallpaper: 'dots', messages: messages, peerName: 'alice', onSend: (_, _) async {})),
      ),
    );
    await tester.pump(const Duration(seconds: 1));
    final list = find.byType(ListView);
    await binding.watchPerformance(() async {
      for (var i = 0; i < 6; i++) {
        await tester.fling(list, const Offset(0, 1400), 4000);
        await tester.pump(const Duration(seconds: 2));
      }
      for (var i = 0; i < 3; i++) {
        await tester.fling(list, const Offset(0, -1400), 4000);
        await tester.pump(const Duration(seconds: 2));
      }
    }, reportKey: 'scrolling_summary');
  });
}
