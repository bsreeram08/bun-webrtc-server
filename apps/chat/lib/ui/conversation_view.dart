import 'package:flutter/material.dart';

import '../store/message.dart';
import '../theme/tokens.dart';
import 'widgets/common.dart';
import 'widgets/icons.dart';
import 'widgets/ticks.dart';
import 'widgets/wallpaper.dart';

const disappearOptions = <String, Duration?>{'Off': null, '1 hour': Duration(hours: 1), '24 hours': Duration(hours: 24), '7 days': Duration(days: 7)};

/// The conversation body: wallpaper, message list, key-change banner and
/// composer. Pure view (data in, callbacks out) so it is widget-testable.
class ConversationView extends StatefulWidget {
  const ConversationView({
    super.key,
    required this.tokens,
    required this.wallpaper,
    required this.messages,
    required this.onSend,
    required this.peerName,
    this.blocked = false,
    this.keyChanged = false,
    this.flagged = const {},
    this.onReviewKey,
    this.status,
  });

  final ChatTokens tokens;
  final String wallpaper;
  final List<ChatMessage> messages;
  final String peerName;

  /// The contact's security code changed and has not been accepted: sending pauses.
  final bool blocked;
  final bool keyChanged;
  final Set<String> flagged;
  final Future<void> Function(String text, Duration? disappearAfter) onSend;
  final VoidCallback? onReviewKey;
  final String? status;

  @override
  State<ConversationView> createState() => ConversationViewState();
}

class ConversationViewState extends State<ConversationView> {
  final _input = TextEditingController();
  final _focus = FocusNode();
  late final Set<String> _initial = widget.messages.map((m) => m.id).toSet();
  String _disappear = 'Off';
  int _sends = 0;

  @override
  void dispose() {
    _input.dispose();
    _focus.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final text = _input.text;
    if (text.trim().isEmpty || widget.blocked) return;
    // Clear at once and keep the keyboard: typing continues while the message saves.
    _input.clear();
    _focus.requestFocus();
    setState(() => _sends++);
    try {
      await widget.onSend(text, disappearOptions[_disappear]);
    } catch (e) {
      if (_input.text.isEmpty) _input.text = text;
      if (mounted) showSnack(context, e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.tokens;
    final messages = widget.messages;
    return Column(
      children: [
        if (widget.keyChanged || widget.blocked)
          Material(
            color: t.warnBg,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 10, 8, 10),
              child: Row(
                children: [
                  Icon(Icons.warning_amber_rounded, color: t.warn),
                  const SizedBox(width: 10),
                  Expanded(
                    key: const Key('key-banner'),
                    child: Text(
                      widget.blocked
                          ? "${widget.peerName}'s security code changed. Sending is paused until you review it."
                          : "${widget.peerName}'s security code changed. Compare it again to be sure no one is in the middle.",
                      style: TextStyle(color: t.text, fontSize: 14),
                    ),
                  ),
                  TextButton(onPressed: widget.onReviewKey, child: const Text('Review')),
                ],
              ),
            ),
          ),
        Expanded(
          child: Wallpaper(
            kind: widget.wallpaper,
            tokens: t,
            child: messages.isEmpty
                ? Center(child: Text('No messages yet', style: TextStyle(color: t.muted)))
                : ListView.builder(
                    reverse: true,
                    padding: const EdgeInsets.fromLTRB(12, 12, 12, 8),
                    itemCount: messages.length,
                    // Keyed by id: status changes update a row in place, new rows animate in.
                    findChildIndexCallback: (key) {
                      final id = (key as ValueKey<String>).value;
                      final index = messages.lastIndexWhere((m) => m.id == id);
                      return index < 0 ? null : messages.length - 1 - index;
                    },
                    itemBuilder: (context, i) {
                      final m = messages[messages.length - 1 - i];
                      return Bubble(
                        key: ValueKey(m.id),
                        message: m,
                        tokens: t,
                        animateIn: !_initial.contains(m.id),
                        flagged: widget.flagged.contains(m.id),
                      );
                    },
                  ),
          ),
        ),
        if (widget.status != null && widget.status!.isNotEmpty)
          Padding(padding: const EdgeInsets.fromLTRB(16, 4, 16, 0), child: Text(widget.status!, style: TextStyle(color: t.muted, fontSize: 12))),
        Material(
          color: t.bg,
          child: SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(8, 8, 8, 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  PopupMenuButton<String>(
                    tooltip: 'Disappearing messages',
                    initialValue: _disappear,
                    onSelected: (v) => setState(() => _disappear = v),
                    itemBuilder: (_) => [for (final k in disappearOptions.keys) PopupMenuItem(value: k, child: Text(k == 'Off' ? 'Keep messages' : 'Disappear after $k'))],
                    child: CircleAvatar(
                      radius: 22,
                      backgroundColor: _disappear == 'Off' ? t.surface : t.okBg,
                      child: Icon(Icons.timer_outlined, color: _disappear == 'Off' ? t.muted : t.accent),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      key: const Key('composer'),
                      controller: _input,
                      focusNode: _focus,
                      minLines: 1,
                      maxLines: 5,
                      maxLength: 4096,
                      buildCounter: (_, {required currentLength, required isFocused, maxLength}) => null,
                      textCapitalization: TextCapitalization.sentences,
                      style: TextStyle(color: t.text, fontFamily: t.mono ? 'monospace' : null),
                      decoration: InputDecoration(
                        hintText: widget.blocked ? 'Review the new security code to send' : 'Message',
                        isDense: true,
                        contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                      ),
                      onSubmitted: (_) => _send(),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Semantics(
                    button: true,
                    label: 'Send message',
                    child: IconButton.filled(
                      key: const Key('send'),
                      onPressed: widget.blocked ? null : _send,
                      style: IconButton.styleFrom(backgroundColor: t.accent, fixedSize: const Size(46, 46)),
                      icon: SendPlane(sends: _sends, color: t.accentInk),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// One message bubble. New rows slide up and fade in once; history is drawn still.
class Bubble extends StatefulWidget {
  const Bubble({super.key, required this.message, required this.tokens, this.animateIn = false, this.flagged = false});
  final ChatMessage message;
  final ChatTokens tokens;
  final bool animateIn;
  final bool flagged;

  @override
  State<Bubble> createState() => _BubbleState();
}

class _BubbleState extends State<Bubble> with SingleTickerProviderStateMixin {
  late final AnimationController _in = AnimationController(vsync: this, duration: const Duration(milliseconds: 180), value: widget.animateIn ? 0 : 1);

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_in.value == 0) {
      if (MediaQuery.disableAnimationsOf(context)) {
        _in.value = 1;
      } else {
        _in.forward();
      }
    }
  }

  @override
  void dispose() {
    _in.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final m = widget.message, t = widget.tokens;
    final mine = m.outgoing;
    final bubble = Container(
      constraints: BoxConstraints(maxWidth: MediaQuery.sizeOf(context).width * .8),
      margin: const EdgeInsets.symmetric(vertical: 3),
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 6),
      decoration: BoxDecoration(
        color: mine ? t.mine : t.theirs,
        borderRadius: BorderRadius.only(
          topLeft: const Radius.circular(18),
          topRight: const Radius.circular(18),
          bottomLeft: Radius.circular(mine ? 18 : 6),
          bottomRight: Radius.circular(mine ? 6 : 18),
        ),
        boxShadow: t.dark ? null : const [BoxShadow(color: Color(0x1F0F1F2A), blurRadius: 1.5, offset: Offset(0, 1))],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        mainAxisSize: MainAxisSize.min,
        children: [
          Align(
            alignment: Alignment.centerLeft,
            widthFactor: 1,
            child: Text(m.text, style: TextStyle(color: t.text, fontSize: 16, height: 1.35, fontFamily: t.mono ? 'monospace' : null)),
          ),
          const SizedBox(height: 2),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (widget.flagged) ...[Icon(Icons.warning_amber_rounded, size: 13, color: t.warn), const SizedBox(width: 3)],
              if (m.expiresAt != null) ...[Icon(Icons.timer_outlined, size: 12, color: t.meta), const SizedBox(width: 3)],
              Text(clock(m.createdAt), style: TextStyle(color: t.meta, fontSize: 11)),
              if (mine) ...[const SizedBox(width: 4), Ticks(status: m.status, color: t.meta, readColor: t.tickRead)],
            ],
          ),
        ],
      ),
    );
    return FadeTransition(
      opacity: _in,
      child: SlideTransition(
        position: Tween(begin: const Offset(0, .25), end: Offset.zero).animate(CurvedAnimation(parent: _in, curve: Curves.easeOut)),
        child: Align(alignment: mine ? Alignment.centerRight : Alignment.centerLeft, child: bubble),
      ),
    );
  }
}
