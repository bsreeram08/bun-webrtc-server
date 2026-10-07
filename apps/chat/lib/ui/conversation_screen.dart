import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../crypto/chat_crypto.dart';
import '../store/message.dart';
import '../theme/theme_prefs.dart';
import 'conversation_view.dart';
import 'safety_sheet.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';

class ConversationScreen extends ConsumerStatefulWidget {
  const ConversationScreen({super.key, required this.contactId});
  final String contactId;
  @override
  ConsumerState<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends ConsumerState<ConversationScreen> {
  List<ChatMessage>? _messages;
  SafetyNumber? _safety;
  StreamSubscription<String?>? _changes;
  late final AppController _app = ref.read(appProvider.notifier);
  late final String _conversationId = _app.messenger!.conversationWith(widget.contactId);

  @override
  void initState() {
    super.initState();
    _app.openConversation(widget.contactId);
    _changes = _app.store?.changes.listen((id) {
      if (id == null || id == _conversationId) _load();
    });
    _load();
    _loadSafety();
  }

  Future<void> _load() async {
    final list = await _app.store?.list(_conversationId) ?? const <ChatMessage>[];
    if (mounted) setState(() => _messages = list);
  }

  Future<void> _loadSafety() async {
    final state = ref.read(appProvider);
    final contact = _app.contactById(widget.contactId);
    if (contact == null || state.user == null) return;
    final safety = await ref.read(cryptoProvider).safety(state.user!.username, widget.contactId, contact.username);
    if (mounted) setState(() => _safety = safety);
  }

  @override
  void dispose() {
    _changes?.cancel();
    _app.closeConversation();
    super.dispose();
  }

  Future<void> _call(Contact contact, String kind) async {
    try {
      await _app.call(contact, kind);
      if (mounted) unawaited(context.push('/call'));
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    }
  }

  Future<void> _resetSession(Contact contact) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset the secure session?'),
        content: Text('Both devices drop this chat\'s current keys and start fresh ones. Your security code with ${contact.username} stays the same.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Reset')),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await _app.resetSession(contact);
      if (mounted) showSnack(context, 'Secure session reset. New keys are in use for this chat.');
    } on CryptoException catch (e) {
      if (mounted) showSnack(context, e.code == 'identity-blocked' ? "${contact.username}'s security code changed. Review it before resetting." : 'Could not reset: ${e.message}');
    } catch (e) {
      if (mounted) showSnack(context, 'Could not reset: $e');
    }
  }

  Future<void> _burn(Contact contact) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Burn this conversation with ${contact.username}?'),
        content: const Text("Deletes every message on this device and asks their device to delete its copy. Their device does this when the encrypted request arrives."),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Keep')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Burn'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await _app.messenger!.burn(contact);
      if (mounted) showSnack(context, 'Burned on this device.');
    } catch (e) {
      if (mounted) showSnack(context, '$e');
    }
  }

  Future<void> _openSafety(Contact contact) async {
    final state = ref.read(appProvider);
    final crypto = ref.read(cryptoProvider);
    var safety = await crypto.safety(state.user!.username, widget.contactId, contact.username);
    if (safety == null) {
      try {
        await crypto.notePeer(widget.contactId, Identity.fromJson(await ref.read(apiProvider).publishedIdentity(contact.username)));
        safety = await crypto.safety(state.user!.username, widget.contactId, contact.username);
      } on ApiException catch (e) {
        if (mounted) showSnack(context, e.message);
        return;
      }
    }
    if (!mounted || safety == null) return;
    final result = await showSafetySheet(context, contact.username, safety);
    if (result != null) {
      await _app.reviewedKey(widget.contactId, verified: result == SafetyAction.verify);
      if (result == SafetyAction.unverify) await crypto.setVerified(widget.contactId, false);
      await _loadSafety();
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final prefs = ref.watch(themePrefsProvider);
    final contact = _app.contactById(widget.contactId);
    if (contact == null) return const Scaffold(body: Center(child: Text('Not a contact')));
    final tokens = prefs.tokens(_conversationId);
    final resolved = prefs.resolve(_conversationId);
    final blocked = _safety?.blocked ?? false;
    final keyChanged = state.keyChanged.contains(widget.contactId) || (_safety?.changed ?? false);
    ref.listen(appProvider.select((s) => s.keyChanged.contains(widget.contactId)), (_, _) => _loadSafety());
    return Theme(
      data: tokens.material(),
      child: Scaffold(
        appBar: AppBar(
          titleSpacing: 0,
          title: Row(
            children: [
              Avatar(name: contact.username, online: contact.online, size: 40),
              const SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w700)),
                  Text(contact.online ? 'online' : 'offline', style: TextStyle(fontSize: 13, color: tokens.muted)),
                ],
              ),
            ],
          ),
          actions: [
            IconButton(tooltip: 'Voice call', onPressed: contact.online ? () => _call(contact, 'voice') : null, icon: const Icon(Icons.call_outlined)),
            IconButton(tooltip: 'Video call', onPressed: contact.online ? () => _call(contact, 'video') : null, icon: const Icon(Icons.videocam_outlined)),
            PopupMenuButton<String>(
              icon: const Icon(Icons.more_horiz),
              onSelected: (v) => switch (v) {
                'safety' => _openSafety(contact),
                'theme' => showThemePicker(context, ref, chatId: _conversationId),
                'burn' => _burn(contact),
                'reset' => _resetSession(contact),
                _ => null,
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'safety', child: Text('Security code')),
                PopupMenuItem(value: 'theme', child: Text('Chat theme')),
                PopupMenuItem(value: 'reset', child: Text('Reset secure session')),
                PopupMenuItem(value: 'burn', child: Text('Burn conversation')),
              ],
            ),
          ],
        ),
        body: _messages == null
            ? const SizedBox.shrink()
            : ConversationView(
                key: ValueKey(_conversationId),
                tokens: tokens,
                wallpaper: resolved.wallpaper,
                messages: _messages!,
                peerName: contact.username,
                blocked: blocked,
                keyChanged: keyChanged,
                flagged: _app.messenger?.flagged ?? const {},
                onReviewKey: () => _openSafety(contact),
                onSend: (text, after) async {
                  await _app.messenger!.send(contact, text, disappearAfter: after);
                },
              ),
      ),
    );
  }
}
