import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:share_plus/share_plus.dart';

import '../app/app_controller.dart';
import '../core/api.dart';
import '../core/pair_id.dart';
import '../store/message.dart';
import 'theme_picker.dart';
import 'widgets/common.dart';

class ChatListScreen extends ConsumerStatefulWidget {
  const ChatListScreen({super.key});
  @override
  ConsumerState<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends ConsumerState<ChatListScreen> {
  final _add = TextEditingController();
  Map<String, ChatMessage> _latest = {};
  StreamSubscription<String?>? _changes;

  @override
  void initState() {
    super.initState();
    final store = ref.read(appProvider.notifier).store;
    _changes = store?.changes.listen((_) => _refresh());
    _refresh();
  }

  Future<void> _refresh() async {
    final store = ref.read(appProvider.notifier).store;
    if (store == null) return;
    final latest = await store.latest();
    if (mounted) setState(() => _latest = latest);
  }

  @override
  void dispose() {
    _changes?.cancel();
    _add.dispose();
    super.dispose();
  }

  Future<void> _guard(Future<void> Function() task) async {
    try {
      await task();
    } on ApiException catch (e) {
      if (mounted) showSnack(context, e.message);
    }
  }

  Future<void> _invite() async {
    final invite = await ref.read(appProvider.notifier).createInvite();
    if (!mounted) return;
    final until = DateTime.fromMillisecondsSinceEpoch(invite.expiresAt);
    await showModalBottomSheet<void>(
      context: context,
      builder: (context) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Invite someone', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text('Works once, until ${until.day}/${until.month}. Share it privately — whoever has it can create an account.'),
            const SizedBox(height: 16),
            SelectableText(invite.link, style: const TextStyle(fontFamily: 'monospace')),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => Clipboard.setData(ClipboardData(text: invite.link)),
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    onPressed: () => SharePlus.instance.share(ShareParams(text: invite.link)),
                    icon: const Icon(Icons.ios_share),
                    label: const Text('Share'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(appProvider);
    final app = ref.read(appProvider.notifier);
    final me = state.user;
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    ref.listen(appProvider.select((s) => s.notice), (_, notice) {
      if (notice != null) {
        showSnack(context, notice);
        app.dismissNotice();
      }
    });
    return Scaffold(
      appBar: AppBar(
        toolbarHeight: 76,
        titleSpacing: 20,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Chats', style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800)),
            if (me != null) Text('@${me.username}', style: TextStyle(fontSize: 14, color: muted)),
          ],
        ),
        actions: [
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_horiz),
            onSelected: (value) => switch (value) {
              'invite' => _guard(_invite),
              'theme' => showThemePicker(context, ref),
              'signout' => app.signOut(),
              'signout-all' => app.signOut(everywhere: true),
              _ => null,
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'invite', child: Text('Invite someone')),
              PopupMenuItem(value: 'theme', child: Text('Appearance')),
              PopupMenuItem(value: 'signout', child: Text('Sign out')),
              PopupMenuItem(value: 'signout-all', child: Text('Sign out everywhere')),
            ],
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 32),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 12),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _add,
                    autocorrect: false,
                    textInputAction: TextInputAction.done,
                    decoration: const InputDecoration(hintText: 'Add contact by username', isDense: true),
                    onSubmitted: (_) => _guard(() async {
                      await app.addContact(_add.text);
                      _add.clear();
                    }),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.tonal(
                  onPressed: () => _guard(() async {
                    await app.addContact(_add.text);
                    _add.clear();
                  }),
                  child: const Text('Add'),
                ),
              ],
            ),
          ),
          if (state.contacts.isEmpty)
            Padding(
              padding: const EdgeInsets.all(32),
              child: Text('No contacts yet. Add someone by username, or invite them.', textAlign: TextAlign.center, style: TextStyle(color: muted)),
            ),
          for (final contact in state.contacts) _row(context, contact, me, state.unread),
        ],
      ),
    );
  }

  Widget _row(BuildContext context, Contact contact, User? me, Map<String, int> unread) {
    final app = ref.read(appProvider.notifier);
    final muted = Theme.of(context).textTheme.bodySmall?.color;
    final scheme = Theme.of(context).colorScheme;
    if (contact.state != ContactState.mutual || contact.id == null || me == null) {
      return ListTile(
        leading: Avatar(name: contact.username),
        title: Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Text(contact.state == ContactState.incoming ? 'Wants to add you' : 'Request sent', style: TextStyle(color: muted)),
        trailing: Wrap(
          spacing: 8,
          children: [
            if (contact.state == ContactState.incoming) FilledButton(onPressed: () => _guard(() => app.acceptContact(contact)), child: const Text('Accept')),
            OutlinedButton(
              onPressed: () => _guard(() => app.removeContact(contact)),
              child: Text(contact.state == ContactState.incoming ? 'Decline' : 'Cancel'),
            ),
          ],
        ),
      );
    }
    final recent = _latest[pairId(me.id, contact.id!)];
    final count = unread[contact.id] ?? 0;
    return ListTile(
      key: ValueKey(contact.id),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: Avatar(name: contact.username, online: contact.online),
      title: Text(contact.username, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 17)),
      subtitle: Text(
        recent != null ? '${recent.outgoing ? 'You: ' : ''}${recent.text}' : (contact.online ? 'Online' : 'Tap to chat'),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(color: count > 0 ? null : muted, fontWeight: count > 0 ? FontWeight.w600 : null),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (recent != null) Text(clock(recent.createdAt), style: TextStyle(fontSize: 12, color: count > 0 ? scheme.primary : muted)),
          if (count > 0) ...[
            const SizedBox(height: 4),
            Badge(label: Text(count > 99 ? '99+' : '$count'), backgroundColor: scheme.primary, textColor: scheme.onPrimary),
          ],
        ],
      ),
      onTap: () => context.push('/chat/${contact.id}'),
    );
  }
}
