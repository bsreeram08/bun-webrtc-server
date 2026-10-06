import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import 'widgets/common.dart';

/// Settings → Security: the chat key rotation schedule and explicit identity regeneration
/// (account.js `rotation-every` and `identity-reset`).
Future<void> showSecuritySettings(BuildContext context, WidgetRef ref) => showModalBottomSheet<void>(
  context: context,
  showDragHandle: true,
  builder: (_) => const _SecuritySheet(),
);

const _choices = {0: 'Off', 86400000: 'Every day', 604800000: 'Every week', 2592000000: 'Every 30 days'};

class _SecuritySheet extends ConsumerStatefulWidget {
  const _SecuritySheet();
  @override
  ConsumerState<_SecuritySheet> createState() => _SecuritySheetState();
}

class _SecuritySheetState extends ConsumerState<_SecuritySheet> {
  late int _value = ref.read(appProvider.notifier).messenger?.rotation.mine ?? 0;
  String? _status;

  Future<void> _regenerate() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Generate new identity keys?'),
        content: const Text('Every contact will see that your security code changed and has to accept it again. Use this only if you think your keys were exposed.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Theme.of(context).colorScheme.error),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Generate new keys'),
          ),
        ],
      ),
    );
    if (yes != true) return;
    try {
      await ref.read(appProvider.notifier).regenerateIdentity();
      setState(() => _status = 'New identity keys are in use. Your contacts will see that your security code changed.');
    } catch (e) {
      if (mounted) showSnack(context, 'Could not generate new keys: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Security', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 16),
            const Text('Rotate chat keys automatically'),
            const SizedBox(height: 8),
            DropdownButton<int>(
              key: const Key('rotation-every'),
              value: _value,
              isExpanded: true,
              items: [for (final entry in _choices.entries) DropdownMenuItem(value: entry.key, child: Text(entry.value))],
              onChanged: (value) async {
                if (value == null) return;
                setState(() {
                  _value = value;
                  _status = value == 0
                      ? "Automatic rotation is off. A contact's shorter interval still applies to your chat with them."
                      : 'Chat keys rotate ${_choices[value]!.toLowerCase()}, or sooner if a contact chose a shorter interval.';
                });
                await ref.read(appProvider.notifier).setRotation(value);
              },
            ),
            const SizedBox(height: 16),
            OutlinedButton(
              key: const Key('identity-reset'),
              style: OutlinedButton.styleFrom(foregroundColor: Theme.of(context).colorScheme.error),
              onPressed: _regenerate,
              child: const Text('Generate new identity keys'),
            ),
            if (_status != null) ...[const SizedBox(height: 12), Text(_status!)],
          ],
        ),
      ),
    );
  }
}
