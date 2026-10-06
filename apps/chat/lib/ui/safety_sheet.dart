import 'package:flutter/material.dart';

import '../crypto/chat_crypto.dart';

enum SafetyAction { verify, unverify, accept }

Future<SafetyAction?> showSafetySheet(BuildContext context, String name, SafetyNumber safety) =>
    showModalBottomSheet<SafetyAction>(context: context, isScrollControlled: true, builder: (_) => SafetySheet(name: name, safety: safety));

/// The 60-digit security code with a contact (compare once, in person or on a call).
class SafetySheet extends StatelessWidget {
  const SafetySheet({super.key, required this.name, required this.safety});
  final String name;
  final SafetyNumber safety;

  @override
  Widget build(BuildContext context) {
    final groups = safety.number.split(' ');
    final scheme = Theme.of(context).colorScheme;
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(safety.verified ? Icons.verified_user : Icons.shield_outlined, color: scheme.primary),
                const SizedBox(width: 10),
                Expanded(child: Text('Security code with $name', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700))),
              ],
            ),
            const SizedBox(height: 18),
            Semantics(
              label: 'Security code ${safety.number}',
              child: GridView.count(
                crossAxisCount: 4,
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                childAspectRatio: 2.2,
                children: [
                  for (final g in groups)
                    Center(child: Text(g, style: const TextStyle(fontFamily: 'monospace', fontSize: 20, fontWeight: FontWeight.w700, letterSpacing: 1))),
                ],
              ),
            ),
            const SizedBox(height: 14),
            Text(
              safety.verified
                  ? 'Verified on this device.'
                  : safety.changed
                  ? 'This code changed recently. Compare it before trusting new messages.'
                  : 'Not verified yet. Compare these 60 digits with the ones on their screen, in person or on a call. If they match, no one — not even this server — can read your messages.',
            ),
            const SizedBox(height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                if (safety.blocked) ...[
                  OutlinedButton(onPressed: () => Navigator.pop(context, SafetyAction.accept), child: const Text('Accept new code')),
                  const SizedBox(width: 10),
                ],
                FilledButton(
                  onPressed: () => Navigator.pop(context, safety.verified ? SafetyAction.unverify : SafetyAction.verify),
                  child: Text(safety.verified ? 'Clear verification' : 'Mark as verified'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
