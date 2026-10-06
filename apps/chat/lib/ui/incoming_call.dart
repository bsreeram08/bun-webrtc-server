import 'package:flutter/material.dart';

import 'widgets/common.dart';
import 'widgets/icons.dart';

/// The in-app incoming call card. Video calls offer Decline / Audio only /
/// Video; voice calls offer Decline / Accept. It captures nothing itself: media
/// starts only from the callbacks, i.e. only after the user taps a button.
class IncomingCallCard extends StatelessWidget {
  const IncomingCallCard({super.key, required this.caller, required this.video, required this.onDecline, required this.onAccept});
  final String caller;
  final bool video;
  final VoidCallback onDecline;

  /// `audioOnly` is true for "Audio only" on a video call.
  final void Function({required bool audioOnly}) onAccept;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Material(
      color: Colors.black54,
      child: SafeArea(
        child: Center(
          child: Container(
            margin: const EdgeInsets.all(20),
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 20),
            constraints: const BoxConstraints(maxWidth: 420),
            decoration: BoxDecoration(color: Theme.of(context).bottomSheetTheme.backgroundColor ?? scheme.surface, borderRadius: BorderRadius.circular(28)),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                PulseRing(color: scheme.primary, child: Avatar(name: caller, size: 96)),
                const SizedBox(height: 16),
                Text(caller, style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800)),
                const SizedBox(height: 4),
                Text(video ? 'Incoming video call' : 'Incoming voice call', style: TextStyle(color: Theme.of(context).textTheme.bodySmall?.color, fontSize: 16)),
                const SizedBox(height: 24),
                Row(
                  children: [
                    Expanded(child: _Choice(key: const Key('decline'), icon: Icons.call_end, label: 'Decline', color: scheme.error, onTap: onDecline)),
                    if (video) ...[
                      const SizedBox(width: 10),
                      Expanded(
                        child: _Choice(key: const Key('accept-audio'), icon: Icons.mic_none, label: 'Audio only', onTap: () => onAccept(audioOnly: true)),
                      ),
                    ],
                    const SizedBox(width: 10),
                    Expanded(
                      child: _Choice(
                        key: const Key('accept'),
                        icon: video ? Icons.videocam_outlined : Icons.call,
                        label: video ? 'Video' : 'Accept',
                        color: scheme.primary,
                        ink: scheme.onPrimary,
                        onTap: () => onAccept(audioOnly: false),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _Choice extends StatelessWidget {
  const _Choice({super.key, required this.icon, required this.label, required this.onTap, this.color, this.ink});
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final Color? color, ink;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final fg = ink ?? (color == null ? scheme.onSurface : Colors.white);
    return Material(
      color: color ?? scheme.surfaceContainerHighest,
      borderRadius: BorderRadius.circular(22),
      child: InkWell(
        borderRadius: BorderRadius.circular(22),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Column(
            children: [
              Icon(icon, color: fg),
              const SizedBox(height: 6),
              Text(label, maxLines: 1, style: TextStyle(color: fg, fontWeight: FontWeight.w700)),
            ],
          ),
        ),
      ),
    );
  }
}
