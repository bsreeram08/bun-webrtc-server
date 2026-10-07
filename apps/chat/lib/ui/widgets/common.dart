import 'package:flutter/material.dart';

String clock(int ms) {
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  final h = t.hour % 12 == 0 ? 12 : t.hour % 12;
  return '$h:${t.minute.toString().padLeft(2, '0')} ${t.hour < 12 ? 'AM' : 'PM'}';
}

void showSnack(BuildContext context, String text) =>
    ScaffoldMessenger.maybeOf(context)?.showSnackBar(SnackBar(content: Text(text), behavior: SnackBarBehavior.floating));

/// Initial-letter avatar with an optional presence dot.
class Avatar extends StatelessWidget {
  const Avatar({super.key, required this.name, this.online, this.size = 48});
  final String name;
  final bool? online;
  final double size;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          CircleAvatar(
            radius: size / 2,
            backgroundColor: scheme.primary.withValues(alpha: .16),
            child: Text(
              name.isEmpty ? '?' : name[0].toUpperCase(),
              style: TextStyle(color: scheme.primary, fontWeight: FontWeight.w800, fontSize: size * .4),
            ),
          ),
          if (online != null)
            Positioned(
              right: -1,
              bottom: -1,
              child: Semantics(
                label: online! ? 'online' : 'offline',
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  width: size * .3,
                  height: size * .3,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: online! ? const Color(0xFF3CD07A) : scheme.outline,
                    border: Border.all(color: Theme.of(context).scaffoldBackgroundColor, width: 2.5),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
