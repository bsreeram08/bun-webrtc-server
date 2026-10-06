import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../theme/theme_prefs.dart';
import '../theme/tokens.dart';

const _accents = ['#a1efce', '#3dff73', '#6fcbff', '#8ab4ff', '#b794ff', '#f6a8cb', '#ff8a65', '#f2c14e', '#0a7a52', '#e2606e'];

/// App theme, or one conversation's theme when [chatId] is given.
Future<void> showThemePicker(BuildContext context, WidgetRef ref, {String? chatId}) =>
    showModalBottomSheet<void>(context: context, isScrollControlled: true, builder: (_) => ThemePicker(chatId: chatId));

class ThemePicker extends ConsumerWidget {
  const ThemePicker({super.key, this.chatId});
  final String? chatId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final prefs = ref.watch(themePrefsProvider);
    final notifier = ref.read(themePrefsProvider.notifier);
    final entry = chatId == null ? prefs.app : prefs.chats[chatId] ?? const ThemeChoice();
    final effective = prefs.resolve(chatId);
    void choose({Object? preset = _keep, Object? accent = _keep, Object? wallpaper = _keep}) {
      final next = ThemeChoice(
        preset: preset == _keep ? entry.preset : preset as String?,
        accent: accent == _keep ? entry.accent : accent as String?,
        wallpaper: wallpaper == _keep ? entry.wallpaper : wallpaper as String?,
      );
      chatId == null ? notifier.setApp(next) : notifier.setChat(chatId!, next);
    }

    final scheme = Theme.of(context).colorScheme;
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(chatId == null ? 'App theme' : 'Chat theme', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700)),
            Text(chatId == null ? 'Every conversation without its own theme, on this device.' : 'Only this conversation, on this device.'),
            const SizedBox(height: 16),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                if (chatId != null) _Swatch(label: 'Same as app', selected: entry.preset == null, onTap: () => choose(preset: null, accent: null)),
                for (final p in presets.values)
                  _Swatch(
                    label: p.name,
                    tokens: ChatTokens.resolve(p.key),
                    selected: (chatId == null ? effective.preset : entry.preset) == p.key,
                    onTap: () => choose(preset: p.key, accent: null),
                  ),
              ],
            ),
            const SizedBox(height: 18),
            const Text('Accent', style: TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            Wrap(
              spacing: 10,
              runSpacing: 10,
              children: [
                for (final hex in _accents)
                  Semantics(
                    button: true,
                    selected: effective.accent == hex,
                    label: 'Accent $hex',
                    child: InkWell(
                      customBorder: const CircleBorder(),
                      onTap: () => choose(accent: hex),
                      child: Container(
                        width: 34,
                        height: 34,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: Color(0xFF000000 | int.parse(hex.substring(1), radix: 16)),
                          border: Border.all(color: effective.accent == hex ? scheme.onSurface : Colors.transparent, width: 3),
                        ),
                      ),
                    ),
                  ),
                if (entry.accent != null) TextButton(onPressed: () => choose(accent: null), child: const Text('Reset')),
              ],
            ),
            const SizedBox(height: 18),
            const Text('Wallpaper', style: TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                ChoiceChip(label: const Text('Theme default'), selected: entry.wallpaper == null, onSelected: (_) => choose(wallpaper: null)),
                for (final w in wallpapers.entries)
                  ChoiceChip(label: Text(w.value), selected: entry.wallpaper == w.key, onSelected: (_) => choose(wallpaper: w.key)),
              ],
            ),
            const SizedBox(height: 16),
            Align(alignment: Alignment.centerRight, child: FilledButton(onPressed: () => Navigator.pop(context), child: const Text('Done'))),
          ],
        ),
      ),
    );
  }
}

const _keep = Object();

class _Swatch extends StatelessWidget {
  const _Swatch({required this.label, required this.selected, required this.onTap, this.tokens});
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final ChatTokens? tokens;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final t = tokens;
    return Semantics(
      button: true,
      selected: selected,
      label: label,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 160),
          width: 96,
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: selected ? scheme.primary : scheme.outline.withValues(alpha: .4), width: selected ? 2.5 : 1),
          ),
          child: Column(
            children: [
              Container(
                height: 54,
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(color: t?.bg ?? scheme.surface, borderRadius: BorderRadius.circular(9)),
                child: t == null
                    ? const Center(child: Icon(Icons.layers_outlined, size: 20))
                    : Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Align(alignment: Alignment.centerLeft, child: _bar(t.theirs, 40)),
                          const SizedBox(height: 5),
                          Align(alignment: Alignment.centerRight, child: _bar(t.mine, 46)),
                          const Spacer(),
                          Align(alignment: Alignment.centerRight, child: CircleAvatar(radius: 4, backgroundColor: t.accent)),
                        ],
                      ),
              ),
              const SizedBox(height: 6),
              Text(label, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600), maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
          ),
        ),
      ),
    );
  }

  Widget _bar(Color color, double width) =>
      Container(width: width, height: 10, decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(5)));
}
