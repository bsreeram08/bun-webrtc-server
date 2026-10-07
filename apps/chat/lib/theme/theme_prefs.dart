import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'tokens.dart';

/// A theme choice: preset, optional custom accent, optional wallpaper.
class ThemeChoice {
  const ThemeChoice({this.preset, this.accent, this.wallpaper});
  final String? preset, accent, wallpaper;

  factory ThemeChoice.fromJson(Object? json) {
    if (json is! Map) return const ThemeChoice();
    final preset = json['preset'], accent = json['accent'], wallpaper = json['wallpaper'];
    return ThemeChoice(
      preset: presets.containsKey(preset) ? preset as String : null,
      accent: isHexColor(accent as String?) ? (accent as String).toLowerCase() : null,
      wallpaper: wallpapers.containsKey(wallpaper) ? wallpaper as String : null,
    );
  }

  Map<String, String> toJson() => {'preset': ?preset, 'accent': ?accent, 'wallpaper': ?wallpaper};
  bool get isEmpty => preset == null && accent == null && wallpaper == null;
}

/// App-wide and per-chat appearance. Cosmetic and local to this device: it is
/// never sent to the server (same rule as theme.js).
class ThemePrefs {
  const ThemePrefs({this.app = const ThemeChoice(), this.chats = const {}});
  final ThemeChoice app;
  final Map<String, ThemeChoice> chats;

  /// Same precedence as theme.js `resolved()`.
  ({String preset, String? accent, String wallpaper}) resolve([String? chatId]) {
    final chat = chatId == null ? const ThemeChoice() : chats[chatId] ?? const ThemeChoice();
    final preset = chat.preset ?? app.preset ?? 'midnight';
    final accent = chat.accent ?? (chat.preset != null ? null : app.accent);
    final wallpaper = chat.wallpaper ?? app.wallpaper ?? presets[preset]!.wallpaper;
    return (preset: preset, accent: accent, wallpaper: wallpaper);
  }

  ChatTokens tokens([String? chatId]) {
    final r = resolve(chatId);
    return ChatTokens.resolve(r.preset, r.accent);
  }
}

class ThemePrefsNotifier extends Notifier<ThemePrefs> {
  static const _maxChats = 300;
  String _account = 'guest';
  SharedPreferences? _prefs;

  @override
  ThemePrefs build() => const ThemePrefs();

  Future<void> load(String? account) async {
    _account = account ?? 'guest';
    _prefs ??= await SharedPreferences.getInstance();
    try {
      final raw = jsonDecode(_prefs!.getString('theme-v1:$_account') ?? '{}') as Map<String, dynamic>;
      final chats = <String, ThemeChoice>{};
      if (raw['chats'] is Map) {
        for (final entry in (raw['chats'] as Map).entries) {
          if (entry.key is String && RegExp(r'^[A-Za-z0-9_:-]{1,80}$').hasMatch(entry.key as String)) {
            chats[entry.key as String] = ThemeChoice.fromJson(entry.value);
          }
        }
      }
      state = ThemePrefs(app: ThemeChoice.fromJson(raw['app']), chats: chats);
    } catch (_) {
      state = const ThemePrefs();
    }
  }

  void setApp(ThemeChoice choice) => _save(ThemePrefs(app: choice, chats: state.chats));

  void setChat(String chatId, ThemeChoice choice) {
    final chats = Map.of(state.chats)..remove(chatId);
    if (!choice.isEmpty) chats[chatId] = choice;
    while (chats.length > _maxChats) {
      chats.remove(chats.keys.first);
    }
    _save(ThemePrefs(app: state.app, chats: chats));
  }

  void _save(ThemePrefs next) {
    state = next;
    _prefs?.setString(
      'theme-v1:$_account',
      jsonEncode({'app': next.app.toJson(), 'chats': next.chats.map((k, v) => MapEntry(k, v.toJson()))}),
    );
  }
}

final themePrefsProvider = NotifierProvider<ThemePrefsNotifier, ThemePrefs>(ThemePrefsNotifier.new);
