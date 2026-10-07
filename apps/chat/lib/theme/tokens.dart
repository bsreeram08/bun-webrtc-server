import 'dart:math' as math;

import 'package:flutter/material.dart';

/// The web client's theme presets and color math (theme.js), so both apps
/// look the same and apply the same WCAG contrast rules.
class Preset {
  const Preset({
    required this.key,
    required this.name,
    required this.dark,
    required this.bg,
    required this.surface,
    required this.surface2,
    required this.raised,
    required this.line,
    required this.lineStrong,
    required this.text,
    required this.muted,
    required this.accent,
    required this.mine,
    required this.theirs,
    required this.danger,
    required this.dangerBg,
    required this.warn,
    required this.warnBg,
    required this.wallpaper,
    this.mono = false,
  });
  final String key, name, wallpaper;
  final bool dark, mono;
  final String bg, surface, surface2, raised, line, lineStrong, text, muted, accent, mine, theirs, danger, dangerBg, warn, warnBg;
}

const presets = <String, Preset>{
  'midnight': Preset(key: 'midnight', name: 'Midnight', dark: true, bg: '#111820', surface: '#192733', surface2: '#20303c', raised: '#263d4c', line: '#344755', lineStrong: '#647987', text: '#eef4f9', muted: '#afbfcc', accent: '#a1efce', mine: '#244535', theirs: '#20303c', danger: '#e2606e', dangerBg: '#562d35', warn: '#f2c14e', warnBg: '#3d321a', wallpaper: 'none'),
  'fsociety': Preset(key: 'fsociety', name: 'fsociety', dark: true, mono: true, bg: '#040805', surface: '#09110b', surface2: '#0e1a11', raised: '#142418', line: '#1c3322', lineStrong: '#2f5a39', text: '#c9f7c8', muted: '#7cb487', accent: '#3dff73', mine: '#0f2b17', theirs: '#0c1810', danger: '#ff4d5e', dangerBg: '#3a1015', warn: '#e8d44d', warnBg: '#2a260c', wallpaper: 'circuit'),
  'light': Preset(key: 'light', name: 'Daylight', dark: false, bg: '#f4f6f8', surface: '#ffffff', surface2: '#eaeff3', raised: '#dfe6ec', line: '#d3dce3', lineStrong: '#a3b1bc', text: '#13202a', muted: '#52616c', accent: '#0a7a52', mine: '#d4f3e4', theirs: '#ffffff', danger: '#c2334a', dangerBg: '#fbe1e5', warn: '#7d5800', warnBg: '#fff1c7', wallpaper: 'dots'),
  'amoled': Preset(key: 'amoled', name: 'AMOLED', dark: true, bg: '#000000', surface: '#0b0b0b', surface2: '#141414', raised: '#1e1e1e', line: '#262626', lineStrong: '#454545', text: '#f2f2f2', muted: '#a6a6a6', accent: '#8ab4ff', mine: '#15253f', theirs: '#161616', danger: '#ff6b78', dangerBg: '#3b141a', warn: '#ffd166', warnBg: '#2e2510', wallpaper: 'none'),
  'dusk': Preset(key: 'dusk', name: 'Dusk', dark: true, bg: '#16111e', surface: '#1f1829', surface2: '#292034', raised: '#342a42', line: '#3d3150', lineStrong: '#6b5b82', text: '#f4eefb', muted: '#c4b7d8', accent: '#f6a8cb', mine: '#4a2944', theirs: '#292034', danger: '#ff6f86', dangerBg: '#4a1f2c', warn: '#f7c86b', warnBg: '#3a2c18', wallpaper: 'gradient'),
  'ocean': Preset(key: 'ocean', name: 'Ocean', dark: true, bg: '#0a1520', surface: '#0f1f2e', surface2: '#14283b', raised: '#1b344d', line: '#233f5a', lineStrong: '#4b6a89', text: '#eaf3fb', muted: '#a8bfd3', accent: '#6fcbff', mine: '#153a59', theirs: '#14283b', danger: '#ff6b78', dangerBg: '#45202a', warn: '#f5c451', warnBg: '#382d14', wallpaper: 'lines'),
};

const wallpapers = <String, String>{'none': 'None', 'dots': 'Dots', 'grid': 'Grid', 'lines': 'Lines', 'gradient': 'Glow', 'circuit': 'Circuit'};

final _hexPattern = RegExp(r'^#[0-9a-fA-F]{6}$');
bool isHexColor(String? value) => value != null && _hexPattern.hasMatch(value);

List<int> _rgb(String hex) => [1, 3, 5].map((i) => int.parse(hex.substring(i, i + 2), radix: 16)).toList();
String _hex(List<double> values) => '#${values.map((v) => v.round().clamp(0, 255).toRadixString(16).padLeft(2, '0')).join()}';

double luminance(String color) {
  final c = _rgb(color).map((v) {
    final x = v / 255;
    return x <= 0.03928 ? x / 12.92 : math.pow((x + 0.055) / 1.055, 2.4).toDouble();
  }).toList();
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

double contrast(String a, String b) {
  final x = luminance(a), y = luminance(b);
  return (math.max(x, y) + 0.05) / (math.min(x, y) + 0.05);
}

String mix(String a, String b, double amount) {
  final p = _rgb(a), q = _rgb(b);
  return _hex([for (var i = 0; i < 3; i++) p[i] * amount + q[i] * (1 - amount)]);
}

String ink(String color) => contrast(color, '#ffffff') >= contrast(color, '#0b0f12') ? '#ffffff' : '#0b0f12';

Color _c(String hex) => Color(0xFF000000 | int.parse(hex.substring(1), radix: 16));

/// Resolved colors for one preset, optionally re-tinted around a custom accent.
class ChatTokens {
  ChatTokens._(this.preset, Map<String, String> v)
    : bg = _c(v['bg']!),
      surface = _c(v['surface']!),
      surface2 = _c(v['surface2']!),
      raised = _c(v['raised']!),
      line = _c(v['line']!),
      lineStrong = _c(v['lineStrong']!),
      text = _c(v['text']!),
      muted = _c(v['muted']!),
      accent = _c(v['accent']!),
      accentInk = _c(v['accentInk']!),
      mine = _c(v['mine']!),
      theirs = _c(v['theirs']!),
      meta = _c(v['meta']!),
      tickRead = _c(v['tickRead']!),
      okBg = _c(v['okBg']!),
      okLine = _c(v['okLine']!),
      danger = _c(v['danger']!),
      dangerBg = _c(v['dangerBg']!),
      dangerText = _c(v['dangerText']!),
      warn = _c(v['warn']!),
      warnBg = _c(v['warnBg']!),
      hex = v;

  final Preset preset;
  final Map<String, String> hex;
  final Color bg, surface, surface2, raised, line, lineStrong, text, muted, accent, accentInk, mine, theirs, meta, tickRead, okBg, okLine, danger, dangerBg, dangerText, warn, warnBg;
  bool get dark => preset.dark;
  bool get mono => preset.mono;

  /// Port of theme.js `tokens()`: tint the outgoing bubble toward the accent,
  /// backing off until its text keeps 4.5:1 contrast.
  factory ChatTokens.resolve(String presetKey, [String? accent]) {
    final p = presets[presetKey] ?? presets['midnight']!;
    final v = <String, String>{
      'bg': p.bg, 'surface': p.surface, 'surface2': p.surface2, 'raised': p.raised, 'line': p.line, 'lineStrong': p.lineStrong,
      'text': p.text, 'muted': p.muted, 'accent': p.accent, 'mine': p.mine, 'theirs': p.theirs,
      'danger': p.danger, 'dangerBg': p.dangerBg, 'warn': p.warn, 'warnBg': p.warnBg,
    };
    if (isHexColor(accent)) {
      v['accent'] = accent!.toLowerCase();
      var amount = p.dark ? 0.34 : 0.24;
      var mine = mix(v['accent']!, p.bg, amount);
      while (contrast(mine, p.text) < 4.5 && amount > 0.04) {
        amount -= 0.03;
        mine = mix(v['accent']!, p.bg, amount);
      }
      v['mine'] = mine;
    }
    v['accentInk'] = ink(v['accent']!);
    v['okBg'] = mix(v['accent']!, p.bg, p.dark ? 0.14 : 0.16);
    v['okLine'] = mix(v['accent']!, p.bg, 0.35);
    v['meta'] = mix(p.text, v['mine']!, 0.72);
    v['tickRead'] = contrast(v['accent']!, v['mine']!) >= 3 ? v['accent']! : p.text;
    v['dangerText'] = p.dark ? mix(p.danger, '#ffffff', 0.7) : p.danger;
    return ChatTokens._(p, v);
  }

  ThemeData material() {
    final scheme = ColorScheme.fromSeed(
      seedColor: accent,
      brightness: dark ? Brightness.dark : Brightness.light,
    ).copyWith(primary: accent, onPrimary: accentInk, surface: bg, onSurface: text, error: danger, outline: lineStrong);
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: bg,
      appBarTheme: AppBarTheme(backgroundColor: bg, foregroundColor: text, elevation: 0, scrolledUnderElevation: 0),
      dividerColor: line,
      bottomSheetTheme: BottomSheetThemeData(backgroundColor: surface2, showDragHandle: true),
      dialogTheme: DialogThemeData(backgroundColor: surface2),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surface,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(24), borderSide: BorderSide(color: lineStrong)),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(24), borderSide: BorderSide(color: lineStrong)),
        hintStyle: TextStyle(color: muted),
      ),
      textTheme: Typography.material2021().englishLike.apply(bodyColor: text, displayColor: text),
    );
  }
}
