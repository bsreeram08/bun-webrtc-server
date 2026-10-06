import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/theme/theme_prefs.dart';
import 'package:private_chat/theme/tokens.dart';

void main() {
  const accents = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#ffffff', '#000000', '#7f7f7f'];

  test('every preset, with and without a custom accent, keeps AA contrast for bubble and button text', () {
    for (final preset in presets.keys) {
      for (final accent in [null, ...accents]) {
        final t = ChatTokens.resolve(preset, accent);
        expect(contrast(t.hex['text']!, t.hex['mine']!), greaterThanOrEqualTo(4.5), reason: '$preset $accent outgoing bubble');
        expect(contrast(t.hex['text']!, t.hex['theirs']!), greaterThanOrEqualTo(4.5), reason: '$preset incoming bubble');
        expect(contrast(t.hex['accentInk']!, t.hex['accent']!), greaterThanOrEqualTo(4.5), reason: '$preset $accent button text');
      }
    }
  });

  test('color math matches WCAG reference values', () {
    expect(contrast('#000000', '#ffffff'), closeTo(21, 0.01));
    expect(contrast('#777777', '#ffffff'), closeTo(4.48, 0.01));
    expect(mix('#000000', '#ffffff', .5), '#808080');
  });

  test('delivered ticks use the accent only where it stands out on the bubble', () {
    for (final preset in presets.keys) {
      final t = ChatTokens.resolve(preset);
      expect(t.hex['tickRead'] == t.hex['accent'] ? contrast(t.hex['accent']!, t.hex['mine']!) >= 3 : true, isTrue, reason: preset);
    }
  });

  test('a chat theme overrides the app theme with the same precedence as theme.js', () {
    const prefs = ThemePrefs(
      app: ThemeChoice(preset: 'ocean', accent: '#ff8a65'),
      chats: {'chat1': ThemeChoice(preset: 'fsociety'), 'chat2': ThemeChoice(wallpaper: 'grid')},
    );
    expect(prefs.resolve(), (preset: 'ocean', accent: '#ff8a65', wallpaper: 'lines'));
    // Picking its own preset drops the app accent and uses the preset's wallpaper.
    expect(prefs.resolve('chat1'), (preset: 'fsociety', accent: null, wallpaper: 'circuit'));
    expect(prefs.resolve('chat2'), (preset: 'ocean', accent: '#ff8a65', wallpaper: 'grid'));
  });

  test('stored preferences are validated against the fixed lists', () {
    final choice = ThemeChoice.fromJson({'preset': 'evil', 'accent': 'url(x)', 'wallpaper': 'nope'});
    expect(choice.isEmpty, isTrue);
  });
}
