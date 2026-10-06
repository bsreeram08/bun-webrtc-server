import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../theme/tokens.dart';

/// Low-contrast chat wallpapers drawn from the theme colors (dots, grid,
/// lines, glow, circuit). Painted once and cached by a RepaintBoundary.
class Wallpaper extends StatelessWidget {
  const Wallpaper({super.key, required this.kind, required this.tokens, required this.child});
  final String kind;
  final ChatTokens tokens;
  final Widget child;

  @override
  Widget build(BuildContext context) => Stack(
    fit: StackFit.expand,
    children: [
      ColoredBox(color: tokens.bg),
      if (kind != 'none') RepaintBoundary(child: CustomPaint(painter: _WallPainter(kind, tokens))),
      child,
    ],
  );
}

class _WallPainter extends CustomPainter {
  _WallPainter(this.kind, this.t);
  final String kind;
  final ChatTokens t;

  @override
  void paint(Canvas canvas, Size size) {
    final ink = t.text.withValues(alpha: t.dark ? .06 : .07);
    final paint = Paint()
      ..color = ink
      ..strokeWidth = 1
      ..style = PaintingStyle.stroke;
    switch (kind) {
      case 'dots':
        final dot = Paint()..color = ink;
        for (var y = 10.0; y < size.height; y += 22) {
          for (var x = (y ~/ 22).isEven ? 10.0 : 21.0; x < size.width; x += 22) {
            canvas.drawCircle(Offset(x, y), 1.4, dot);
          }
        }
      case 'grid':
        paint.color = t.text.withValues(alpha: t.dark ? .035 : .05);
        for (var x = 0.0; x < size.width; x += 28) {
          canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
        }
        for (var y = 0.0; y < size.height; y += 28) {
          canvas.drawLine(Offset(0, y), Offset(size.width, y), paint);
        }
      case 'lines':
        for (var d = -size.height; d < size.width; d += 18) {
          canvas.drawLine(Offset(d, size.height), Offset(d + size.height, 0), paint);
        }
      case 'gradient':
        final rect = Offset.zero & size;
        canvas.drawRect(
          rect,
          Paint()
            ..shader = RadialGradient(
              center: const Alignment(.7, -.8),
              radius: 1.2,
              colors: [t.accent.withValues(alpha: .16), t.accent.withValues(alpha: 0)],
            ).createShader(rect),
        );
      case 'circuit':
        paint.color = t.accent.withValues(alpha: .1);
        final rng = math.Random(7);
        final node = Paint()..color = t.accent.withValues(alpha: .14);
        for (var y = 30.0; y < size.height; y += 64) {
          for (var x = 20.0; x < size.width; x += 80) {
            final path = Path()
              ..moveTo(x, y)
              ..lineTo(x + 24, y)
              ..lineTo(x + 36, y + (rng.nextBool() ? 14 : -14))
              ..lineTo(x + 64, y + (rng.nextBool() ? 14 : -14));
            canvas.drawPath(path, paint);
            canvas.drawCircle(Offset(x, y), 2.4, node);
          }
        }
    }
  }

  @override
  bool shouldRepaint(_WallPainter old) => old.kind != kind || old.t.hex != t.hex;
}
