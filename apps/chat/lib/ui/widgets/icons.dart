import 'package:flutter/material.dart';

/// Animated line icons drawn with CustomPainter (the web app's SVG icons).
/// Motion is short and purposeful and switches off under reduced motion.

/// Mic / camera with a slash that draws in when [off] becomes true.
class SlashIcon extends StatelessWidget {
  const SlashIcon({super.key, required this.icon, required this.off, this.size = 26, this.color});
  final IconData icon;
  final bool off;
  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final reduce = MediaQuery.disableAnimationsOf(context);
    final c = color ?? IconTheme.of(context).color ?? Colors.white;
    return TweenAnimationBuilder<double>(
      tween: Tween(end: off ? 1 : 0),
      duration: reduce ? Duration.zero : const Duration(milliseconds: 220),
      curve: Curves.easeOut,
      builder: (context, t, _) => CustomPaint(
        foregroundPainter: _SlashPainter(t, c),
        child: Icon(icon, size: size, color: c),
      ),
    );
  }
}

class _SlashPainter extends CustomPainter {
  _SlashPainter(this.t, this.color);
  final double t;
  final Color color;
  @override
  void paint(Canvas canvas, Size size) {
    if (t == 0) return;
    final paint = Paint()
      ..color = color
      ..strokeWidth = 2.2
      ..strokeCap = StrokeCap.round;
    final a = Offset(size.width * .14, size.height * .14), b = Offset(size.width * .86, size.height * .86);
    canvas.drawLine(a, Offset.lerp(a, b, t)!, paint);
  }

  @override
  bool shouldRepaint(_SlashPainter old) => old.t != t || old.color != color;
}

/// Send button: the paper plane lifts and flies off, then returns, on each [sends] change.
class SendPlane extends StatefulWidget {
  const SendPlane({super.key, required this.sends, required this.color});
  final int sends;
  final Color color;
  @override
  State<SendPlane> createState() => _SendPlaneState();
}

class _SendPlaneState extends State<SendPlane> with SingleTickerProviderStateMixin {
  late final AnimationController c = AnimationController(vsync: this, duration: const Duration(milliseconds: 360));
  @override
  void didUpdateWidget(SendPlane oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.sends != widget.sends && !MediaQuery.disableAnimationsOf(context)) c.forward(from: 0);
  }

  @override
  void dispose() {
    c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: c,
    builder: (context, child) {
      final t = c.value;
      // Out to the top right for the first half, back in from below for the second.
      final offset = t < .5 ? Offset(t * 2 * 18, -t * 2 * 18) : Offset((t - 1) * 2 * 10, (1 - t) * 2 * 10);
      return Transform.translate(offset: offset, child: Opacity(opacity: t < .5 ? 1 - t : t, child: child));
    },
    child: Icon(Icons.send_rounded, color: widget.color),
  );
}

/// Verification shield; the check draws in when [verified] becomes true.
class ShieldCheck extends StatelessWidget {
  const ShieldCheck({super.key, required this.verified, required this.color, this.warn = false});
  final bool verified, warn;
  final Color color;
  @override
  Widget build(BuildContext context) {
    final reduce = MediaQuery.disableAnimationsOf(context);
    return TweenAnimationBuilder<double>(
      tween: Tween(end: verified ? 1 : 0),
      duration: reduce ? Duration.zero : const Duration(milliseconds: 320),
      builder: (context, t, _) => CustomPaint(size: const Size(26, 28), painter: _ShieldPainter(t, color, warn)),
    );
  }
}

class _ShieldPainter extends CustomPainter {
  _ShieldPainter(this.t, this.color, this.warn);
  final double t;
  final Color color;
  final bool warn;
  @override
  void paint(Canvas canvas, Size s) {
    final paint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..strokeJoin = StrokeJoin.round
      ..strokeCap = StrokeCap.round;
    final shield = Path()
      ..moveTo(s.width / 2, 2)
      ..lineTo(s.width - 3, 6)
      ..quadraticBezierTo(s.width - 3, s.height - 6, s.width / 2, s.height - 2)
      ..quadraticBezierTo(3, s.height - 6, 3, 6)
      ..close();
    canvas.drawPath(shield, paint);
    if (warn) {
      canvas.drawLine(Offset(s.width / 2, 9), Offset(s.width / 2, s.height - 12), paint);
      canvas.drawCircle(Offset(s.width / 2, s.height - 8), .8, paint);
      return;
    }
    final check = Path()
      ..moveTo(s.width * .3, s.height * .5)
      ..lineTo(s.width * .45, s.height * .64)
      ..lineTo(s.width * .72, s.height * .36);
    for (final m in check.computeMetrics()) {
      canvas.drawPath(m.extractPath(0, m.length * t), paint);
    }
  }

  @override
  bool shouldRepaint(_ShieldPainter old) => old.t != t || old.color != color || old.warn != warn;
}

/// A soft pulsing ring behind the caller's avatar while a call rings.
class PulseRing extends StatefulWidget {
  const PulseRing({super.key, required this.child, required this.color});
  final Widget child;
  final Color color;
  @override
  State<PulseRing> createState() => _PulseRingState();
}

class _PulseRingState extends State<PulseRing> with SingleTickerProviderStateMixin {
  late final AnimationController c = AnimationController(vsync: this, duration: const Duration(milliseconds: 1400));
  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (MediaQuery.disableAnimationsOf(context)) {
      c.stop();
    } else if (!c.isAnimating) {
      c.repeat();
    }
  }

  @override
  void dispose() {
    c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: c,
    builder: (context, child) => Container(
      padding: EdgeInsets.all(6 + 10 * c.value),
      decoration: BoxDecoration(shape: BoxShape.circle, color: widget.color.withValues(alpha: .18 * (1 - c.value))),
      child: child,
    ),
    child: widget.child,
  );
}
