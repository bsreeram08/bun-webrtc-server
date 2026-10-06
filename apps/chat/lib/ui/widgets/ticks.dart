import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../store/message.dart';

/// Delivery ticks that animate only when the status changes, never on first
/// build (opening a conversation draws history still). sent: one check draws
/// in; delivered: the second draws in and both take the accent color; queued:
/// a small rotating clock. Respects reduced motion.
class Ticks extends StatefulWidget {
  const Ticks({super.key, required this.status, required this.color, required this.readColor});
  final MessageStatus status;
  final Color color;
  final Color readColor;

  @override
  State<Ticks> createState() => TicksState();
}

class TicksState extends State<Ticks> with TickerProviderStateMixin {
  late final AnimationController draw = AnimationController(vsync: this, duration: const Duration(milliseconds: 260), value: 1);
  late final AnimationController spin = AnimationController(vsync: this, duration: const Duration(milliseconds: 1600));

  /// How many times a change animation has started (observable in tests).
  int animations = 0;

  @override
  void initState() {
    super.initState();
    _syncSpin();
  }

  @override
  void didUpdateWidget(Ticks oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.status != widget.status) {
      _syncSpin();
      if (!MediaQuery.disableAnimationsOf(context)) {
        animations++;
        draw.forward(from: 0);
      }
    }
  }

  void _syncSpin() {
    final reduce = WidgetsBinding.instance.platformDispatcher.accessibilityFeatures.disableAnimations;
    if (widget.status == MessageStatus.queued && !reduce) {
      spin.repeat();
    } else {
      spin.stop();
    }
  }

  @override
  void dispose() {
    draw.dispose();
    spin.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final label = switch (widget.status) {
      MessageStatus.queued => 'Queued on this device',
      MessageStatus.sent => 'Sent',
      MessageStatus.delivered => 'Delivered',
      MessageStatus.uncertain => 'Delivery unconfirmed',
    };
    return Semantics(
      label: label,
      child: SizedBox(
        width: 18,
        height: 12,
        child: AnimatedBuilder(
          animation: Listenable.merge([draw, spin]),
          builder: (context, _) => CustomPaint(
            painter: _TickPainter(
              status: widget.status,
              progress: Curves.easeOut.transform(draw.value),
              spin: spin.value,
              color: widget.status == MessageStatus.delivered ? widget.readColor : widget.color,
            ),
          ),
        ),
      ),
    );
  }
}

class _TickPainter extends CustomPainter {
  _TickPainter({required this.status, required this.progress, required this.spin, required this.color});
  final MessageStatus status;
  final double progress, spin;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.6
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    if (status == MessageStatus.queued) {
      final center = Offset(size.width - 6, size.height / 2);
      canvas.drawCircle(center, 4.6, paint);
      final angle = spin * 2 * math.pi - math.pi / 2;
      canvas.drawLine(center, center + Offset(math.cos(angle), math.sin(angle)) * 3, paint);
      canvas.drawLine(center, center + const Offset(0, -2.6), paint);
      return;
    }
    Path check(double dx) => Path()
      ..moveTo(dx + 1, 6.5)
      ..lineTo(dx + 4, 9.5)
      ..lineTo(dx + 10, 2.5);
    void drawPartial(Path path, double amount) {
      for (final metric in path.computeMetrics()) {
        canvas.drawPath(metric.extractPath(0, metric.length * amount.clamp(0, 1)), paint);
      }
    }

    if (status == MessageStatus.delivered) {
      drawPartial(check(0), 1);
      drawPartial(check(6), progress);
    } else {
      drawPartial(check(6), progress);
    }
  }

  @override
  bool shouldRepaint(_TickPainter old) => old.progress != progress || old.spin != spin || old.status != status || old.color != color;
}
