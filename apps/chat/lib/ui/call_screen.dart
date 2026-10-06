import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../app/app_controller.dart';
import '../calls/call_controller.dart';
import 'widgets/common.dart';
import 'widgets/icons.dart';

class CallScreen extends ConsumerWidget {
  const CallScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final call = ref.watch(appProvider.select((s) => s.call));
    if (call == null) return const Scaffold(body: Center(child: Text('No call')));
    return ListenableBuilder(
      listenable: call,
      builder: (context, _) {
        if (call.phase == CallPhase.ended) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (context.mounted && Navigator.canPop(context)) Navigator.pop(context);
            ref.read(appProvider.notifier).callFinished();
            if (call.endReason != null && context.mounted) showSnack(context, call.endReason!);
          });
        }
        return CallView(
          peerName: call.peerName,
          status: call.status,
          verify: call.verify,
          verifyCode: call.verifyCode,
          verifyLabel: call.verifyLabel,
          muted: call.muted,
          cameraOff: call.cameraOff || !call.hasLocalVideo,
          speaker: call.speaker,
          remote: call.remoteVideo ? RTCVideoView(call.remoteRenderer, objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover) : null,
          local: call.hasLocalVideo && !call.cameraOff ? RTCVideoView(call.localRenderer, mirror: true, objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover) : null,
          onMute: call.toggleMute,
          onCamera: call.toggleCamera,
          onSpeaker: Platform.isAndroid || Platform.isIOS ? call.toggleSpeaker : null,
          onEnd: call.hangUp,
        );
      },
    );
  }
}

/// The in-call layout: remote video (or the caller's avatar) full screen,
/// the local picture-in-picture, the verification code on top, round controls below.
class CallView extends StatelessWidget {
  const CallView({
    super.key,
    required this.peerName,
    required this.status,
    required this.verify,
    required this.verifyCode,
    required this.verifyLabel,
    required this.muted,
    required this.cameraOff,
    required this.speaker,
    required this.onMute,
    required this.onCamera,
    required this.onEnd,
    this.onSpeaker,
    this.remote,
    this.local,
  });

  final String peerName, status, verifyCode, verifyLabel;
  final VerifyState verify;
  final bool muted, cameraOff, speaker;
  final VoidCallback onMute, onCamera, onEnd;
  final VoidCallback? onSpeaker;
  final Widget? remote, local;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    const light = Colors.white;
    final warn = verify == VerifyState.warn;
    return Scaffold(
      backgroundColor: const Color(0xFF0B1016),
      body: Stack(
        fit: StackFit.expand,
        children: [
          remote ??
              Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  PulseRing(color: scheme.primary, child: Avatar(name: peerName, size: 120)),
                  const SizedBox(height: 18),
                  Text(peerName, style: const TextStyle(color: light, fontSize: 24, fontWeight: FontWeight.w700)),
                ],
              ),
          if (local != null)
            Positioned(
              right: 16,
              top: MediaQuery.paddingOf(context).top + 96,
              width: 108,
              height: 144,
              child: ClipRRect(borderRadius: BorderRadius.circular(16), child: local),
            ),
          Positioned(
            left: 0,
            right: 0,
            top: 0,
            child: Container(
              padding: EdgeInsets.fromLTRB(16, MediaQuery.paddingOf(context).top + 10, 16, 24),
              decoration: const BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0xAA000000), Color(0x00000000)])),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    key: const Key('verify-badge'),
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                    decoration: BoxDecoration(
                      color: (warn ? const Color(0xFF3D321A) : verify == VerifyState.ok ? const Color(0xFF1D3A2C) : const Color(0xFF20303C)).withValues(alpha: .92),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: warn ? const Color(0xFF7A6326) : const Color(0x33FFFFFF)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        ShieldCheck(verified: verify == VerifyState.ok, warn: warn, color: warn ? const Color(0xFFF2C14E) : scheme.primary),
                        const SizedBox(width: 10),
                        Flexible(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (verifyCode.isNotEmpty)
                                Text(verifyCode, style: const TextStyle(color: light, fontSize: 28, fontWeight: FontWeight.w800, letterSpacing: 2, fontFeatures: [FontFeature.tabularFigures()])),
                              Text(verifyLabel, style: TextStyle(color: warn ? const Color(0xFFF2C14E) : const Color(0xFFC3CFD8), fontSize: 13)),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(status, style: const TextStyle(color: Color(0xFFC3CFD8), fontSize: 13)),
                ],
              ),
            ),
          ),
          Positioned(
            left: 0,
            right: 0,
            bottom: 0,
            child: Container(
              padding: EdgeInsets.fromLTRB(12, 40, 12, MediaQuery.paddingOf(context).bottom + 20),
              decoration: const BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [Color(0x00000000), Color(0xBB000000)])),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _Round(label: muted ? 'Unmute' : 'Mute', active: muted, onTap: onMute, child: SlashIcon(icon: Icons.mic_none, off: muted, color: muted ? Colors.black : light)),
                  _Round(label: 'Camera', active: cameraOff, onTap: onCamera, child: SlashIcon(icon: Icons.videocam_outlined, off: cameraOff, color: cameraOff ? Colors.black : light)),
                  if (onSpeaker != null)
                    _Round(label: 'Speaker', active: speaker, onTap: onSpeaker!, child: Icon(speaker ? Icons.volume_up : Icons.volume_down, color: speaker ? Colors.black : light)),
                  _Round(label: 'End', end: true, onTap: onEnd, child: const Icon(Icons.call_end, color: light, size: 30)),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Round extends StatelessWidget {
  const _Round({required this.label, required this.onTap, required this.child, this.active = false, this.end = false});
  final String label;
  final VoidCallback onTap;
  final Widget child;
  final bool active, end;

  @override
  Widget build(BuildContext context) => Semantics(
    button: true,
    label: label,
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Material(
          color: end ? const Color(0xFFE2606E) : active ? Colors.white : const Color(0x33FFFFFF),
          shape: const CircleBorder(),
          child: InkWell(
            customBorder: const CircleBorder(),
            onTap: onTap,
            child: SizedBox.square(dimension: end ? 70 : 58, child: Center(child: child)),
          ),
        ),
        const SizedBox(height: 6),
        ExcludeSemantics(child: Text(label, style: const TextStyle(color: Colors.white, fontSize: 12))),
      ],
    ),
  );
}
