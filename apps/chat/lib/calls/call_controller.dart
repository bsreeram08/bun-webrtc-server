import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import '../core/api.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/sas.dart';
import 'signaling.dart';

enum CallPhase { idle, preparing, waiting, connecting, connected, reconnecting, ended }

enum VerifyState { pending, ok, warn }

/// One device-to-device call, speaking the room protocol of server.ts and
/// app.js: token rotation on `welcome`, pairings bound to `sessionId`, perfect
/// negotiation (polite/impolite), ICE via `/rooms/:id/ice` (with TURN), and the
/// verify-v1 data channel. Media is captured only by [start], which the UI
/// calls only after the user taps Call or an Accept button.
class CallController extends ChangeNotifier {
  CallController({required this.api, required this.crypto, required this.peerName});

  final Api api;
  final ChatCrypto crypto;
  final String peerName;

  CallPhase phase = CallPhase.idle;
  String status = '';
  VerifyState verify = VerifyState.pending;
  String verifyCode = '';
  String verifyLabel = 'Verifying this call…';
  bool muted = false, cameraOff = false, speaker = true, remoteVideo = false, hasLocalVideo = false;
  String? endReason;

  final localRenderer = RTCVideoRenderer();
  final remoteRenderer = RTCVideoRenderer();

  String? _roomId, _token, _sessionId;
  bool _polite = false, _ready = false, _makingOffer = false, _ignoreOffer = false, _active = false;
  WebSocket? _socket;
  RTCPeerConnection? _pc;
  MediaStream? _local;
  Map<String, dynamic>? _ice;
  Future<void> _queue = Future.value();
  final List<(RTCIceCandidate, String?)> _pendingCandidates = [];
  Timer? _verifyTimer;
  int _generation = 0;

  bool get active => _active;

  /// [audioOnly] answers a video call with the microphone only.
  Future<void> start({required String roomId, required String token, required String kind, bool audioOnly = false}) async {
    _roomId = roomId;
    _token = token;
    _active = true;
    _set(CallPhase.preparing, 'Preparing your microphone…');
    await localRenderer.initialize();
    await remoteRenderer.initialize();
    final video = kind == 'video' && !audioOnly;
    try {
      _local = await navigator.mediaDevices.getUserMedia({'audio': true, 'video': video ? {'facingMode': 'user'} : false});
    } catch (_) {
      return end('Microphone or camera permission denied. Allow access, then try again.');
    }
    if (!_active) {
      await _stopLocal();
      return;
    }
    hasLocalVideo = video;
    localRenderer.srcObject = _local;
    if (Platform.isAndroid || Platform.isIOS) await Helper.setSpeakerphoneOn(video);
    speaker = video;
    _ice = await api.ice(roomId, token).catchError((Object _) => <String, dynamic>{'iceServers': <Object>[]});
    await _connectSocket();
  }

  Future<void> _connectSocket() async {
    final base = api.base;
    final url = base.replace(scheme: base.scheme == 'https' ? 'wss' : 'ws', path: '/rooms/$_roomId/socket');
    try {
      // The room socket checks Origin like the web client's; native sends the server's own origin.
      final socket = await WebSocket.connect(url.toString(), protocols: ['webrtc', _token!], headers: {'Origin': base.origin})
          .timeout(const Duration(seconds: 10));
      _socket = socket;
      _set(CallPhase.waiting, 'Calling $peerName…');
      socket.listen(
        (data) => _queue = _queue.then((_) => _receive(data)).catchError((Object _) => end('Call negotiation failed.')),
        onDone: () {
          if (_socket != socket || !_active) return;
          final code = socket.closeCode;
          _socket = null;
          _closePeer();
          end(switch (code) {
            4002 => '$peerName declined the call.',
            4001 => 'Switched to a new call.',
            _ => 'Call ended.',
          });
        },
      );
    } catch (_) {
      end('Could not reach the call server.');
    }
  }

  Future<void> _receive(Object? raw) async {
    final message = RoomMessage.parse(raw);
    if (message == null) throw const FormatException('Invalid signaling message');
    switch (message) {
      case Welcome(:final polite, :final token):
        _polite = polite;
        _token = token;
      case Ready(:final sessionId):
        await _closePeer();
        _sessionId = sessionId;
        _ready = true;
        await _createPeer();
        _set(CallPhase.connecting, 'Connecting to $peerName…');
      case PeerLeft():
        await _closePeer();
        _set(CallPhase.reconnecting, '$peerName disconnected. Waiting for them to return…');
      case RoomError():
        break;
      case Description(:final type, :final sdp, :final sessionId):
        final pc = _pc;
        if (pc == null || !_ready || sessionId != _sessionId) return;
        final generation = _generation;
        final state = pc.signalingState;
        final collision = type == 'offer' && (_makingOffer || state != RTCSignalingState.RTCSignalingStateStable);
        _ignoreOffer = !_polite && collision;
        if (_ignoreOffer) {
          _pendingCandidates.clear();
          return;
        }
        if (collision) {
          await pc.setLocalDescription(RTCSessionDescription(null, 'rollback'));
        }
        await pc.setRemoteDescription(RTCSessionDescription(sdp, type));
        if (generation != _generation) return;
        final remote = await pc.getRemoteDescription();
        final waiting = List.of(_pendingCandidates);
        _pendingCandidates.clear();
        for (final (candidate, ufrag) in waiting) {
          // A new ICE generation can arrive before its SDP: keep only what matches this one.
          if (matchesGeneration(remote?.sdp, ufrag)) {
            await pc.addCandidate(candidate);
          } else {
            _pendingCandidates.add((candidate, ufrag));
          }
        }
        if (type == 'offer') {
          final answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          if (generation == _generation) _send(describeFrame('answer', answer.sdp!, _sessionId!));
        }
      case Candidate(:final sessionId, :final candidate, :final sdpMid, :final sdpMLineIndex, :final usernameFragment):
        final pc = _pc;
        if (pc == null || !_ready || sessionId != _sessionId || _ignoreOffer || candidate == null) return;
        final ice = RTCIceCandidate(candidate, sdpMid, sdpMLineIndex);
        final remote = await pc.getRemoteDescription();
        if (remote == null || !matchesGeneration(remote.sdp, usernameFragment)) {
          if (_pendingCandidates.length >= 128) throw const FormatException('Too many pending candidates');
          _pendingCandidates.add((ice, usernameFragment));
        } else {
          await pc.addCandidate(ice);
        }
    }
  }

  Future<void> _createPeer() async {
    final pc = await createPeerConnection({...?_ice, 'sdpSemantics': 'unified-plan'});
    _pc = pc;
    final generation = ++_generation;
    for (final track in _local?.getTracks() ?? <MediaStreamTrack>[]) {
      await pc.addTrack(track, _local!);
    }
    pc.onIceCandidate = (candidate) {
      if (_pc != pc) return;
      _send(candidateFrame({
        'candidate': candidate.candidate,
        'sdpMid': candidate.sdpMid,
        'sdpMLineIndex': candidate.sdpMLineIndex,
      }, _sessionId!));
    };
    pc.onTrack = (event) {
      if (_pc != pc || event.streams.isEmpty) return;
      remoteRenderer.srcObject = event.streams.first;
      remoteVideo = event.streams.first.getVideoTracks().isNotEmpty;
      notifyListeners();
    };
    pc.onConnectionState = (state) {
      if (_pc != pc) return;
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        _set(CallPhase.connected, 'Connected — your call is live.');
        _verifyTimer ??= Timer(const Duration(seconds: 15), () {
          if (_pc == pc && verify != VerifyState.ok) _showVerify(VerifyState.warn, 'Could not verify — treat this call as untrusted and end it.');
        });
      } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
          state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _set(CallPhase.reconnecting, 'Connection interrupted. Reconnecting your call…');
        if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed && !_polite) pc.restartIce();
      }
    };
    pc.onRenegotiationNeeded = () async {
      if (!_ready || _pc != pc) return;
      if (_polite && await pc.getRemoteDescription() == null) return;
      try {
        _makingOffer = true;
        final offer = await pc.createOffer();
        if (_pc != pc || generation != _generation) return;
        await pc.setLocalDescription(offer);
        _send(describeFrame('offer', offer.sdp!, _sessionId!));
      } catch (_) {
        end('Could not negotiate this call.');
      } finally {
        _makingOffer = false;
      }
    };
    _attachVerify(pc, await pc.createDataChannel('verify-v1', RTCDataChannelInit()..negotiated = true..id = 1000..ordered = true));
    // The impolite side starts negotiation once its tracks are attached.
    if (!_polite) pc.onRenegotiationNeeded?.call();
  }

  /// verify-v1: commit, reveal after both commitments exist, then derive the code
  /// from both DTLS fingerprints and both nonces. Fails closed on anything unexpected.
  void _attachVerify(RTCPeerConnection pc, RTCDataChannel channel) {
    _showVerify(VerifyState.pending, 'Verifying this call…');
    final mine = crypto.sasCommit();
    String? peerCommit, peerNonce;
    var committed = false, revealed = false, done = false;
    void fail() {
      if (done || _pc != pc) return;
      done = true;
      channel.close();
      _showVerify(VerifyState.warn, 'Verification failed — end the call. Someone may be in the middle.');
    }

    void send(Map<String, String> value) => channel.send(RTCDataChannelMessage(jsonEncode(value)));
    void reveal() {
      if (committed && peerCommit != null && !revealed) {
        revealed = true;
        send({'type': 'reveal', 'nonce': mine.nonce});
      }
    }

    channel.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen && !committed) {
        send({'type': 'commit', 'hash': mine.hash});
        committed = true;
        reveal();
      }
    };
    channel.onMessage = (message) async {
      if (done || _pc != pc) return;
      final packet = message.isBinary ? null : parseVerifyPacket(message.text);
      if (packet == null) return fail();
      if (packet['type'] == 'commit' && peerCommit == null && Sas.isHex64(packet['value'])) {
        peerCommit = packet['value'];
        reveal();
        return;
      }
      if (packet['type'] != 'reveal' || !revealed || peerNonce != null || !crypto.sasCheck(packet['value']!, peerCommit ?? '')) return fail();
      peerNonce = packet['value'];
      try {
        final local = await pc.getLocalDescription(), remote = await pc.getRemoteDescription();
        final code = crypto.sasCode(local?.sdp ?? '', remote?.sdp ?? '', [mine.nonce, peerNonce!]);
        done = true;
        _verifyTimer?.cancel();
        verifyCode = code;
        _showVerify(VerifyState.ok, 'Same code on their screen? No one is listening in.');
      } catch (_) {
        fail();
      }
    };
  }

  void _showVerify(VerifyState state, String label) {
    verify = state;
    verifyLabel = label;
    if (state != VerifyState.ok) verifyCode = '';
    notifyListeners();
  }

  void _send(String frame) {
    if (_socket?.readyState == WebSocket.open) _socket!.add(frame);
  }

  void _set(CallPhase next, String text) {
    phase = next;
    status = text;
    notifyListeners();
  }

  Future<void> toggleMute() async {
    muted = !muted;
    for (final track in _local?.getAudioTracks() ?? <MediaStreamTrack>[]) {
      track.enabled = !muted;
    }
    notifyListeners();
  }

  /// Turns the camera on or off. A call answered audio-only captures the camera
  /// on first use and renegotiates to add the video track.
  Future<void> toggleCamera() async {
    final videos = _local?.getVideoTracks() ?? <MediaStreamTrack>[];
    if (videos.isEmpty) {
      final added = await navigator.mediaDevices.getUserMedia({'audio': false, 'video': {'facingMode': 'user'}});
      final track = added.getVideoTracks().first;
      await _local?.addTrack(track);
      await _pc?.addTrack(track, _local!);
      localRenderer.srcObject = _local;
      hasLocalVideo = true;
      cameraOff = false;
    } else {
      cameraOff = !cameraOff;
      for (final track in videos) {
        track.enabled = !cameraOff;
      }
    }
    notifyListeners();
  }

  Future<void> toggleSpeaker() async {
    speaker = !speaker;
    if (Platform.isAndroid || Platform.isIOS) await Helper.setSpeakerphoneOn(speaker);
    notifyListeners();
  }

  Future<void> _closePeer() async {
    _generation++;
    _verifyTimer?.cancel();
    _verifyTimer = null;
    final pc = _pc;
    _pc = null;
    _sessionId = null;
    _ready = false;
    _pendingCandidates.clear();
    _makingOffer = false;
    _ignoreOffer = false;
    remoteRenderer.srcObject = null;
    remoteVideo = false;
    await pc?.close();
  }

  Future<void> _stopLocal() async {
    for (final track in _local?.getTracks() ?? <MediaStreamTrack>[]) {
      await track.stop();
    }
    await _local?.dispose();
    _local = null;
    localRenderer.srcObject = null;
  }

  /// Hangs up: tells the server to end the room for both sides.
  Future<void> hangUp() async {
    _send(jsonEncode({'type': 'hangup'}));
    await end('Call ended.');
  }

  Future<void> end(String reason) async {
    if (!_active && phase == CallPhase.ended) return;
    _active = false;
    endReason = reason;
    await _closePeer();
    await _stopLocal();
    final socket = _socket;
    _socket = null;
    await socket?.close();
    _set(CallPhase.ended, reason);
  }

  @override
  void dispose() {
    _verifyTimer?.cancel();
    localRenderer.dispose();
    remoteRenderer.dispose();
    super.dispose();
  }
}
