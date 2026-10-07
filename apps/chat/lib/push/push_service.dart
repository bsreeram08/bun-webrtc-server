import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_callkit_incoming/entities/entities.dart';
import 'package:flutter_callkit_incoming/flutter_callkit_incoming.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/api.dart';

/// Push payloads are data-only and never carry message text:
/// `{type: message|call|missed|verify, from, kind?, roomId?, nonce?}`.
class PushData {
  const PushData({required this.type, this.from, this.kind, this.roomId, this.nonce});
  final String type;
  final String? from, kind, roomId, nonce;

  static final _username = RegExp(r'^[a-z0-9_]{3,20}$');

  static PushData? parse(Map<String, dynamic> data) {
    final type = data['type'];
    if (type is! String || !const ['message', 'call', 'missed', 'verify'].contains(type)) return null;
    final from = data['from'];
    if (type != 'verify' && (from is! String || !_username.hasMatch(from))) return null;
    return PushData(type: type, from: from as String?, kind: data['kind'] as String?, roomId: data['roomId'] as String?, nonce: data['nonce'] as String?);
  }
}

const _storage = FlutterSecureStorage();
const _installKey = 'push-install-id-v1', _pendingKey = 'push-pending-v1', _tokenKey = 'session-token-v1';
final _notifications = FlutterLocalNotificationsPlugin();

/// Confirms a `verify` push from any isolate (background handlers run in their own).
Future<void> confirmVerify(PushData push) async {
  final pending = await _storage.read(key: _pendingKey), session = await _storage.read(key: _tokenKey);
  if (pending == null || session == null || push.nonce == null) return;
  final registration = jsonDecode(pending) as Map<String, dynamic>;
  final api = Api()..token = session;
  await api.confirmPush(registration['platform'] as String, registration['token'] as String, push.nonce!);
  await _storage.write(key: '$_pendingKey-confirmed', value: '${registration['platform']}:${registration['token']}');
}

/// Shows the system UI for a push. Message text is never in the payload, so
/// notifications only say who wrote; tapping opens that conversation.
Future<void> presentPush(PushData push) async {
  switch (push.type) {
    case 'verify':
      await confirmVerify(push);
    case 'call':
      // Android: high-priority data message → the ConnectionService full-screen call UI.
      // iOS calls arrive as VoIP pushes and are reported to CallKit natively in AppDelegate.
      if (Platform.isAndroid) {
        await FlutterCallkitIncoming.showCallkitIncoming(
          CallKitParams(
            id: _uuid(),
            nameCaller: push.from,
            handle: push.from,
            appName: 'Private Chat',
            type: push.kind == 'video' ? 1 : 0,
            duration: 45000,
            extra: {'from': push.from, 'kind': push.kind, 'roomId': push.roomId},
            android: const AndroidParams(isCustomNotification: true, isShowFullLockedScreen: true, backgroundColor: '#111820', actionColor: '#a1efce'),
          ),
        );
      }
    case 'missed':
      await _show(push.from.hashCode, 'Missed ${push.kind ?? ''} call', 'From ${push.from}', 'open=${push.from}');
    case 'message':
      await _show(push.from.hashCode, 'New message', 'From ${push.from}', 'open=${push.from}');
  }
}

Future<void> _show(int id, String title, String body, String payload) => _notifications.show(
  id: id,
  title: title,
  body: body,
  payload: payload,
  notificationDetails: const NotificationDetails(
    android: AndroidNotificationDetails('messages', 'Messages', importance: Importance.high, priority: Priority.high),
    iOS: DarwinNotificationDetails(),
    macOS: DarwinNotificationDetails(),
  ),
);

String _uuid() {
  final r = Random.secure(), b = List<int>.generate(16, (_) => r.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final h = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
}

@pragma('vm:entry-point')
Future<void> firebaseBackgroundHandler(RemoteMessage message) async {
  final push = PushData.parse(message.data);
  if (push != null) await presentPush(push);
}

/// Registers this install for push with proof of possession:
/// 1. POST /api/push/native {platform, token, installId};
/// 2. the server sends a silent `verify` push, which [confirmVerify] answers within 2 minutes;
/// 3. only then (iOS) register the `apns-voip` token with the same installId.
/// Retries with backoff (iOS may delay background pushes) and re-registers on token refresh.
class PushService {
  PushService(this.api);
  final Api api;
  final _opens = StreamController<String>.broadcast();
  bool _started = false;

  /// Usernames whose conversation a notification tap asked to open.
  Stream<String> get opens => _opens.stream;

  /// Accept / decline taps on the system call UI (CallKit / ConnectionService).
  Stream<CallEvent?> get callEvents => FlutterCallkitIncoming.onEvent;

  Future<String> installId() async {
    var id = await _storage.read(key: _installKey);
    if (id == null) {
      id = _uuid();
      await _storage.write(key: _installKey, value: id);
    }
    return id;
  }

  Future<void> start() async {
    if (_started || !(Platform.isAndroid || Platform.isIOS)) return;
    _started = true;
    await _notifications.initialize(
      // Permission is requested once below (firebase_messaging), not again here.
      settings: const InitializationSettings(
        android: AndroidInitializationSettings('@mipmap/ic_launcher'),
        iOS: DarwinInitializationSettings(requestAlertPermission: false, requestBadgePermission: false, requestSoundPermission: false),
      ),
      onDidReceiveNotificationResponse: (response) {
        final payload = response.payload ?? '';
        if (payload.startsWith('open=')) _opens.add(payload.substring(5));
      },
    );
    try {
      // google-services.json / GoogleService-Info.plist are not committed: see apps/chat/README.md.
      await Firebase.initializeApp();
    } catch (e) {
      debugPrint('Push disabled: Firebase is not configured ($e)');
      return;
    }
    final messaging = FirebaseMessaging.instance;
    await messaging.requestPermission();
    FirebaseMessaging.onBackgroundMessage(firebaseBackgroundHandler);
    FirebaseMessaging.onMessage.listen((message) {
      final push = PushData.parse(message.data);
      // In the foreground the events socket already delivers messages and calls; only verify matters.
      if (push?.type == 'verify') unawaited(confirmVerify(push!));
    });
    FirebaseMessaging.onMessageOpenedApp.listen((message) {
      final from = message.data['from'];
      if (from is String) _opens.add(from);
    });
    if (Platform.isAndroid) {
      final token = await messaging.getToken();
      if (token != null) unawaited(_register('fcm', token));
      messaging.onTokenRefresh.listen((token) => _register('fcm', token));
    } else {
      String? apns;
      for (var i = 0; i < 10 && apns == null; i++) {
        apns = await messaging.getAPNSToken();
        if (apns == null) await Future<void>.delayed(const Duration(seconds: 2));
      }
      // apns-voip binds only next to a confirmed apns token from the same install.
      if (apns != null && await _register('apns', apns)) await _registerVoip();
    }
  }

  /// 201: bound. 202: the token is bound to another session (reinstall, account switch); the
  /// server sends a VoIP `verify` push, which AppDelegate reports to CallKit as a placeholder,
  /// ends at once, and forwards here as a custom CallKit event with the nonce.
  Future<void> _registerVoip() async {
    final voip = await FlutterCallkitIncoming.getDevicePushTokenVoIP();
    if (voip is! String || voip.isEmpty) return;
    final nonce = Completer<String>();
    final sub = FlutterCallkitIncoming.onEvent.listen((event) {
      if (event is CallEventActionCallCustom && event.body['type'] == 'voip-verify' && event.body['nonce'] is String && !nonce.isCompleted) {
        nonce.complete(event.body['nonce'] as String);
      }
    });
    try {
      if (await api.registerPush('apns-voip', voip, await installId()) == 202) {
        await api.confirmPush('apns-voip', voip, await nonce.future.timeout(const Duration(minutes: 2)));
      }
    } catch (e) {
      debugPrint('VoIP push registration failed: $e');
    } finally {
      await sub.cancel();
    }
  }

  /// Returns true once the server has confirmed possession of [token].
  Future<bool> _register(String platform, String token) async {
    final id = await installId();
    for (var attempt = 0; attempt < 5; attempt++) {
      await _storage.write(key: _pendingKey, value: jsonEncode({'platform': platform, 'token': token}));
      try {
        await api.registerPush(platform, token, id);
      } on ApiException catch (e) {
        if (e.status == 400 || e.status == 401 || e.status == 403) return false;
      } catch (_) {}
      // Wait for the verify push to be confirmed (foreground or background handler).
      for (var i = 0; i < 25; i++) {
        await Future<void>.delayed(const Duration(seconds: 5));
        if (await _storage.read(key: '$_pendingKey-confirmed') == '$platform:$token') return true;
      }
      await Future<void>.delayed(Duration(seconds: 30 * (1 << attempt)));
    }
    return false;
  }
}
