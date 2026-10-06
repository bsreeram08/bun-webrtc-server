import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';

import '../calls/call_controller.dart';
import '../core/api.dart';
import '../core/events.dart';
import '../crypto/chat_crypto.dart';
import '../crypto/rust_chat_crypto.dart';
import '../messaging/messenger.dart';
import '../store/message_store.dart';
import '../theme/theme_prefs.dart';

/// Riverpod: providers make every dependency (API, crypto, storage, passkeys)
/// overridable in tests without a DI framework, and Notifier state rebuilds
/// only the widgets that watch it.

/// Passkey ceremonies, behind an interface so tests and screenshots need no OS prompt.
abstract class PasskeyClient {
  Future<Map<String, dynamic>> register(Map<String, dynamic> options);
  Future<Map<String, dynamic>> authenticate(Map<String, dynamic> options);
}

class PlatformPasskeys implements PasskeyClient {
  final _authenticator = PasskeyAuthenticator();
  @override
  Future<Map<String, dynamic>> register(Map<String, dynamic> options) async =>
      (await _authenticator.register(RegisterRequestType.fromJson(options))).toJson();
  @override
  Future<Map<String, dynamic>> authenticate(Map<String, dynamic> options) async =>
      (await _authenticator.authenticate(AuthenticateRequestType.fromJson(options, preferImmediatelyAvailableCredentials: false))).toJson();
}

/// Bearer token storage (Keychain / Android Keystore).
abstract class TokenStore {
  Future<String?> read();
  Future<void> write(String? token);
}

class SecureTokenStore implements TokenStore {
  static const _key = 'session-token-v1';
  final _storage = const FlutterSecureStorage();
  @override
  Future<String?> read() => _storage.read(key: _key);
  @override
  Future<void> write(String? token) => token == null ? _storage.delete(key: _key) : _storage.write(key: _key, value: token);
}

final apiProvider = Provider<Api>((ref) => Api());

/// Off in tests and the screenshot demo (no OS permission prompts, no Firebase).
final pushEnabledProvider = Provider<bool>((ref) => true);
final passkeysProvider = Provider<PasskeyClient>((ref) => PlatformPasskeys());
final tokenStoreProvider = Provider<TokenStore>((ref) => SecureTokenStore());

/// The Rust core (crates/chatcore) through flutter_rust_bridge. Tests and the demo override this
/// with FakeChatCrypto.
final cryptoProvider = Provider<ChatCrypto>((ref) => RustChatCrypto());

/// Rotation settings for an account on this device (account.js `rotation-*` keys in localStorage).
final rotationPrefsProvider = Provider<Future<RotationPrefs> Function(String userId)>((ref) => (userId) async {
  final prefs = await SharedPreferences.getInstance();
  return SharedRotationPrefs(prefs, userId);
});

class SharedRotationPrefs implements RotationPrefs {
  SharedRotationPrefs(this._prefs, this._user);
  final SharedPreferences _prefs;
  final String _user;
  String get _mineKey => 'rotation-v1:$_user';
  String _peerKey(String id) => 'rotation-peer-v1:$_user:$id';
  String _toldKey(String id) => 'rotation-told-v1:$_user:$id';
  @override
  int get mine => _prefs.getInt(_mineKey) ?? 0;
  @override
  set mine(int value) => _prefs.setInt(_mineKey, value);
  @override
  int peer(String contactId) => _prefs.getInt(_peerKey(contactId)) ?? 0;
  @override
  void setPeer(String contactId, int value) => _prefs.setInt(_peerKey(contactId), value);
  @override
  String? told(String contactId) => _prefs.getString(_toldKey(contactId));
  @override
  void setTold(String contactId, String value) => _prefs.setString(_toldKey(contactId), value);
  @override
  void clearTold() {
    for (final key in _prefs.getKeys().where((k) => k.startsWith('rotation-told-v1:$_user:')).toList()) {
      _prefs.remove(key);
    }
  }
}

/// Opens the per-account message database.
final storeOpenerProvider = Provider<Future<MessageStore> Function(String userId)>((ref) => (userId) async {
  final dir = await getApplicationSupportDirectory();
  return MessageStore.open(databaseFactory, p.join(dir.path, 'messages-$userId.db'));
});

enum AuthPhase { loading, signedOut, signedIn }

@immutable
class IncomingCall {
  const IncomingCall({required this.contact, required this.kind, required this.roomId, required this.token});
  final Contact contact;
  final String kind;
  final String roomId;
  final String token;
}

@immutable
class AppState {
  const AppState({
    this.phase = AuthPhase.loading,
    this.user,
    this.contacts = const [],
    this.unread = const {},
    this.notice,
    this.incoming,
    this.call,
    this.keyChanged = const {},
    this.inactiveDevice = false,
  });
  final AuthPhase phase;
  final User? user;
  final List<Contact> contacts;
  final Map<String, int> unread;
  final String? notice;
  final IncomingCall? incoming;
  final CallController? call;

  /// Contacts whose security code changed and has not been reviewed.
  final Set<String> keyChanged;

  /// Encrypted messaging for this account is active on another device or browser.
  final bool inactiveDevice;

  AppState copyWith({
    AuthPhase? phase,
    User? user,
    List<Contact>? contacts,
    Map<String, int>? unread,
    String? notice,
    bool clearNotice = false,
    IncomingCall? incoming,
    bool clearIncoming = false,
    CallController? call,
    bool clearCall = false,
    Set<String>? keyChanged,
    bool? inactiveDevice,
  }) => AppState(
    phase: phase ?? this.phase,
    user: user ?? this.user,
    contacts: contacts ?? this.contacts,
    unread: unread ?? this.unread,
    notice: clearNotice ? null : notice ?? this.notice,
    incoming: clearIncoming ? null : incoming ?? this.incoming,
    call: clearCall ? null : call ?? this.call,
    keyChanged: keyChanged ?? this.keyChanged,
    inactiveDevice: inactiveDevice ?? this.inactiveDevice,
  );
}

class AppController extends Notifier<AppState> {
  Api get _api => ref.read(apiProvider);
  ChatCrypto get _crypto => ref.read(cryptoProvider);
  EventsClient? _events;
  Messenger? messenger;
  MessageStore? store;
  final _subscriptions = <StreamSubscription<Object?>>[];
  String? viewingContact;
  Timer? _missTimer;

  @override
  AppState build() {
    ref.onDispose(_teardown);
    return const AppState();
  }

  /// Restores a saved session, if any.
  Future<void> restore() async {
    final token = await ref.read(tokenStoreProvider).read();
    if (token == null) {
      state = state.copyWith(phase: AuthPhase.signedOut);
      return;
    }
    _api.token = token;
    try {
      await _signedIn(await _api.me(), token);
    } on ApiException catch (error) {
      if (error.status == 401) await ref.read(tokenStoreProvider).write(null);
      state = state.copyWith(phase: AuthPhase.signedOut, notice: error.status == 401 ? 'Your session ended. Sign in again.' : null);
    } catch (_) {
      state = state.copyWith(phase: AuthPhase.signedOut, notice: 'Could not reach the server. Check your connection.');
    }
  }

  Future<void> signIn() async {
    final flow = await _api.loginOptions();
    final response = await ref.read(passkeysProvider).authenticate(flow.options);
    final result = await _api.loginVerify(flow.flowId, response);
    await _signedIn(result.user, result.token);
  }

  Future<void> register(String invite, String username) async {
    final flow = await _api.registerOptions(invite.trim(), username.trim().toLowerCase());
    final response = await ref.read(passkeysProvider).register(flow.options);
    final result = await _api.registerVerify(flow.flowId, response);
    await _signedIn(result.user, result.token);
  }

  Future<void> _signedIn(User user, String token) async {
    _api.token = token;
    await ref.read(tokenStoreProvider).write(token);
    await ref.read(themePrefsProvider.notifier).load(user.id);
    final dbStore = await ref.read(storeOpenerProvider)(user.id);
    store = dbStore;
    await _crypto.init('keys-${user.id}');
    final events = EventsClient(url: _api.base.replace(scheme: _api.base.scheme == 'https' ? 'wss' : 'ws', path: '/api/events'), token: token);
    _events = events;
    final m = Messenger(
      api: _api,
      crypto: _crypto,
      store: dbStore,
      me: user,
      contactById: contactById,
      mutualContacts: () => state.contacts.where((c) => c.state == ContactState.mutual && c.id != null).toList(),
      ack: events.ack,
      viewing: () => viewingContact,
      rotation: await ref.read(rotationPrefsProvider)(user.id),
    );
    messenger = m;
    _subscriptions
      ..add(events.events.listen(_onEvent))
      ..add(m.notices.listen((text) => state = state.copyWith(notice: text)))
      ..add(m.unreadChanges.listen((unread) => state = state.copyWith(unread: unread)))
      ..add(m.identityChanges.listen((id) => state = state.copyWith(keyChanged: {...state.keyChanged, id})))
      ..add(m.activeChanges.listen((active) => state = state.copyWith(inactiveDevice: !active)));
    state = state.copyWith(phase: AuthPhase.signedIn, user: user, clearNotice: true);
    unawaited(_checkActive());
    await loadContacts();
    unawaited(events.connect());
  }

  Contact? contactById(String id) {
    for (final c in state.contacts) {
      if (c.id == id) return c;
    }
    return null;
  }

  Future<void> loadContacts() async {
    try {
      final online = {for (final c in state.contacts) if (c.online && c.id != null) c.id!};
      final contacts = await _api.contacts();
      state = state.copyWith(contacts: [for (final c in contacts) c.online || online.contains(c.id) ? c.copyWith(online: true) : c]);
      unawaited(messenger?.flush());
    } on ApiException catch (error) {
      if (error.status == 401) await signOut(silent: true);
    } catch (_) {}
  }

  /// Feeds an account event as if it came from the server (tests and the screenshot demo).
  void handleEvent(AccountEvent event) => _onEvent(event);

  void _onEvent(AccountEvent event) {
    switch (event) {
      case Hello(:final online):
        state = state.copyWith(contacts: [for (final c in state.contacts) c.copyWith(online: online.contains(c.id))]);
        unawaited(_checkActive());
      case Presence(:final id, :final online):
        state = state.copyWith(contacts: [for (final c in state.contacts) c.id == id ? c.copyWith(online: online) : c]);
      case ContactsChanged():
        unawaited(loadContacts());
      case KeysChanged(:final id):
        // Our own id: another device may have taken over this account's encryption.
        unawaited(id == state.user?.id ? _checkActive() : _checkIdentity(id));
      case EnvelopeEvent():
        unawaited(messenger?.receive(event));
      case Incoming():
        _incoming(event);
      case Ended(:final roomId):
        final ring = state.incoming;
        if (ring?.roomId == roomId) {
          state = state.copyWith(clearIncoming: true, notice: 'Missed ${ring!.kind} call from ${ring.contact.username}');
        }
      case SignedOutEvent():
        unawaited(signOut(silent: true, message: 'Your session ended. Sign in again.'));
    }
  }

  Future<void> _checkActive() async {
    try {
      final active = await messenger?.checkActive();
      if (active != null) state = state.copyWith(inactiveDevice: !active);
    } catch (e) {
      state = state.copyWith(notice: 'Could not check encryption keys: $e');
    }
  }

  /// Conversation ⋯ → Reset secure session.
  Future<void> resetSession(Contact contact) async => messenger!.resetSession(contact);

  /// Settings → Security: this device's rotation interval (ms, 0 = off).
  Future<void> setRotation(int value) async => messenger?.setMyRotation(value);

  /// Settings → Security: new identity keys (explicit; contacts see a security-code change).
  Future<void> regenerateIdentity() async {
    await messenger?.regenerateIdentity();
    state = state.copyWith(inactiveDevice: false);
  }

  /// "Use this device instead": only ever from the user's tap.
  Future<void> useThisDevice() async {
    await messenger?.takeOver();
    state = state.copyWith(inactiveDevice: false);
  }

  Future<void> _checkIdentity(String contactId) async {
    final contact = contactById(contactId);
    if (contact == null) return;
    try {
      final identity = Identity.fromJson(await _api.publishedIdentity(contact.username));
      await _crypto.notePeer(contactId, identity);
      final safety = await _crypto.safety(state.user!.username, contactId, contact.username);
      if (safety != null && (safety.changed || safety.blocked)) state = state.copyWith(keyChanged: {...state.keyChanged, contactId});
      unawaited(messenger?.flush());
    } catch (_) {}
  }

  // ---------- Calls ----------
  void _incoming(Incoming event) {
    // Contact chats use the encrypted mailbox; only calls ring.
    if (event.kind == 'chat') return;
    final contact = contactById(event.fromId) ?? Contact(id: event.fromId, username: event.fromUsername, state: ContactState.mutual, online: true);
    state = state.copyWith(incoming: IncomingCall(contact: contact, kind: event.kind, roomId: event.roomId, token: event.token));
    _events?.ringing(event.roomId);
    _missTimer?.cancel();
    _missTimer = Timer(const Duration(seconds: 45), () {
      if (state.incoming?.roomId == event.roomId) {
        state = state.copyWith(clearIncoming: true, notice: 'Missed ${event.kind} call from ${contact.username}');
      }
    });
  }

  /// Nothing captures media until this runs from an Accept tap.
  Future<CallController?> accept({required bool audioOnly}) async {
    final ring = state.incoming;
    if (ring == null) return null;
    _missTimer?.cancel();
    state = state.copyWith(clearIncoming: true);
    return _startCall(ring.contact, ring.kind, ring.roomId, ring.token, audioOnly: audioOnly);
  }

  Future<void> decline() async {
    final ring = state.incoming;
    _missTimer?.cancel();
    state = state.copyWith(clearIncoming: true);
    if (ring != null) {
      try {
        await _api.decline(ring.contact.username, ring.roomId);
      } catch (_) {}
    }
  }

  Future<CallController?> call(Contact contact, String kind) async {
    final session = await _api.session(contact.username, kind);
    return _startCall(contact, kind, session.roomId, session.token);
  }

  Future<CallController> _startCall(Contact contact, String kind, String roomId, String token, {bool audioOnly = false}) async {
    await state.call?.end('Switched to a new call.');
    final controller = CallController(api: _api, crypto: _crypto, peerName: contact.username);
    state = state.copyWith(call: controller);
    unawaited(controller.start(roomId: roomId, token: token, kind: kind, audioOnly: audioOnly));
    return controller;
  }

  void callFinished() {
    state.call?.dispose();
    state = state.copyWith(clearCall: true);
  }

  // ---------- Contacts, invites, safety ----------
  Future<void> addContact(String username) async {
    await _api.requestContact(username.trim().toLowerCase());
    state = state.copyWith(notice: 'Request sent to @${username.trim().toLowerCase()}. They appear in your chats once they accept.');
    await loadContacts();
  }

  Future<void> acceptContact(Contact c) async {
    await _api.acceptContact(c.username);
    await loadContacts();
  }

  Future<void> removeContact(Contact c) async {
    await _api.removeContact(c.username);
    await loadContacts();
  }

  Future<({String link, int expiresAt})> createInvite() async {
    final invite = await _api.createInvite();
    return (link: _api.base.replace(fragment: 'invite=${invite.code}').toString(), expiresAt: invite.expiresAt);
  }

  Future<void> reviewedKey(String contactId, {required bool verified}) async {
    if (verified) {
      await _crypto.setVerified(contactId, true);
    } else {
      await _crypto.acceptChange(contactId);
    }
    state = state.copyWith(keyChanged: {...state.keyChanged}..remove(contactId));
    unawaited(messenger?.flush());
  }

  void dismissNotice() => state = state.copyWith(clearNotice: true);

  void openConversation(String contactId) {
    viewingContact = contactId;
    messenger?.markRead(contactId);
  }

  void closeConversation() => viewingContact = null;

  // ---------- Sign out ----------
  Future<void> signOut({bool everywhere = false, bool silent = false, String? message}) async {
    if (!silent) {
      try {
        await _api.logout(everywhere: everywhere);
      } catch (_) {}
    }
    await _teardown();
    await ref.read(tokenStoreProvider).write(null);
    _api.token = null;
    state = AppState(phase: AuthPhase.signedOut, notice: message ?? (everywhere ? 'Signed out on every device.' : 'Signed out.'));
  }

  Future<void> _teardown() async {
    _missTimer?.cancel();
    for (final s in _subscriptions) {
      await s.cancel();
    }
    _subscriptions.clear();
    await _events?.close();
    _events = null;
    await state.call?.end('Signed out.');
    await messenger?.dispose();
    messenger = null;
    await store?.close();
    store = null;
  }
}

final appProvider = NotifierProvider<AppController, AppState>(AppController.new);
