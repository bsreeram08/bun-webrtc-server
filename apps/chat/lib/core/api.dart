import 'dart:async';
import 'dart:convert';

import 'dart:io' show Platform;

import 'package:http/http.dart' as http;

/// Server base URL. Override with `--dart-define=BASE_URL=http://10.0.2.2:3000`.
const defaultBaseUrl = String.fromEnvironment('BASE_URL', defaultValue: 'https://calls.sreerams.in');

class User {
  const User({required this.id, required this.username});
  final String id;
  final String username;
  factory User.fromJson(Map<String, dynamic> json) => User(id: json['id'] as String, username: json['username'] as String);
}

enum ContactState { mutual, incoming, outgoing }

class Contact {
  const Contact({required this.id, required this.username, required this.state, this.online = false});
  final String? id;
  final String username;
  final ContactState state;
  final bool online;

  Contact copyWith({bool? online}) => Contact(id: id, username: username, state: state, online: online ?? this.online);

  factory Contact.fromJson(Map<String, dynamic> json) => Contact(
    id: json['id'] as String?,
    username: json['username'] as String,
    state: ContactState.values.byName(json['state'] as String),
    online: json['online'] as bool? ?? false,
  );
}

class ApiException implements Exception {
  const ApiException(this.message, this.status);
  final String message;
  final int status;
  @override
  String toString() => message;
}

/// The native client name the server expects in passkey ceremonies.
String nativeClient() => Platform.isIOS
    ? 'ios'
    : Platform.isAndroid
    ? 'android'
    : Platform.isMacOS
    ? 'macos'
    : Platform.isWindows
    ? 'windows'
    : 'linux';

/// The account API (`/api/*`). Native clients authenticate with a bearer
/// session token and must send NO Origin header (a bearer request with an
/// Origin is rejected). The token comes from the passkey `verify` response
/// (`{user, session: {token, expiresAt}}`) when the ceremony declares its
/// native `client`; native never receives a cookie.
class Api {
  Api({String baseUrl = defaultBaseUrl, http.Client? client, String? clientName})
    : base = Uri.parse(baseUrl),
      _client = client ?? http.Client(),
      _clientName = clientName; // ignore: prefer_initializing_formals

  final Uri base;
  final http.Client _client;
  final String? _clientName;
  String? token;

  /// HTTP status of the most recent [call] (e.g. 201 bound vs 202 pending push verification).
  int lastStatus = 0;
  String get client => _clientName ?? nativeClient();

  Uri uri(String path) => base.resolve(path);

  Future<Map<String, dynamic>> call(String path, {String method = 'GET', Object? body}) async {
    final request = http.Request(method, uri(path))..headers['Accept'] = 'application/json';
    if (token != null) request.headers['Authorization'] = 'Bearer $token';
    if (body != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(body);
    }
    final response = await http.Response.fromStream(await _client.send(request).timeout(const Duration(seconds: 15)));
    lastStatus = response.statusCode;
    Map<String, dynamic> data = const {};
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) data = decoded;
    } catch (_) {}
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ApiException(data['error'] as String? ?? 'Something went wrong. Try again.', response.statusCode);
    }
    return data;
  }

  // ---- Passkeys ----
  Future<({String flowId, Map<String, dynamic> options})> loginOptions() async {
    final data = await call('/api/login/options', method: 'POST', body: {'client': client});
    return (flowId: data['flowId'] as String, options: data['options'] as Map<String, dynamic>);
  }

  Future<({User user, String token})> loginVerify(String flowId, Map<String, dynamic> response) async =>
      _session(await call('/api/login/verify', method: 'POST', body: {'flowId': flowId, 'response': response, 'client': client}));

  ({User user, String token}) _session(Map<String, dynamic> data) =>
      (user: User.fromJson(data['user'] as Map<String, dynamic>), token: (data['session'] as Map<String, dynamic>)['token'] as String);

  Future<({String flowId, Map<String, dynamic> options})> registerOptions(String invite, String username) async {
    final data = await call('/api/register/options', method: 'POST', body: {'invite': invite, 'username': username, 'client': client});
    return (flowId: data['flowId'] as String, options: data['options'] as Map<String, dynamic>);
  }

  Future<({User user, String token})> registerVerify(String flowId, Map<String, dynamic> response) async =>
      _session(await call('/api/register/verify', method: 'POST', body: {'flowId': flowId, 'response': response, 'client': client}));

  Future<User> me() async => User.fromJson((await call('/api/me'))['user'] as Map<String, dynamic>);
  Future<void> logout({bool everywhere = false}) => call(everywhere ? '/api/logout?all=1' : '/api/logout', method: 'POST', body: const {});

  // ---- Contacts and invites ----
  Future<List<Contact>> contacts() async =>
      ((await call('/api/contacts'))['contacts'] as List).cast<Map<String, dynamic>>().map(Contact.fromJson).toList();
  Future<void> requestContact(String username) => call('/api/contacts', method: 'POST', body: {'username': username});
  Future<void> acceptContact(String username) => call('/api/contacts/$username/accept', method: 'POST', body: const {});
  Future<void> removeContact(String username) => call('/api/contacts/$username', method: 'DELETE');
  Future<({String code, int expiresAt})> createInvite() async {
    final data = await call('/api/invites', method: 'POST', body: const {});
    return (code: data['code'] as String, expiresAt: data['expiresAt'] as int);
  }

  // ---- Keys and mailbox ----
  /// [identity] is the account's currently published identity (null before the first upload).
  Future<({int oneTimePreKeys, int? signedPreKeyId, Map<String, dynamic>? identity})> keyCount() async {
    final data = await call('/api/keys/count');
    return (
      oneTimePreKeys: data['oneTimePreKeys'] as int,
      signedPreKeyId: data['signedPreKeyId'] as int?,
      identity: data['identity'] as Map<String, dynamic>?,
    );
  }

  Future<void> uploadKeys(Map<String, dynamic> upload) => call('/api/keys', method: 'PUT', body: upload);
  Future<String> bundleJson(String username) async => jsonEncode(await call('/api/keys/$username'));
  Future<Map<String, dynamic>> publishedIdentity(String username) async =>
      (await call('/api/keys/$username/identity'))['identity'] as Map<String, dynamic>;
  Future<void> postEnvelope(String username, String envelope) =>
      call('/api/messages', method: 'POST', body: {'to': username, 'envelope': envelope});

  // ---- Calls ----
  Future<({String roomId, String token})> session(String username, String kind) async {
    final data = await call('/api/conversations/$username/session', method: 'POST', body: {'kind': kind});
    return (roomId: data['roomId'] as String, token: data['token'] as String);
  }

  Future<void> decline(String username, String roomId) =>
      call('/api/conversations/$username/decline', method: 'POST', body: {'roomId': roomId});

  /// Room ICE uses the room participant credential (not the account session) and,
  /// like the room socket, the server's own Origin.
  Future<Map<String, dynamic>> ice(String roomId, String roomToken) async {
    final response = await _client.get(uri('/rooms/$roomId/ice'), headers: {'Authorization': 'Bearer $roomToken', 'Origin': base.origin});
    if (response.statusCode != 200) throw ApiException('Call ended or credentials expired.', response.statusCode);
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  // ---- Push (proof of possession) ----
  /// Step 1: the server answers with a silent `{type: verify, nonce}` push to [pushToken].
  /// Returns the HTTP status: for `apns-voip`, 201 bound directly and 202 means a
  /// VoIP `verify` push is on its way and must be confirmed.
  Future<int> registerPush(String platform, String pushToken, String installId) async {
    await call('/api/push/native', method: 'POST', body: {'platform': platform, 'token': pushToken, 'installId': installId});
    return lastStatus;
  }

  /// Step 2, within 2 minutes of the verify push.
  Future<void> confirmPush(String platform, String pushToken, String nonce) =>
      call('/api/push/native/confirm', method: 'POST', body: {'platform': platform, 'token': pushToken, 'nonce': nonce});

  /// `{api, minClient: {...}}`: show "update required" when this build is older.
  Future<Map<String, dynamic>> version() => call('/api/version');
}
