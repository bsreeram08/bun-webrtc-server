import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

import 'chat_crypto.dart';
import 'sas.dart';

/// Test and UI stand-in for the Rust core. It does NOT encrypt: envelopes are
/// base64url JSON. It does model the trust rules the UI depends on (pinned
/// identity, changed/blocked state, verified flag) and implements the call
/// verification code exactly like verify.js, so it is interoperable there.
class FakeChatCrypto implements ChatCrypto {
  FakeChatCrypto({this.me = const Identity(dh: 'fake-dh', sign: 'fake-sign')});

  Identity me;
  final Map<String, SessionInfo> sessions = {};
  final List<String> rotations = [];
  final List<String> rotateCommits = [];
  final Map<String, _Peer> _peers = {};
  final Map<String, String> _pending = {};
  final Set<String> committed = {};
  final Random _random = Random.secure();

  /// Tests: make the next [init] fail as a locked key database.
  bool locked = false;

  @override
  Future<void> init(String dbPath) async {
    if (locked) throw const CryptoException('key database could not be unlocked', code: 'storage', keysLocked: true);
  }

  @override
  Future<void> resetLocal(String dbPath) async {
    locked = false;
    me = Identity(dh: 'fake-dh-${_random.nextInt(1 << 31)}', sign: 'fake-sign');
  }

  @override
  Future<Identity> identity() async => me;

  @override
  Future<PrekeyUpload> preparePrekeys(DateTime now, {required int oneTimeOnServer}) async =>
      PrekeyUpload(
        identity: me,
        signedPreKey: const {'id': 1, 'key': 'spk', 'signature': 'sig'},
        rotated: false,
        oneTimePreKeys: oneTimeOnServer < 20
            ? [for (var i = 0; i < 100 - oneTimeOnServer; i++) {'id': i + 1, 'key': 'opk$i'}]
            : null,
      );

  @override
  Future<EncryptResult> encryptTo(String contactId, String plaintextJson, {String? bundleJson}) async {
    final peer = _peers[contactId];
    if (peer == null) {
      if (bundleJson == null) return const NeedsBundle();
      final bundle = jsonDecode(bundleJson) as Map<String, dynamic>;
      await notePeer(contactId, Identity.fromJson(bundle['identity'] as Map<String, dynamic>));
    }
    if (_peers[contactId]!.blocked) return const IdentityBlocked();
    sessions.putIfAbsent(contactId, () => SessionInfo(sid: 'sent-$contactId', startedAt: DateTime.now().millisecondsSinceEpoch));
    return Encrypted(base64Url.encode(utf8.encode(jsonEncode({'fake': 1, 'from': me.toJson(), 'p': plaintextJson}))).replaceAll('=', ''));
  }

  /// Tests: decryption fails as a locked key database (core `storage`).
  bool lockDecrypt = false;

  @override
  Future<Decrypted> decryptFrom(String contactId, String envelope, {Identity? publishedIdentity}) async {
    if (lockDecrypt) throw const CryptoException('key database could not be unlocked', code: 'storage', keysLocked: true);
    Map<String, dynamic> outer;
    try {
      outer = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(envelope)))) as Map<String, dynamic>;
    } catch (_) {
      throw const CryptoException('Malformed envelope', code: 'malformed');
    }
    final claimed = Identity.fromJson(outer['from'] as Map<String, dynamic>);
    final known = _peers[contactId];
    final changed = known != null && known.identity != claimed;
    if (known == null) _peers[contactId] = _Peer(claimed);
    if (changed) {
      known.identity = claimed;
      known.changed = true;
      known.blocked = true;
      known.verified = false;
    }
    final id = 'c${_random.nextInt(1 << 31)}';
    _pending[id] = contactId;
    return Decrypted(
      plaintextJson: outer['p'] as String,
      commitId: id,
      identityChanged: changed,
      firstContact: known == null,
      identity: claimed,
    );
  }

  @override
  Future<void> commit(String commitId, {bool rotate = false}) async {
    final contact = _pending.remove(commitId);
    if (contact == null) return;
    committed.add(commitId);
    sessions.putIfAbsent(contact, () => SessionInfo(sid: 's$commitId', startedAt: DateTime.now().millisecondsSinceEpoch));
    if (rotate) rotateCommits.add(commitId);
  }

  @override
  Future<void> abort(String commitId) async => _pending.remove(commitId);

  @override
  Future<void> rotate(String contactId) async {
    rotations.add(contactId);
    sessions[contactId] = SessionInfo(sid: 'r${rotations.length}', startedAt: DateTime.now().millisecondsSinceEpoch);
  }

  @override
  Future<SessionInfo?> sessionInfo(String contactId) async => sessions[contactId];

  @override
  Future<void> resetIdentity() async {
    me = Identity(dh: 'fake-dh-${_random.nextInt(1 << 31)}', sign: 'fake-sign');
    sessions.clear();
  }

  @override
  Future<void> notePeer(String contactId, Identity identity) async {
    final known = _peers[contactId];
    if (known == null) {
      _peers[contactId] = _Peer(identity);
    } else if (known.identity != identity) {
      known
        ..identity = identity
        ..changed = true
        ..blocked = true
        ..verified = false;
    }
  }

  @override
  Future<SafetyNumber?> safety(String myUsername, String contactId, String theirUsername) async {
    final peer = _peers[contactId];
    if (peer == null) return null;
    final parts = [
      '$myUsername:${me.dh}:${me.sign}',
      '$theirUsername:${peer.identity.dh}:${peer.identity.sign}',
    ]..sort();
    final digest = sha512.convert(utf8.encode(parts.join('|'))).bytes;
    final groups = [
      for (var i = 0; i < 12; i++)
        ((digest[i * 5] << 32 | digest[i * 5 + 1] << 24 | digest[i * 5 + 2] << 16 | digest[i * 5 + 3] << 8 | digest[i * 5 + 4]) % 100000)
            .toString()
            .padLeft(5, '0'),
    ];
    return SafetyNumber(number: groups.join(' '), verified: peer.verified, changed: peer.changed, blocked: peer.blocked);
  }

  @override
  Future<void> setVerified(String contactId, bool verified) async {
    final peer = _peers[contactId];
    if (peer == null) return;
    peer
      ..verified = verified
      ..changed = verified ? false : peer.changed
      ..blocked = false;
  }

  @override
  Future<void> acceptChange(String contactId) async {
    final peer = _peers[contactId];
    if (peer == null) return;
    peer
      ..changed = false
      ..blocked = false;
  }

  @override
  SasCommitment sasCommit() => Sas.commit(_random);

  @override
  bool sasCheck(String nonce, String hash) => Sas.check(nonce, hash);

  @override
  String sasCode(String localSdp, String remoteSdp, List<String> nonces) =>
      Sas.code(localSdp, remoteSdp, nonces);
}

class _Peer {
  _Peer(this.identity);
  Identity identity;
  bool changed = false;
  bool blocked = false;
  bool verified = false;
}
