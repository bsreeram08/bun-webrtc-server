import 'dart:convert';
import 'dart:math';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../src/rust/api.dart' as core;
import '../src/rust/frb_generated.dart';
import 'chat_crypto.dart';

/// The real end-to-end encryption: `crates/chatcore` (Rust port of signal.js / verify.js, checked
/// against them by `bun run test:interop`) through flutter_rust_bridge.
///
/// The key database lives in the app support directory and is sealed (AES-256-GCM) with a random
/// 32-byte store key held in the platform keystore (Keychain / Android Keystore). The core fails
/// closed: a missing or wrong store key is a `storage` error, never silently new keys.
class RustChatCrypto implements ChatCrypto {
  RustChatCrypto({Future<String> Function()? directory, StoreKeys? storeKeys, this.externalLibrary})
    : _directory = directory ?? (() async => (await getApplicationSupportDirectory()).path),
      _storeKeys = storeKeys ?? SecureStoreKeys();

  final Future<String> Function() _directory;
  final StoreKeys _storeKeys;

  /// Tests on the host load the dylib built by `cargo build` in `rust/`.
  final ExternalLibrary? externalLibrary;
  static Future<void>? _loaded;

  Future<T> _call<T>(Future<T> Function() work) async {
    try {
      return await work();
    } on core.CoreError catch (error) {
      throw CryptoException(error.message, code: error.code);
    }
  }

  T _sync<T>(T Function() work) {
    try {
      return work();
    } on core.CoreError catch (error) {
      throw CryptoException(error.message, code: error.code);
    }
  }

  @override
  Future<void> init(String name) async {
    await (_loaded ??= RustLib.init(externalLibrary: externalLibrary));
    final path = p.join(await _directory(), '$name.sqlite');
    final key = await _storeKeys.keyFor(name);
    await _call(() => core.init(dbPath: path, storeKey: key));
  }

  @override
  Future<Identity> identity() => _call(() async {
    final id = await core.identity();
    return Identity(dh: id.dh, sign: id.sign);
  });

  @override
  Future<PrekeyUpload> preparePrekeys(DateTime now, {required int oneTimeOnServer}) => _call(() async {
    final keys = jsonDecode(await core.preparePrekeys(nowMs: BigInt.from(now.millisecondsSinceEpoch))) as Map<String, dynamic>;
    List<Map<String, dynamic>>? oneTime;
    if (oneTimeOnServer < 20) {
      final count = 100 - min(oneTimeOnServer, 100);
      oneTime = (jsonDecode(await core.oneTimePrekeys(count: BigInt.from(count == 0 ? 100 : count))) as List).cast<Map<String, dynamic>>();
    }
    return PrekeyUpload(
      identity: Identity.fromJson(keys['identity'] as Map<String, dynamic>),
      signedPreKey: keys['signedPreKey'] as Map<String, dynamic>,
      rotated: keys['rotated'] as bool,
      oneTimePreKeys: oneTime,
    );
  });

  @override
  Future<EncryptResult> encryptTo(String contactId, String plaintextJson, {String? bundleJson}) async {
    try {
      final envelope = await core.encryptTo(contactId: contactId, plaintextJson: plaintextJson, bundleJson: bundleJson);
      return envelope == null ? const NeedsBundle() : Encrypted(envelope);
    } on core.CoreError catch (error) {
      if (error.code == 'identity-blocked') return const IdentityBlocked();
      throw CryptoException(error.message, code: error.code);
    }
  }

  @override
  Future<Decrypted> decryptFrom(String contactId, String envelope, {Identity? publishedIdentity}) => _call(() async {
    final result = await core.decryptFrom(
      contactId: contactId,
      envelope: envelope,
      publishedIdentity: publishedIdentity == null ? null : core.Identity(dh: publishedIdentity.dh, sign: publishedIdentity.sign),
    );
    final claimed = result.identity;
    return Decrypted(
      plaintextJson: result.plaintextJson,
      commitId: result.pendingId,
      identityChanged: result.identityChanged,
      firstContact: result.firstContact,
      identity: claimed == null ? null : Identity(dh: claimed.dh, sign: claimed.sign),
    );
  });

  @override
  Future<void> commit(String commitId, {bool rotate = false}) => _call(() => core.commit(pendingId: commitId, rotate: rotate));

  @override
  Future<void> abort(String commitId) => _call(() => core.abort(pendingId: commitId));

  @override
  Future<void> notePeer(String contactId, Identity identity) =>
      _call(() => core.notePeer(contactId: contactId, identity: core.Identity(dh: identity.dh, sign: identity.sign)));

  @override
  Future<SafetyNumber?> safety(String myUsername, String contactId, String theirUsername) => _call(() async {
    final value = await core.safety(myUsername: myUsername, contactId: contactId, theirUsername: theirUsername);
    return value == null ? null : SafetyNumber(number: value.number, verified: value.verified, changed: value.changed, blocked: value.blocked);
  });

  @override
  Future<void> setVerified(String contactId, bool verified) => _call(() => core.setVerified(contactId: contactId, verified: verified));

  @override
  Future<void> acceptChange(String contactId) => _call(() => core.acceptChange(contactId: contactId));

  @override
  Future<void> rotate(String contactId) => _call(() => core.rotate(contactId: contactId));

  @override
  Future<SessionInfo?> sessionInfo(String contactId) => _call(() async {
    final info = await core.sessionInfo(contactId: contactId);
    return info == null ? null : SessionInfo(sid: info.sid, startedAt: info.startedAt.toInt());
  });

  @override
  Future<void> resetIdentity() => _call(core.resetIdentity);

  @override
  SasCommitment sasCommit() => _sync(() {
    final nonce = core.sasNewNonce();
    return SasCommitment(nonce: nonce, hash: core.sasCommitment(nonce: nonce));
  });

  @override
  bool sasCheck(String nonce, String hash) => core.sasCheckReveal(peerCommitment: hash, peerNonce: nonce);

  @override
  String sasCode(String localSdp, String remoteSdp, List<String> nonces) {
    if (nonces.length != 2) throw const CryptoException('Two nonces are required', code: 'invalid');
    return _sync(() => core.sasCode(localSdp: localSdp, remoteSdp: remoteSdp, myNonce: nonces[0], peerNonce: nonces[1]));
  }
}

/// Where the per-account store key lives.
abstract class StoreKeys {
  Future<List<int>> keyFor(String account);
}

/// 32 random bytes per account in the platform keystore, created on first use.
class SecureStoreKeys implements StoreKeys {
  final _storage = const FlutterSecureStorage();
  @override
  Future<List<int>> keyFor(String account) async {
    final name = 'chatcore-store-key-v1:$account';
    final saved = await _storage.read(key: name);
    if (saved != null) return base64Url.decode(saved);
    final random = Random.secure();
    final key = List<int>.generate(32, (_) => random.nextInt(256));
    await _storage.write(key: name, value: base64Url.encode(key));
    return key;
  }
}
