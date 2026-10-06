/// The end-to-end encryption boundary of the app.
///
/// The real implementation is `crates/chatcore` (a Rust port of the web
/// client's signal.js and verify.js) exposed through flutter_rust_bridge.
/// Everything above this interface treats envelopes as opaque strings, so the
/// Rust core and the web client stay the single source of truth for the
/// protocol. [FakeChatCrypto] implements the same contract for tests and UI work.
library;

/// A contact's long-term identity: X25519 (`dh`) and Ed25519 (`sign`) public
/// keys, base64url, exactly as the server publishes them.
class Identity {
  const Identity({required this.dh, required this.sign});
  final String dh;
  final String sign;

  factory Identity.fromJson(Map<String, dynamic> json) =>
      Identity(dh: json['dh'] as String, sign: json['sign'] as String);
  Map<String, dynamic> toJson() => {'dh': dh, 'sign': sign};

  @override
  bool operator ==(Object other) =>
      other is Identity && other.dh == dh && other.sign == sign;
  @override
  int get hashCode => Object.hash(dh, sign);
}

/// What to upload with `PUT /api/keys` after [ChatCrypto.preparePrekeys].
class PrekeyUpload {
  const PrekeyUpload({
    required this.identity,
    required this.signedPreKey,
    required this.rotated,
    this.oneTimePreKeys,
  });
  final Identity identity;
  final Map<String, dynamic> signedPreKey;
  final bool rotated;
  final List<Map<String, dynamic>>? oneTimePreKeys;

  Map<String, dynamic> toJson() => {
    'identity': identity.toJson(),
    'signedPreKey': signedPreKey,
    'oneTimePreKeys': ?oneTimePreKeys,
  };
}

/// Result of [ChatCrypto.encryptTo].
sealed class EncryptResult {
  const EncryptResult();
}

/// Ready to post to `/api/messages`.
class Encrypted extends EncryptResult {
  const Encrypted(this.envelope);
  final String envelope;
}

/// No usable session: fetch `GET /api/keys/:username` and call again with it.
class NeedsBundle extends EncryptResult {
  const NeedsBundle();
}

/// The contact's security code changed and the user has not accepted it.
/// Nothing may be encrypted to the new identity until [ChatCrypto.acceptChange].
class IdentityBlocked extends EncryptResult {
  const IdentityBlocked();
}

/// Result of [ChatCrypto.decryptFrom]. The ratchet does not advance until
/// [ChatCrypto.commit] is called with [commitId], after the plaintext is
/// stored, so a crash between the two re-delivers the envelope instead of
/// losing it.
class Decrypted {
  const Decrypted({
    required this.plaintextJson,
    required this.commitId,
    this.identityChanged = false,
    this.firstContact = false,
    this.identity,
  });
  final String plaintextJson;
  final String commitId;
  final bool identityChanged;
  final bool firstContact;

  /// Set for a message that opened a new session: the identity it claims.
  final Identity? identity;
}

/// A decryption failure. [code] uses the same vocabulary as the web client
/// (`replay`, `malformed`, `auth`, `skip-limit`, `unknown-session`,
/// `unknown-spk`, `claim-limit`, `storage`, ...) so [inboundDisposition]
/// classifies it identically. An uncoded error is retried, never discarded.
class CryptoException implements Exception {
  const CryptoException(this.message, {this.code});
  final String message;
  final String? code;
  @override
  String toString() => message;
}

class SafetyNumber {
  const SafetyNumber({
    required this.number,
    required this.verified,
    required this.changed,
    required this.blocked,
  });

  /// 60 digits in 12 groups of 5, separated by spaces.
  final String number;
  final bool verified;
  final bool changed;
  final bool blocked;
}

/// One side of the call verification exchange (verify-v1, commit then reveal).
class SasCommitment {
  const SasCommitment({required this.nonce, required this.hash});

  /// 64 lowercase hex characters; revealed only after the peer has committed.
  final String nonce;

  /// SHA-256 of [nonce], 64 lowercase hex characters.
  final String hash;
}

abstract class ChatCrypto {
  /// Opens (or creates) the key store for the signed-in account.
  Future<void> init(String dbPath);

  Future<Identity> identity();

  /// Rotates the signed prekey weekly and tops up one-time prekeys.
  /// [oneTimeOnServer] is `GET /api/keys/count`'s `oneTimePreKeys`.
  Future<PrekeyUpload> preparePrekeys(DateTime now, {required int oneTimeOnServer});

  /// [plaintextJson] is the inner payload, e.g.
  /// `{"v":1,"type":"message","id":...,"text":...,"createdAt":...,"expiresAt":...}`.
  Future<EncryptResult> encryptTo(
    String contactId,
    String plaintextJson, {
    String? bundleJson,
  });

  /// Throws [CryptoException] for anything it cannot decrypt.
  /// [publishedIdentity] is the server's published identity for the sender,
  /// used as defence in depth only (the pinned identity is the trust boundary).
  Future<Decrypted> decryptFrom(
    String contactId,
    String envelope, {
    Identity? publishedIdentity,
  });

  /// Advances the ratchet for a decrypted message once it has been stored.
  Future<void> commit(String commitId);

  /// Records an identity seen from the server (key-change events). A
  /// different identity than the pinned one is flagged and blocks sending.
  Future<void> notePeer(String contactId, Identity identity);

  Future<SafetyNumber?> safety(
    String myUsername,
    String contactId,
    String theirUsername,
  );
  Future<void> setVerified(String contactId, bool verified);
  Future<void> acceptChange(String contactId);

  // ---- Call verification (verify-v1) ----
  SasCommitment sasCommit();
  bool sasCheck(String nonce, String hash);

  /// Six digits as "123 456". Throws [CryptoException] unless each SDP has
  /// exactly one canonical `a=fingerprint:sha-256` line (fails closed).
  String sasCode(String localSdp, String remoteSdp, List<String> nonces);
}
