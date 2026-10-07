import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'chat_crypto.dart';

/// verify.js in Dart: the call verification code. A relay that terminates
/// DTLS on each side sees different fingerprints per leg, and commit-then-reveal
/// stops it choosing a nonce after seeing ours, so its two codes match only by
/// chance (1 in 1,000,000). Used by [FakeChatCrypto]; the Rust core provides the
/// same functions for production and the two must agree byte for byte.
abstract final class Sas {
  static const label = 'webrtc-bun-sas-v1';
  static final _hex64 = RegExp(r'^[0-9a-f]{64}$');
  static final _line = RegExp(r'^a=fingerprint:sha-256 ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){31})$');

  static String _hex(List<int> bytes) => bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  static String _sha256Hex(String text) => _hex(sha256.convert(utf8.encode(text)).bytes);

  static SasCommitment commit(Random random) {
    final nonce = _hex(List<int>.generate(32, (_) => random.nextInt(256)));
    return SasCommitment(nonce: nonce, hash: _sha256Hex(nonce));
  }

  static bool isHex64(Object? value) => value is String && _hex64.hasMatch(value);

  static bool check(String nonce, String hash) => isHex64(nonce) && isHex64(hash) && _sha256Hex(nonce) == hash;

  /// Fails closed on any fingerprint line it does not parse exactly: a lenient
  /// parser could hash a decoy while DTLS authenticates a different key.
  static String fingerprint(String sdp) {
    final values = <String>{};
    for (final line in sdp.split(RegExp(r'\r?\n'))) {
      if (!line.toLowerCase().contains('fingerprint')) continue;
      final match = _line.firstMatch(line);
      if (match == null) throw const CryptoException('Unsupported DTLS fingerprint', code: 'malformed');
      values.add('sha-256 ${match.group(1)!.toUpperCase()}');
    }
    if (values.length != 1) throw const CryptoException('Expected exactly one DTLS fingerprint', code: 'malformed');
    return values.single;
  }

  static String code(String localSdp, String remoteSdp, List<String> nonces) {
    final prints = [fingerprint(localSdp), fingerprint(remoteSdp)]..sort();
    if (nonces.length != 2 || !nonces.every(isHex64)) throw const CryptoException('Invalid verification input', code: 'malformed');
    final sortedNonces = [...nonces]..sort();
    final digest = sha256.convert(utf8.encode([label, ...prints, ...sortedNonces].join('\n'))).bytes;
    final value = ByteData.sublistView(Uint8List.fromList(digest)).getUint32(0) % 1000000;
    final text = value.toString().padLeft(6, '0');
    return '${text.substring(0, 3)} ${text.substring(3)}';
  }
}
