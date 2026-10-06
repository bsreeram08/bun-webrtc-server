import 'dart:convert';

import 'package:crypto/crypto.dart';

/// One stable, opaque conversation id per pair of users, identical to the web
/// client's `pairId`, so history keys match across devices and backups.
String pairId(String me, String other) {
  final key = ([me, other]..sort()).join(':');
  final digest = sha256.convert(utf8.encode('webrtc-bun-pair-v1:$key')).bytes;
  return base64Url.encode(digest).replaceAll('=', '');
}
