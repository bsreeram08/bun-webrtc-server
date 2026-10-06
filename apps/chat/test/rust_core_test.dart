// RustChatCrypto against the real Rust core on the host (the dylib `cargo build` produces in rust/).
// Skipped when it has not been built: `cargo build --manifest-path rust/Cargo.toml`.
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';

class _Key implements StoreKeys {
  _Key(this.byte);
  final int byte;
  @override
  Future<List<int>> keyFor(String account) async => List<int>.filled(32, byte);
}

String sdp(String byte) => 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 ${List.filled(32, byte).join(':')}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n';

void main() {
  final dylib = File('rust/target/debug/${Platform.isMacOS ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so'}');
  final skip = dylib.existsSync() ? false : 'build rust/ first';
  late Directory dir;
  setUpAll(() => dir = Directory.systemTemp.createTempSync('chatcore-dart-'));
  tearDownAll(() => dir.deleteSync(recursive: true));
  RustChatCrypto crypto(int keyByte) => RustChatCrypto(directory: () async => dir.path, storeKeys: _Key(keyByte), externalLibrary: ExternalLibrary.open(dylib.absolute.path));

  test('the core reproduces the verify.js call code vector and keeps its identity across opens', () async {
    final core = crypto(1);
    await core.init('account');
    expect(core.sasCode(sdp('ab'), sdp('CD'), ['1' * 64, '2' * 64]), '996 300');
    expect(core.sasCode(sdp('cd'), sdp('ab'), ['2' * 64, '1' * 64]), '996 300');
    final commitment = core.sasCommit();
    expect(core.sasCheck(commitment.nonce, commitment.hash), isTrue);
    expect(() => core.sasCode('v=0\r\n', sdp('ab'), ['1' * 64, '2' * 64]), throwsA(isA<CryptoException>()));
    final identity = await core.identity();
    final upload = await core.preparePrekeys(DateTime.now(), oneTimeOnServer: 0);
    expect(upload.identity, identity);
    expect(upload.oneTimePreKeys, hasLength(100));
    await core.init('account'); // Reopen: same sealed database, same identity.
    expect(await core.identity(), identity);
  }, skip: skip);

  test('the key database refuses the wrong store key (sealed at rest, fails closed)', () async {
    await crypto(1).init('sealed');
    await crypto(1).identity();
    await expectLater(crypto(2).init('sealed'), throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'storage')));
  }, skip: skip);
}
