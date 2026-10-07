// RustChatCrypto against the real Rust core on the host (the dylib `cargo build` produces in rust/).
// Skipped when it has not been built: `cargo build --manifest-path rust/Cargo.toml`.
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart' show ExternalLibrary;
import 'package:flutter_test/flutter_test.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/rust_chat_crypto.dart';

String sdp(String byte) => 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 ${List.filled(32, byte).join(':')}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n';

void main() {
  final dylib = File('rust/target/debug/${Platform.isMacOS ? 'libchatcore_bridge.dylib' : 'libchatcore_bridge.so'}');
  final skip = dylib.existsSync() ? false : 'build rust/ first';
  late Directory dir;
  setUpAll(() => dir = Directory.systemTemp.createTempSync('chatcore-dart-'));
  tearDownAll(() => dir.deleteSync(recursive: true));
  RustChatCrypto crypto(StoreKeys keys) => RustChatCrypto(directory: () async => dir.path, storeKeys: keys, externalLibrary: ExternalLibrary.open(dylib.absolute.path));

  test('the core reproduces the verify.js call code vector and keeps its identity across opens', () async {
    final keys = MemoryStoreKeys();
    final core = crypto(keys);
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

  Matcher locked() => throwsA(isA<CryptoException>().having((e) => e.code, 'code', 'storage').having((e) => e.keysLocked, 'keysLocked', isTrue));

  test('fails closed instead of starting over: wrong key, missing key, deleted database', () async {
    final keys = MemoryStoreKeys();
    await crypto(keys).init('sealed');
    final identity = await crypto(keys).identity();
    // Wrong store key.
    final wrong = MemoryStoreKeys()..keys['sealed'] = List<int>.filled(32, 9);
    await expectLater(crypto(wrong).init('sealed'), locked());
    // A failed open never leaves the previously opened store usable.
    await expectLater(crypto(keys).identity(), locked());
    // Store key missing (keystore cleared) next to an existing database: refused, and no key is minted.
    final lost = MemoryStoreKeys();
    await expectLater(crypto(lost).init('sealed'), locked());
    expect(lost.keys, isEmpty, reason: 'no new store key over an existing database');
    // Database deleted while the keystore still holds its key: "missing or reset", never a fresh identity.
    for (final suffix in ['', '-wal', '-shm']) {
      final file = File('${dir.path}/sealed.sqlite$suffix');
      if (file.existsSync()) file.deleteSync();
    }
    await expectLater(crypto(keys).init('sealed'), locked());
    // Only the explicit recovery starts over.
    await crypto(keys).resetLocal('sealed');
    await crypto(keys).init('sealed');
    expect(await crypto(keys).identity(), isNot(identity));
  }, skip: skip);
}
