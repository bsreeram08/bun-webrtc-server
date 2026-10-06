import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart' hide Description;
import 'package:private_chat/calls/signaling.dart';
import 'package:private_chat/core/events.dart';
import 'package:private_chat/crypto/chat_crypto.dart';
import 'package:private_chat/crypto/sas.dart';

String sdp(String byte) => 'v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\na=fingerprint:sha-256 ${List.filled(32, byte).join(':')}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n';

void main() {
  final token = 'a' * 43;
  group('room signaling messages', () {
    test('welcome carries the rotated token; malformed tokens are rejected', () {
      final welcome = RoomMessage.parse(jsonEncode({'type': 'welcome', 'polite': true, 'token': token}));
      expect(welcome, isA<Welcome>().having((w) => w.token, 'token', token).having((w) => w.polite, 'polite', true));
      expect(RoomMessage.parse(jsonEncode({'type': 'welcome', 'polite': true})), isNull);
      expect(RoomMessage.parse(jsonEncode({'type': 'welcome', 'polite': true, 'token': 'short'})), isNull);
    });
    test('ready, peer-left, error, description and candidate parse; unknown types do not', () {
      expect(RoomMessage.parse(jsonEncode({'type': 'ready', 'sessionId': token})), isA<Ready>());
      expect(RoomMessage.parse(jsonEncode({'type': 'peer-left'})), isA<PeerLeft>());
      expect(RoomMessage.parse(jsonEncode({'type': 'error', 'error': 'Stale session'})), isA<RoomError>());
      final d = RoomMessage.parse(jsonEncode({'type': 'description', 'description': {'type': 'offer', 'sdp': 'v=0'}, 'sessionId': token}));
      expect(d, isA<Description>().having((x) => x.type, 'type', 'offer'));
      expect(RoomMessage.parse(jsonEncode({'type': 'description', 'description': {'type': 'pranswer', 'sdp': 'v=0'}, 'sessionId': token})), isNull);
      final c = RoomMessage.parse(jsonEncode({'type': 'candidate', 'candidate': {'candidate': 'candidate:1', 'sdpMid': '0', 'sdpMLineIndex': 0, 'usernameFragment': 'u'}, 'sessionId': token}));
      expect(c, isA<Candidate>().having((x) => x.usernameFragment, 'ufrag', 'u'));
      expect(RoomMessage.parse(jsonEncode({'type': 'candidate', 'candidate': null, 'sessionId': token})), isA<Candidate>().having((x) => x.candidate, 'end', isNull));
      expect(RoomMessage.parse(jsonEncode({'type': 'hangup'})), isNull);
      expect(RoomMessage.parse('not json'), isNull);
      expect(RoomMessage.parse('x' * 70001), isNull);
    });
    test('outgoing frames bind to the pairing session', () {
      expect(jsonDecode(describeFrame('answer', 'v=0', token)), {'type': 'description', 'description': {'type': 'answer', 'sdp': 'v=0'}, 'sessionId': token});
      expect(jsonDecode(candidateFrame(null, token)), {'type': 'candidate', 'candidate': null, 'sessionId': token});
    });
    test('candidates match only their ICE generation', () {
      const remote = 'v=0\r\na=ice-ufrag:abcd\r\n';
      expect(matchesGeneration(remote, 'abcd'), isTrue);
      expect(matchesGeneration(remote, 'efgh'), isFalse);
      expect(matchesGeneration(remote, null), isTrue);
      expect(matchesGeneration(null, 'abcd'), isFalse);
    });
  });

  group('account events', () {
    test('parse every server event and ignore anything else', () {
      expect(AccountEvent.parse(jsonEncode({'type': 'hello', 'online': ['x']})), isA<Hello>());
      expect(AccountEvent.parse(jsonEncode({'type': 'presence', 'id': 'x', 'online': true})), isA<Presence>());
      expect(AccountEvent.parse(jsonEncode({'type': 'incoming', 'from': {'id': 'x', 'username': 'alice'}, 'kind': 'video', 'roomId': token, 'token': token})), isA<Incoming>());
      expect(
        AccountEvent.parse(jsonEncode({'type': 'envelope', 'id': 'e1', 'from': {'id': 'x', 'username': 'alice'}, 'envelope': 'abc', 'createdAt': 1})),
        isA<EnvelopeEvent>().having((e) => e.fromUsername, 'from', 'alice'),
      );
      expect(AccountEvent.parse(jsonEncode({'type': 'presence', 'id': 'x'})), isNull);
      expect(AccountEvent.parse(jsonEncode({'type': 'weird'})), isNull);
      expect(AccountEvent.parse(42), isNull);
    });
  });

  group('call verification code (verify-v1)', () {
    test('matches verify.js for the same fingerprints and nonces', () {
      // Computed with packages/signaling/public/verify.js sasCode([AB.., CD..], ['1'*64, '2'*64]).
      expect(Sas.code(sdp('ab'), sdp('CD'), ['1' * 64, '2' * 64]), '996 300');
      expect(Sas.code(sdp('cd'), sdp('ab'), ['2' * 64, '1' * 64]), '996 300');
    });
    test('a relay with its own DTLS key on each leg yields different codes', () {
      final nonces = ['1' * 64, '2' * 64];
      expect(Sas.code(sdp('aa'), sdp('11'), nonces), isNot(Sas.code(sdp('bb'), sdp('22'), nonces)));
    });
    test('fails closed on decoy, duplicate, non-canonical or missing fingerprints', () {
      final nonces = ['1' * 64, '2' * 64];
      for (final bad in [
        '${sdp('aa')}a=fingerprint:sha-256 ${List.filled(32, 'BB').join(':')}\r\n',
        'a=fingerprint:sha-256  ${List.filled(32, 'AA').join(':')}\r\n',
        'a=FINGERPRINT:sha-256 ${List.filled(32, 'AA').join(':')}\r\n',
        'a=fingerprint:sha-1 ${List.filled(20, 'AA').join(':')}\r\n',
        'v=0\r\n',
      ]) {
        expect(() => Sas.code(bad, sdp('cc'), nonces), throwsA(isA<CryptoException>()), reason: bad);
      }
      expect(() => Sas.code(sdp('aa'), sdp('cc'), ['zz', '1' * 64]), throwsA(isA<CryptoException>()));
    });
    test('commit/reveal: a reveal must match its commitment', () {
      final commitment = Sas.commit(Random(1));
      expect(Sas.check(commitment.nonce, commitment.hash), isTrue);
      expect(Sas.check('f' * 64, commitment.hash), isFalse);
      expect(parseVerifyPacket(jsonEncode({'type': 'commit', 'hash': commitment.hash})), {'type': 'commit', 'value': commitment.hash});
      expect(parseVerifyPacket(jsonEncode({'type': 'reveal', 'nonce': 'x', 'extra': 1})), isNull);
      expect(parseVerifyPacket('x' * 300), isNull);
    });
  });
}
