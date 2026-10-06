# Private Chat (Flutter)

Native client for iOS, Android and macOS (Windows/Linux build if their toolchains
exist). It speaks the same protocol as the web client in `packages/signaling/public`:
passkey accounts, end-to-end encrypted contact messages through the server mailbox,
device-to-device calls with the six-digit verification code, burn, disappearing
messages and the same themes.

```
lib/
  app/app_controller.dart   Riverpod state: auth, contacts, presence, unread, incoming calls
  core/                     typed API client (bearer, no Origin), events socket, pair ids
  crypto/                   ChatCrypto contract, FakeChatCrypto, call verification code (Sas)
  store/                    SQLite message store (chat-store.js rules), inbound disposition
  messaging/messenger.dart  mailbox receive/send, encrypted receipts, burn, send queue
  calls/                    room signaling parser, CallController (flutter_webrtc, verify-v1)
  push/push_service.dart    FCM / APNs / PushKit with proof of possession
  theme/                    presets, accent contrast clamping, per-chat prefs
  ui/                       screens and animated widgets (ticks, icons, wallpapers)
  demo/main_demo.dart       screenshot demo against a fake in-process server
```

State: **Riverpod** — every dependency (API, crypto, store, passkeys, token store) is a
provider, so tests and the demo override them without a DI framework.

## Run

```sh
flutter run                                   # against https://calls.sreerams.in
flutter run --dart-define=BASE_URL=http://localhost:3000
flutter run -t lib/demo/main_demo.dart --dart-define=DEMO_SCREEN=chat   # offline demo
flutter test
flutter drive --profile -d macos --driver=test_driver/perf_driver.dart --target=integration_test/scroll_perf_test.dart
```

## Before a real device build (user actions)

1. **Apple Developer team**: set the team for `Runner` in Xcode (iOS and macOS),
   bundle id `in.sreerams.calls`. Enable capabilities Push Notifications, Background
   Modes (Audio, Voice over IP, Remote notifications) and Associated Domains
   (`webcredentials:calls.sreerams.in`, `applinks:calls.sreerams.in`) — already in
   `ios/Runner/Runner.entitlements`. Switch `aps-environment` to `production` for
   TestFlight/App Store.
2. **APNs + VoIP**: create an APNs key (.p8) in the developer portal and give the
   server its key id, team id and bundle id (the server sends APNs and VoIP pushes
   directly; Firebase is not used to relay iOS pushes).
3. **Firebase (Android push)**: create a Firebase project with Android app
   `in.sreerams.calls`, download `google-services.json` to
   `android/app/google-services.json` (not committed) and apply the
   `com.google.gms.google-services` Gradle plugin. On iOS, `GoogleService-Info.plist`
   goes in `ios/Runner/` (not committed); it is only needed because
   firebase_messaging reads the APNs token. Without config the app runs and push is
   disabled (logged).
4. **Passkeys**: the server must serve `/.well-known/apple-app-site-association`
   (webcredentials for `TEAMID.in.sreerams.calls`) and `/.well-known/assetlinks.json`
   with the Android signing certificate SHA-256 of every key you sign with (debug and
   release). The server must accept the Android origin `android:apk-key-hash:<…>` in
   WebAuthn verification.
5. **Android signing**: create a release keystore and `android/key.properties`.

## Integration TODOs

- `cryptoProvider` (lib/app/app_controller.dart) returns `FakeChatCrypto`, which does
  **not encrypt**. Wire the flutter_rust_bridge binding of `crates/chatcore` there:
  implement `ChatCrypto` by forwarding each method, mapping core errors to
  `CryptoException.code` (`replay`, `malformed`, `auth`, `skip-limit`,
  `unknown-session`, `unknown-spk`, `claim-limit`, `storage`, `identity-blocked`).
  `Sas` in `lib/crypto/sas.dart` is cross-checked against verify.js
  (`test/protocol_test.dart`); the core's `sas_code` must give the same vector.
- `ChatCrypto.init` receives `keys-<userId>`; the binding should resolve it inside
  the app support directory.
- **Web key storage parity**: web clients now store X25519 private keys AES-GCM-wrapped
  (Safari could not persist X25519 CryptoKeys). The Rust core keeps its own store, but
  backup/restore formats must stay compatible if keys ever move between clients.
- **Chat key rotation**: handle the new inner payloads `{type: 'rotate'}` and
  `{type: 'policy', rotateEveryMs}` (today `Messenger._checkPayload` rejects unknown
  types as `invalid`, which acks and discards them with a notice).
- **Active device**: implemented (`Messenger.checkActive` / `takeOver`, banner
  "Use this device instead"); re-checked on sign-in, reconnect and our own `keys` event.
- **Perf**: `integration_test/scroll_perf_test.dart` is written but its numbers were not
  collected (see the report).
