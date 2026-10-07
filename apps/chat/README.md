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
  crypto/                   ChatCrypto contract, RustChatCrypto (the real core), FakeChatCrypto, Sas
  src/rust/                 flutter_rust_bridge bindings (generated) for rust/ → crates/chatcore
  store/                    SQLite message store (chat-store.js rules), inbound disposition
  messaging/messenger.dart  mailbox receive/send, encrypted receipts, burn, send queue
  calls/                    room signaling parser, CallController (flutter_webrtc, verify-v1)
  push/push_service.dart    FCM / APNs / PushKit with proof of possession
  theme/                    presets, accent contrast clamping, per-chat prefs
  ui/                       screens and animated widgets (ticks, icons, wallpapers)
  demo/main_demo.dart       screenshot demo against a fake in-process server
rust/                       bridge crate (flutter_rust_bridge 2.13.0) over ../../../crates/chatcore
rust_builder/               cargokit plugin: builds the Rust core during `flutter build` on every platform
```

Encryption is `crates/chatcore`, a Rust port of the web client's signal.js / verify.js, checked
against them message by message by `bun run test:interop` (both directions). The app calls it through
flutter_rust_bridge (`RustChatCrypto`, the default `cryptoProvider`). Regenerate the bindings after
changing `rust/src/api.rs`: `flutter_rust_bridge_codegen generate` (codegen 2.13.0).

State: **Riverpod** — every dependency (API, crypto, store, passkeys, token store) is a
provider, so tests and the demo override them without a DI framework.

## Run

```sh
flutter run                                   # against https://calls.sreerams.in
flutter run --dart-define=BASE_URL=http://localhost:3000
flutter run -t lib/demo/main_demo.dart --dart-define=DEMO_SCREEN=chat   # offline demo
flutter test                                  # includes the Rust core on the host once rust/ is built
cargo build --manifest-path rust/Cargo.toml    # host dylib for test/rust_core_test.dart
bun run test:cross-client                      # (repo root) web client ↔ this app's Rust core, real server
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

## Verified (2026-10-06)

- `flutter analyze` clean; `flutter test` passes (unit, widget, messenger with rotation, and
  `test/rust_core_test.dart` against the real Rust core: the verify.js call-code vector `996 300`, a
  sealed key database that refuses the wrong store key).
- `bun run test:cross-client`: the real web client (Chromium) and this app's real crypto path (Rust core,
  Messenger, store, API client, events socket) exchange messages through a local server in both
  directions, with encrypted receipts, matching safety numbers, a session reset started on either side,
  the active-device rule (an inactive second browser leaves envelopes for the active one) and burn.
- Builds: `flutter build ios --simulator --no-codesign`, `flutter build apk --debug` (arm64-v8a,
  armeabi-v7a, x86_64 `.so` in the APK), `flutter build macos --debug` — each links the Rust core.

## Key storage on devices

The Rust core keeps keys, sessions and pinned identities in `<app support>/keys-<userId>.sqlite`,
sealed with AES-256-GCM under a random 32-byte store key held in the platform keystore
(`flutter_secure_storage`: Keychain / Android Keystore). Every value is bound to its row and store; a
plaintext, moved, foreign or tampered row refuses the whole database (`storage` error), and a missing
or wrong store key never silently creates new keys. See `crates/chatcore/src/store.rs`.

## Not verified / TODO

- Real devices, real push delivery (FCM/APNs/VoIP), CallKit/ConnectionService on hardware, passkeys on
  device (needs the Apple team, Firebase project and app association files — see above).
- Rotation notices are shown as status lines; the web app's stored "system" lines are not ported to
  the native message store yet.
- Scroll performance numbers (`integration_test/scroll_perf_test.dart`) were not collected.
- Windows/Linux builds (scaffolds exist; no toolchains on the build machine).
- `rust/Cargo.lock` pins `libc 0.2.177`: newer libc breaks `backtrace` (via flutter_rust_bridge) on the
  iOS simulator target.
