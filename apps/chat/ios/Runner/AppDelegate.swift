import CallKit
import Flutter
import PushKit
import UIKit
import flutter_callkit_incoming

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate, PKPushRegistryDelegate {
  private var voipRegistry: PKPushRegistry?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    // VoIP pushes wake the app for incoming calls even when it was not running.
    let registry = PKPushRegistry(queue: DispatchQueue.main)
    registry.delegate = self
    registry.desiredPushTypes = [.voIP]
    voipRegistry = registry
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }

  func pushRegistry(_ registry: PKPushRegistry, didUpdate credentials: PKPushCredentials, for type: PKPushType) {
    let token = credentials.token.map { String(format: "%02x", $0) }.joined()
    SwiftFlutterCallkitIncomingPlugin.sharedInstance?.setDevicePushTokenVoIP(token)
  }

  func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {
    SwiftFlutterCallkitIncomingPlugin.sharedInstance?.setDevicePushTokenVoIP("")
  }

  /// iOS requires every VoIP push to be reported to CallKit immediately, before
  /// Dart runs. The payload is `{type: "call", from, kind, roomId}` (never message
  /// text); the room credential is fetched by the app over its authenticated
  /// events connection after the user accepts, so the push itself grants nothing.
  func pushRegistry(
    _ registry: PKPushRegistry,
    didReceiveIncomingPushWith payload: PKPushPayload,
    for type: PKPushType,
    completion: @escaping () -> Void
  ) {
    let info = payload.dictionaryPayload
    // Proof of possession for a VoIP token the server saw bound elsewhere (reinstall or account
    // switch): a VoIP push must still be reported to CallKit, so report a placeholder, end it at
    // once, and hand the nonce to Dart, which POSTs /api/push/native/confirm.
    if (info["type"] as? String) == "verify", let nonce = info["nonce"] as? String {
      let placeholder = flutter_callkit_incoming.Data(id: UUID().uuidString, nameCaller: "Verifying notifications…", handle: "", type: 0)
      SwiftFlutterCallkitIncomingPlugin.sharedInstance?.showCallkitIncoming(placeholder, fromPushKit: true)
      SwiftFlutterCallkitIncomingPlugin.sharedInstance?.endCall(placeholder)
      UserDefaults.standard.set(nonce, forKey: "voip-verify-nonce")
      SwiftFlutterCallkitIncomingPlugin.sharedInstance?.sendEventCustom(
        "com.hiennv.flutter_callkit_incoming.ACTION_CALL_CUSTOM", body: ["type": "voip-verify", "nonce": nonce])
      DispatchQueue.main.asyncAfter(deadline: .now() + 1) { completion() }
      return
    }
    let from = (info["from"] as? String) ?? "Contact"
    let kind = (info["kind"] as? String) ?? "voice"
    let data = flutter_callkit_incoming.Data(id: UUID().uuidString, nameCaller: from, handle: from, type: kind == "video" ? 1 : 0)
    data.appName = "Private Chat"
    data.extra = ["from": from, "kind": kind, "roomId": (info["roomId"] as? String) ?? ""]
    data.duration = 45000
    SwiftFlutterCallkitIncomingPlugin.sharedInstance?.showCallkitIncoming(data, fromPushKit: true)
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { completion() }
  }
}
