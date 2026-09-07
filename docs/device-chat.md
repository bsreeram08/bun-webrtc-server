# Device-to-device chat and phone migration

The test app sends text over an ordered WebRTC data channel between the two invited participants. The Bun service forwards connection setup only. It has no chat message, history, or backup endpoint. Coturn can relay encrypted packets when a direct connection is unavailable. [WebRTC data channels use SCTP over DTLS](https://www.rfc-editor.org/rfc/rfc8831.html).

Choose chat-only mode to connect without giving microphone or camera permission. Messages and pending outgoing messages are stored in this browser's IndexedDB on your device. A message is marked delivered only after the other app acknowledges storing it. Both apps need to be open and connected to deliver messages; this is not a server mailbox or background push service.

The current test service still uses expiring two-person invitations. Queued messages can only be delivered while that invitation remains valid. Restarting the signaling service loses rooms. Reopening an invitation reconnects its room; a different invitation is a different conversation. Persistent accounts, a contact directory, multi-device identity, and native background incoming calls are separate work.

## Disappearing messages

Choose off, 1 hour, 24 hours, or 7 days for newly sent messages. Expiry starts when a message is queued on the sender's device, including time spent offline. Changing the setting does not change old messages. The recipient can see each message's expiry.

Expired messages are removed when the app runs, and omitted from exported or restored backups. A suspended or powered-off device cannot execute a deletion timer; the app purges expired history when it runs again. Expiry is based on device clocks, so incorrect clocks can affect it. This is application deletion, not a promise of forensic secure erasure. A recipient can still copy or photograph a message.

## Back up to Google Drive and restore on a new phone

1. In the app's backup controls, enter a strong, unique backup password and export the encrypted backup file.
2. Save or upload that file to your Google Drive using the device's Files/Drive app. Keep the password separately, for example in a password manager.
3. On the new phone, open the same app, download the encrypted file from Drive, then select it in the app's restore controls and enter the password.

Export and restore happen on the device. There is no automatic Google account integration or background Drive upload in this version. The file uses password-derived encryption and cannot be restored without its password. Neither the app administrator nor Google Drive receives the password from this app. Older copies already in Drive cannot be remotely erased when a message disappears; remove old backups yourself if you no longer want to retain them.

Backups restore history, not invitation tokens, administrator credentials, TURN credentials, or account identities. Restoring old outgoing messages does not automatically resend them. You need a valid invitation to join a live conversation on the new phone.

## Device and server trust

Live transport and exported backups are encrypted. Local browser history is stored in the device's browser database; it is not a separately password-locked vault. Protect your phone and browser profile with the device's lock and disk encryption. Clearing site data, deleting the browser profile, or browser storage eviction can remove the local copy. Keep an encrypted backup if you need recovery.

The app caches only its public interface files to let you read local history offline. It does not cache authenticated room API responses. The installed app launches without an invitation; paste your private invitation when joining.

The server delivering JavaScript and connection setup remains trusted. This implementation does not provide Signal-style identity verification or an independent cryptographic audit. See the [security model](security.md). Tests and remaining deployment checks are recorded in [verification status](status.md).
