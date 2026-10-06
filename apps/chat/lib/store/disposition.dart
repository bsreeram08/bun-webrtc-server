/// What to do with a mailbox envelope after trying to process it: acknowledge
/// (the server deletes it) or leave it for redelivery. Port of
/// `ChatStore.inboundDisposition`. Fails closed: only known permanent outcomes
/// are acknowledged at once; storage errors and anything uncoded or unknown are
/// retried and acknowledged with a notice only after [limit] attempts. Every
/// discard except a true replay is reported.
class Disposition {
  const Disposition({required this.ack, this.notice});
  final bool ack;

  /// storage-full, conversation-full, invalid, undecryptable, gave-up, retrying, or null.
  final String? notice;

  @override
  bool operator ==(Object other) => other is Disposition && other.ack == ack && other.notice == notice;
  @override
  int get hashCode => Object.hash(ack, notice);
  @override
  String toString() => 'Disposition(ack: $ack, notice: $notice)';
}

const _permanent = <String, String?>{
  'replay': null,
  'full': 'storage-full',
  'conversation-full': 'conversation-full',
  'invalid': 'invalid',
  'conflict': 'invalid',
  'mismatch': 'invalid',
  'malformed': 'undecryptable',
  'auth': 'undecryptable',
  'skip-limit': 'undecryptable',
  'unknown-session': 'undecryptable',
  'unknown-spk': 'undecryptable',
  'claim-limit': 'undecryptable',
};

/// [hasError] false means the envelope was handled successfully.
Disposition inboundDisposition({required bool hasError, String? code, required int attempts, int limit = 3}) {
  if (!hasError) return const Disposition(ack: true);
  if (code != null && _permanent.containsKey(code)) return Disposition(ack: true, notice: _permanent[code]);
  return attempts >= limit ? const Disposition(ack: true, notice: 'gave-up') : const Disposition(ack: false, notice: 'retrying');
}

String? noticeText(String? notice, String from) => switch (notice) {
  'storage-full' => 'A message from $from was discarded: this device holds 2,000 messages. Clear some history to receive more.',
  'conversation-full' => 'A message from $from was discarded: this conversation holds 500 incoming messages. Burn or clear it to receive more from them.',
  'invalid' => 'A message from $from was invalid or did not match their published security code, and was discarded.',
  'gave-up' => 'A message from $from could not be saved after several tries and was discarded.',
  'undecryptable' => 'A message from $from could not be decrypted and was discarded.',
  _ => null,
};
