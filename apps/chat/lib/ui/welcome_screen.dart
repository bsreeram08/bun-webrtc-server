import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../app/app_controller.dart';
import '../core/api.dart';

class WelcomeScreen extends ConsumerStatefulWidget {
  const WelcomeScreen({super.key, this.invite});
  final String? invite;
  @override
  ConsumerState<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends ConsumerState<WelcomeScreen> {
  late final _invite = TextEditingController(text: widget.invite ?? '');
  final _username = TextEditingController();
  late bool _registering = widget.invite != null;
  bool _busy = false;
  String? _error;

  Future<void> _run(Future<void> Function() task) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await task();
    } on ApiException catch (e) {
      _error = e.message;
    } catch (e) {
      _error = e.toString().contains('Cancel') ? 'Passkey request was cancelled.' : 'Something went wrong: $e';
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _invite.dispose();
    _username.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final notice = ref.watch(appProvider.select((s) => s.notice));
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: ListView(
              padding: const EdgeInsets.fromLTRB(24, 48, 24, 24),
              shrinkWrap: true,
              children: [
                Align(
                  alignment: Alignment.centerLeft,
                  child: Container(
                    width: 64,
                    height: 64,
                    decoration: BoxDecoration(color: scheme.primary.withValues(alpha: .14), borderRadius: BorderRadius.circular(18)),
                    child: Icon(Icons.lock_outline_rounded, color: scheme.primary, size: 32),
                  ),
                ),
                const SizedBox(height: 20),
                Text('Private Chat', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800)),
                const SizedBox(height: 8),
                Text(
                  'End-to-end encrypted messages and calls. Your server can deliver them but never read them.',
                  style: TextStyle(color: Theme.of(context).textTheme.bodySmall?.color, fontSize: 16),
                ),
                const SizedBox(height: 32),
                if (!_registering) ...[
                  FilledButton.icon(
                    key: const Key('signin'),
                    onPressed: _busy ? null : () => _run(ref.read(appProvider.notifier).signIn),
                    icon: const Icon(Icons.fingerprint),
                    label: const Text('Sign in with passkey'),
                    style: FilledButton.styleFrom(
                      minimumSize: const Size.fromHeight(54),
                      textStyle: const TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextButton(onPressed: _busy ? null : () => setState(() => _registering = true), child: const Text('Have an invite? Create an account')),
                ] else ...[
                  TextField(
                    controller: _invite,
                    decoration: const InputDecoration(labelText: 'Invite code'),
                    autocorrect: false,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _username,
                    decoration: const InputDecoration(labelText: 'Username', helperText: '3–20 lowercase letters, digits or _'),
                    autocorrect: false,
                  ),
                  const SizedBox(height: 20),
                  FilledButton(
                    onPressed: _busy ? null : () => _run(() => ref.read(appProvider.notifier).register(_invite.text, _username.text)),
                    style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(54)),
                    child: const Text('Create account with passkey'),
                  ),
                  TextButton(onPressed: _busy ? null : () => setState(() => _registering = false), child: const Text('I already have an account')),
                ],
                if (_error != null || notice != null) ...[
                  const SizedBox(height: 16),
                  Text(_error ?? notice!, style: TextStyle(color: _error != null ? scheme.error : null)),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
