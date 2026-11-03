import 'dart:io';

import 'package:flutter/material.dart';

import 'signaling.dart';
import 'update_check.dart';

// Update files live in the R2 bucket remote-link-updates, served via its custom domain.
const kUpdateManifestBase =
    'https://updates.mixed-tools.site/update-';

/// Passed by scripts/build-release.ps1 (--dart-define=APP_VERSION); the default mirrors pubspec.yaml.
const kAppVersion = String.fromEnvironment('APP_VERSION', defaultValue: '0.1.0');

/// Unattended password, trusted devices and update check. The parent rebuilds it on [Signaling] changes.
class SettingsPanel extends StatefulWidget {
  const SettingsPanel({super.key, required this.signaling});
  final Signaling signaling;
  @override
  State<SettingsPanel> createState() => _SettingsPanelState();
}

class _SettingsPanelState extends State<SettingsPanel> {
  final password = TextEditingController();
  String preset = 'normal';
  bool checking = false;

  @override
  void dispose() {
    password.dispose();
    super.dispose();
  }

  void _snack(String text) => ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(text)));

  Future<void> _run(Future<void> Function() action) async {
    try {
      await action();
    } catch (e) {
      if (mounted) _snack('$e');
    }
  }

  Future<void> _update() async {
    final platform = Platform.isWindows ? 'windows' : 'linux';
    setState(() => checking = true);
    try {
      final path = await checkForUpdate(
        manifestUrl: Uri.parse('$kUpdateManifestBase$platform.json'),
        currentVersion: kAppVersion,
        platform: platform,
      );
      if (!mounted) return;
      if (path == null) {
        _snack('You are up to date');
        return;
      }
      if (Platform.isLinux) {
        await showDialog<void>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Update downloaded'),
            content: SelectableText('Verified installer: $path'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('OK'),
              ),
            ],
          ),
        );
        return;
      }
      final install = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Install update?'),
          content: const Text(
            'A verified update is ready. The app will close and the installer will run.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Later'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('Install'),
            ),
          ],
        ),
      );
      if (install == true) {
        await Process.start(path, ['/SILENT'], mode: ProcessStartMode.detached);
        exit(0);
      }
    } catch (e) {
      if (mounted) _snack('Update check failed: $e');
    } finally {
      if (mounted) setState(() => checking = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = widget.signaling;
    return Card(
      child: ExpansionTile(
        title: const Text('Settings'),
        childrenPadding: const EdgeInsets.all(16),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Unattended access',
              style: Theme.of(context).textTheme.titleMedium),
          Text(
            s.unattendedEnabled
                ? 'On (${s.unattendedPreset}). Remote devices that know the password connect without a prompt. Never elevated.'
                : 'Off. Every request needs your approval unless the device is trusted.',
          ),
          if (s.unattendedNotice != null) Text(s.unattendedNotice!),
          TextField(
            controller: password,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Password (12+ characters)',
            ),
          ),
          DropdownButton<String>(
            value: preset,
            onChanged: (v) => setState(() => preset = v!),
            items: const [
              DropdownMenuItem(
                  value: 'basic', child: Text('Basic - view only')),
              DropdownMenuItem(
                value: 'normal',
                child: Text('Normal - view and input'),
              ),
            ],
          ),
          Wrap(
            spacing: 8,
            children: [
              FilledButton(
                onPressed: () => _run(() async {
                  await s.setUnattended(password.text, preset);
                  password.clear();
                }),
                child: Text(
                    s.unattendedEnabled ? 'Change password' : 'Set password'),
              ),
              if (s.unattendedEnabled)
                OutlinedButton(
                  onPressed: () => _run(s.clearUnattended),
                  child: const Text('Turn off'),
                ),
            ],
          ),
          const SizedBox(height: 16),
          Text('Trusted devices',
              style: Theme.of(context).textTheme.titleMedium),
          if (s.trustError != null) Text(s.trustError!),
          if (s.trusted.isEmpty)
            const Text(
                'None. After you accept a session you can trust the device.'),
          for (final d in s.trusted)
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text('Device ${d.controllerId} (${d.preset})'),
              subtitle: Text('Key ${d.deviceId.substring(0, 16)}'),
              trailing: TextButton(
                onPressed: () => _run(() => s.revokeTrusted(d)),
                child: const Text('Revoke'),
              ),
            ),
          if (Platform.isWindows || Platform.isLinux) ...[
            const SizedBox(height: 16),
            OutlinedButton(
              onPressed: checking ? null : _update,
              child: Text(checking ? 'Checking...' : 'Check for updates'),
            ),
          ],
        ],
      ),
    );
  }
}
