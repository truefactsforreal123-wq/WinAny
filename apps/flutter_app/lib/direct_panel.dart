import 'dart:io';

import 'package:flutter/material.dart';
import 'package:remote_transport/remote_transport.dart';

import 'direct_connection.dart';

/// Local-only controls. The owning screen must call stop when shutting down.
class DirectPanel extends StatefulWidget {
  const DirectPanel({super.key, required this.connection});
  final DirectConnection connection;
  @override
  State<DirectPanel> createState() => _DirectPanelState();
}

class _DirectPanelState extends State<DirectPanel> {
  final address = TextEditingController(text: '127.0.0.1');
  final port = TextEditingController(text: '4443');
  final pem = TextEditingController(),
      key = TextEditingController(),
      der = TextEditingController();
  bool upnp = false;
  @override
  void dispose() {
    address.dispose();
    port.dispose();
    pem.dispose();
    key.dispose();
    der.dispose();
    super.dispose();
  }

  Future<bool> _confirm(String title, String content, String action) async =>
      await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(title),
          content: SingleChildScrollView(child: SelectableText(content)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: Text(action),
            ),
          ],
        ),
      ) ??
      false;
  Future<AccessRequest?> _accept(String fingerprint, String code) async {
    if (!mounted) return null;
    String preset = 'basic';
    final selected = <String, bool>{
      for (final name in [
        'view',
        'input',
        'clipboard_text',
        'clipboard_images',
        'clipboard_files',
        'file_transfer',
        'audio',
        'lock',
        'power',
        'elevated',
        'tv_keys',
        'tv_apps',
        'adb',
      ])
        name: false,
    };
    final choice = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, set) => AlertDialog(
          title: const Text('Incoming direct connection'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(
                  'Controller key SHA-256:\n$fingerprint\n\nCompare this code with the controller:\n$code',
                ),
                const Text(
                  'Desktop input requires a single full display. If input is allowed, that display is shared; window input and multi-display control are unavailable.',
                ),
                DropdownButton<String>(
                  value: preset,
                  items: const [
                    DropdownMenuItem(value: 'basic', child: Text('Basic')),
                    DropdownMenuItem(value: 'normal', child: Text('Normal')),
                    DropdownMenuItem(value: 'full', child: Text('Full')),
                    DropdownMenuItem(value: 'custom', child: Text('Custom')),
                  ],
                  onChanged: (v) => set(() => preset = v!),
                ),
                if (preset == 'custom')
                  ...selected.keys.map(
                    (name) => CheckboxListTile(
                      title: Text(name),
                      value: selected[name],
                      onChanged: (v) => set(() => selected[name] = v ?? false),
                    ),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Deny'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Accept'),
            ),
          ],
        ),
      ),
    );
    if (choice != true || !mounted) return null;
    final elevated = preset == 'full' ||
        (preset == 'custom' && selected.values.any((v) => v));
    if (elevated &&
        !await _confirm(
          'Confirm elevated access',
          'The selected access can grant sensitive control. Allow this session?',
          'Allow',
        )) return null;
    return AccessRequest(
      preset,
      permissions: preset == 'custom' ? selected : const {},
      elevatedConfirmed: elevated,
    );
  }

  Future<void> _run(Future<void> Function() action) async {
    try {
      await action();
    } catch (e) {
      if (mounted)
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Direct connection failed: $e')));
    }
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: widget.connection,
        builder: (context, _) => Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'Direct IP (no TURN)',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            Text(widget.connection.status),
            if (widget.connection.externalAddress != null)
              SelectableText('External: ${widget.connection.externalAddress}'),
            SwitchListTile(
              title: const Text('Map port via UPnP (listener)'),
              value: upnp,
              onChanged: widget.connection.listening
                  ? null
                  : (v) => setState(() => upnp = v),
            ),
            TextField(
              controller: address,
              decoration: const InputDecoration(
                labelText: 'Numeric IP address (listen or connect)',
              ),
            ),
            TextField(
              controller: port,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(labelText: 'Port'),
            ),
            TextField(
              controller: pem,
              decoration: const InputDecoration(
                labelText: 'Owner TLS certificate PEM path',
              ),
            ),
            TextField(
              controller: key,
              decoration: const InputDecoration(
                labelText: 'Owner TLS private key PEM path',
              ),
            ),
            TextField(
              controller: der,
              decoration: const InputDecoration(
                labelText: 'Same certificate DER path',
              ),
            ),
            Wrap(
              spacing: 8,
              children: [
                OutlinedButton(
                  onPressed: widget.connection.busy ||
                          widget.connection.listening ||
                          widget.connection.active
                      ? null
                      : () => _run(() async {
                            if (!await _confirm(
                              'Open a direct listener?',
                              'This opens a network port. Only enable it on a trusted network or with owner-configured port forwarding. TLS handshake floods also require firewall rate limiting.',
                              'Enable',
                            )) return;
                            await widget.connection.listen(
                              address: InternetAddress(address.text.trim()),
                              port: int.parse(port.text),
                              certificatePemPath: pem.text.trim(),
                              privateKeyPemPath: key.text.trim(),
                              certificateDerPath: der.text.trim(),
                              accept: _accept,
                              upnp: upnp,
                            );
                          }),
                  child: const Text('Enable listener'),
                ),
                FilledButton(
                  onPressed: widget.connection.busy ||
                          widget.connection.listening ||
                          widget.connection.active
                      ? null
                      : () => _run(
                            () => widget.connection.connect(
                              address: InternetAddress(address.text.trim()),
                              port: int.parse(port.text),
                              approveCertificate: (fingerprint) => _confirm(
                                'Approve TLS certificate',
                                'Verify this SHA-256 fingerprint with the owner before disclosing your identity:\n$fingerprint',
                                'Approve',
                              ),
                              confirmPeer: (cert, peerKey, code) => _confirm(
                                'Compare identity and code',
                                'Certificate SHA-256:\n$cert\n\nDevice key SHA-256:\n$peerKey\n\nCompare this code with the target:\n$code',
                                'They match',
                              ),
                            ),
                          ),
                  child: const Text('Connect'),
                ),
                OutlinedButton(
                  onPressed: widget.connection.listening ||
                          widget.connection.active ||
                          widget.connection.busy
                      ? () => _run(widget.connection.stop)
                      : null,
                  child: const Text('Stop'),
                ),
              ],
            ),
            if (widget.connection.error != null)
              Text(
                widget.connection.error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
          ],
        ),
      );
}
