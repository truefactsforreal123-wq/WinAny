import 'dart:io';

import 'package:flutter/material.dart';

import 'tv_service.dart';

/// The caller owns [service] and must dispose it when the application closes.
class TvPanel extends StatefulWidget {
  const TvPanel({
    super.key,
    required this.service,
    required this.remoteEnabled,
    required this.sendRemote,
  });
  final TvService service;
  final bool remoteEnabled;
  final Future<Map<String, dynamic>> Function(Map<String, dynamic>) sendRemote;
  @override
  State<TvPanel> createState() => _TvPanelState();
}

class _TvPanelState extends State<TvPanel> {
  final host = TextEditingController();
  final pin = TextEditingController();
  final text = TextEditingController();
  final app = TextEditingController();
  final apk = TextEditingController();
  String brand = 'samsung';
  String? selected;
  bool remote = false, busy = false, refreshPending = false;
  int viewEpoch = 0;
  String? message;
  List<Map<String, dynamic>> devices = [];
  List<Map<String, String>> found = [];
  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void didUpdateWidget(covariant TvPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!widget.remoteEnabled && remote) {
      remote = false;
      viewEpoch++;
      selected = null;
      devices = [];
      refreshPending = true;
      if (!busy) {
        refreshPending = false;
        Future.microtask(_refresh);
      }
    }
  }

  @override
  void dispose() {
    host.dispose();
    pin.dispose();
    text.dispose();
    app.dispose();
    apk.dispose();
    super.dispose();
  }

  Future<Map<String, dynamic>> _send(Map<String, dynamic> request) => remote
      ? widget.sendRemote(request)
      : widget.service.localDispatch(request);
  Future<void> _run(Future<void> Function() operation) async {
    if (busy) return;
    setState(() {
      busy = true;
      message = null;
    });
    try {
      await operation();
    } catch (e) {
      if (mounted) setState(() => message = 'TV operation failed: $e');
    } finally {
      if (mounted) {
        setState(() => busy = false);
        if (refreshPending) {
          refreshPending = false;
          Future.microtask(_refresh);
        }
      }
    }
  }

  Future<void> _refresh() => _run(() async {
    final epoch = viewEpoch;
    final response = await _send({'action': 'list'});
    final raw = response['devices'];
    if (raw is! List) throw StateError('Invalid TV list response');
    final list = raw.map((v) => Map<String, dynamic>.from(v as Map)).toList();
    if (!mounted || epoch != viewEpoch) return;
    setState(() {
      devices = list;
      if (!list.any((d) => d['id'] == selected)) selected = null;
    });
  });
  Future<void> _scan() => _run(() async {
    final result = await widget.service.discover();
    if (!mounted) return;
    setState(() {
      found = result;
      message = result.isEmpty ? 'No TVs found.' : null;
    });
  });
  /// Android TV (6 hex digits) and Vizio (4 digits) show a PIN on the TV during pairing.
  Future<String> _askPin() async {
    final c = TextEditingController();
    final v = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Enter the PIN shown on the TV'),
        content: TextField(controller: c, autofocus: true),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, c.text.trim()),
            child: const Text('Pair'),
          ),
        ],
      ),
    );
    if (v == null) throw StateError('PIN entry cancelled');
    return v;
  }

  Future<void> _pair() async {
    final address = host.text.trim();
    final fingerprint = pin.text.trim();
    final approved = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Confirm local TV identity'),
        content: Text(
          brand == 'firetv'
              ? 'Allow ADB control of the TV at $address? Enable ADB debugging on the TV and accept the RSA prompt shown there. Requires adb (Android platform-tools) on this PC.'
              : brand == 'roku'
              ? 'Allow plaintext control of Roku at $address on your trusted LAN? Roku restricts third-party ECP use; review its policy before use.'
              : 'Confirm $brand at $address. Verify this SHA-256 certificate fingerprint out of band with the TV owner before approving:\n\n$fingerprint\n\nA wrong or unverified fingerprint is not safe.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('I verified and approve'),
          ),
        ],
      ),
    );
    if (approved != true || !mounted) return;
    await _run(() async {
      await widget.service.pairLocal(
        brand: brand,
        host: address,
        fingerprint: fingerprint,
        confirmed: true,
        readPin: _askPin,
      );
      final response = await widget.service.localDispatch({'action': 'list'});
      if (!mounted) return;
      setState(() {
        devices = (response['devices'] as List)
            .map((v) => Map<String, dynamic>.from(v as Map))
            .toList();
        message = 'Pairing accepted. TV control is firmware-dependent.';
      });
    });
  }

  Future<void> _action(String action, [String? value]) => _run(() async {
    final id = selected;
    if (id == null) throw StateError('Select a TV');
    final result = await _send({
      'action': action,
      'id': id,
      if (value != null) 'value': value,
    });
    if (mounted)
      setState(() => message = result['note']?.toString() ?? result.toString());
  });
  Future<void> _install() => _run(() async {
    final id = selected, path = apk.text.trim();
    if (id == null) throw StateError('Select a TV');
    if (!path.toLowerCase().endsWith('.apk') || !File(path).existsSync()) {
      throw ArgumentError('APK path must be an existing .apk file');
    }
    if (mounted) setState(() => message = 'Installing...');
    await widget.service.installApk(id, path);
    if (mounted) setState(() => message = 'Companion app installed.');
  });
  @override
  Widget build(BuildContext context) {
    final current = devices.where((d) => d['id'] == selected).firstOrNull;
    final keys =
        (current?['keys'] as List?)?.whereType<String>().toSet() ?? <String>{};
    final capabilities =
        (current?['capabilities'] as List?)?.whereType<String>().toSet() ??
        <String>{};
    Widget key(String label, String value) => OutlinedButton(
      onPressed: !busy && keys.contains(value)
          ? () => _action('key', value)
          : null,
      child: Text(label),
    );
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'TV control',
            style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
          ),
          const Text(
            'TV screen viewing is not supported. Fire TV (needs ADB) and Apple TV (needs HAP pairing) are not supported.',
          ),
          const Text(
            'Roku ECP is plaintext and Roku restricts third-party ECP use; review vendor policy.',
          ),
          SwitchListTile(
            title: const Text('Control TVs on remote device'),
            subtitle: Text(
              widget.remoteEnabled
                  ? 'Uses the active controller session.'
                  : 'Requires an active controller session.',
            ),
            value: remote,
            onChanged: widget.remoteEnabled && !busy
                ? (v) {
                    setState(() {
                      remote = v;
                      viewEpoch++;
                      selected = null;
                      devices = [];
                    });
                    _refresh();
                  }
                : null,
          ),
          if (!remote) ...[
            DropdownButton<String>(
              value: brand,
              items: const [
                DropdownMenuItem(value: 'samsung', child: Text('Samsung')),
                DropdownMenuItem(value: 'lg', child: Text('LG webOS')),
                DropdownMenuItem(value: 'roku', child: Text('Roku')),
                DropdownMenuItem(value: 'androidtv', child: Text('Android TV')),
                DropdownMenuItem(value: 'firetv', child: Text('Fire TV (ADB)')),
                DropdownMenuItem(value: 'vizio', child: Text('Vizio SmartCast')),
              ],
              onChanged: busy ? null : (v) => setState(() => brand = v!),
            ),
            TextField(
              controller: host,
              decoration: const InputDecoration(
                labelText: 'TV private IPv4 address',
              ),
            ),
            if (brand != 'roku' && brand != 'firetv')
              TextField(
                controller: pin,
                decoration: const InputDecoration(
                  labelText: 'Locally verified certificate SHA-256 fingerprint',
                  helperText: 'Verify out of band before pairing.',
                ),
              ),
            OutlinedButton(
              onPressed: busy ? null : _scan,
              child: const Text('Scan network'),
            ),
            Wrap(
              spacing: 4,
              children: [
                for (final d in found)
                  ActionChip(
                    label: Text('${d['brand']} ${d['host']}'),
                    onPressed:
                        busy ||
                            !const {
                              'samsung',
                              'lg',
                              'roku',
                              'androidtv',
                              'firetv',
                              'vizio',
                            }.contains(d['brand'])
                        ? null
                        : () => setState(() {
                            brand = d['brand']!;
                            host.text = d['host']!;
                          }),
                  ),
              ],
            ),
            FilledButton(
              onPressed: busy ? null : _pair,
              child: const Text('Pair locally'),
            ),
          ],
          Row(
            children: [
              Expanded(
                child: DropdownButton<String>(
                  isExpanded: true,
                  hint: const Text('Select paired TV'),
                  value: selected,
                  items: devices
                      .map(
                        (d) => DropdownMenuItem<String>(
                          value: d['id'] as String,
                          child: Text('${d['brand']} Ã‚Â· ${d['id']}'),
                        ),
                      )
                      .toList(),
                  onChanged: busy ? null : (v) => setState(() => selected = v),
                ),
              ),
              IconButton(
                onPressed: busy ? null : _refresh,
                icon: const Icon(Icons.refresh),
                tooltip: 'Refresh',
              ),
            ],
          ),
          if (current != null) ...[
            Text('Capabilities: ${capabilities.join(', ')}'),
            Wrap(
              spacing: 4,
              children: [
                key('Up', 'up'),
                key('Down', 'down'),
                key('Left', 'left'),
                key('Right', 'right'),
                key('OK', 'enter'),
                key('Back', 'back'),
                key('Home', 'home'),
                key('Volume +', 'volume_up'),
                key('Volume -', 'volume_down'),
                key('Mute', 'mute'),
                key('Power off', 'power_off'),
              ],
            ),
            if (capabilities.contains('state'))
              TextButton(
                onPressed: busy ? null : () => _action('state'),
                child: const Text('Get state'),
              ),
            if (capabilities.contains('text'))
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: text,
                      decoration: const InputDecoration(labelText: 'Text'),
                    ),
                  ),
                  TextButton(
                    onPressed: busy ? null : () => _action('text', text.text),
                    child: const Text('Send'),
                  ),
                ],
              ),
            if (capabilities.contains('apps'))
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: app,
                      decoration: const InputDecoration(labelText: 'App ID'),
                    ),
                  ),
                  TextButton(
                    onPressed: busy ? null : () => _action('app', app.text),
                    child: const Text('Launch'),
                  ),
                ],
              ),
          ],
          if (!remote && current?['brand'] == 'firetv')
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: apk,
                    decoration: const InputDecoration(labelText: 'Companion APK path'),
                  ),
                ),
                TextButton(
                  onPressed: busy ? null : _install,
                  child: const Text('Install companion app'),
                ),
              ],
            ),
          if (busy) const LinearProgressIndicator(),
          if (message != null) SelectableText(message!),
        ],
      ),
    );
  }
}
