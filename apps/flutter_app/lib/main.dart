import 'package:flutter/material.dart';

import 'dart:io';
import 'dart:async';
import 'dart:math' as math;

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'signaling.dart';
import 'local_store.dart';
import 'direct_connection.dart';
import 'direct_panel.dart';
import 'tv_service.dart';
import 'tv_panel.dart';
import 'settings_panel.dart';
import 'video_pointer.dart';

import 'package:flutter_webrtc/flutter_webrtc.dart';

final signalingProvider = ChangeNotifierProvider<Signaling>(
  (ref) => Signaling(),
);
void main() => runApp(const ProviderScope(child: RemoteLinkApp()));

class RemoteLinkApp extends StatelessWidget {
  const RemoteLinkApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Remote Link',
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff4246a5)),
          useMaterial3: true,
        ),
        home: const Dashboard(),
      );
}

class Dashboard extends ConsumerStatefulWidget {
  const Dashboard({super.key});
  @override
  ConsumerState<Dashboard> createState() => _DashboardState();
}

class _DashboardState extends ConsumerState<Dashboard>
    with WidgetsBindingObserver {
  final endpoint = TextEditingController(
    text: 'wss://remote-signaling.mohamedelmahrouky04.workers.dev/v1/ws',
  );
  final peer = TextEditingController();
  final outgoingFile = TextEditingController();
  final remoteText = TextEditingController();
  final unattendedSecret = TextEditingController();
  String? shownFileOffer;
  String? shownIncoming;
  LocalStore? store;
  List<String> saved = [];
  List<String> auditEntries = [];
  String? storageError;
  DirectConnection? direct;
  String? directError;
  TvService? tv;
  String? tvError;
  bool tvLoading = false;
  late final Signaling _signaling; // ref is unusable during dispose
  final mods = <String>{};
  bool trackpad = false;
  double tx = .5, ty = .5;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _signaling = ref.read(signalingProvider);
    _signaling.onAudit = _auditEvent;
    _signaling.onSecretUsed = unattendedSecret.clear;
    scheduleMicrotask(() => unawaited(_signaling.loadTrust())); // not during build
    _openStore();
  }

  Future<void> _auditEvent(String event) async {
    try {
      await store?.audit(event);
      final audit = await store?.auditEntries();
      if (mounted && audit != null) setState(() => auditEntries = audit);
    } catch (_) {}
  }

  void _tapKey(Signaling state, String code) {
    for (final down in const [true, false]) {
      state.sendInput({'t': 'key', 'code': code, 'down': down});
    }
    setState(_releaseMods);
  }

  Future<void> _openStore() async {
    try {
      final opened = await LocalStore.open();
      final devices = await opened.devices();
      final audit = await opened.auditEntries();
      if (!mounted) {
        await opened.close();
        return;
      }
      setState(() {
        store = opened;
        saved = devices;
        auditEntries = audit;
      });
    } catch (e) {
      if (mounted)
        setState(() => storageError = 'Local storage unavailable: $e');
    }
  }

  Future<void> _saveDevice() async {
    final id = peer.text.trim();
    if (!RegExp(r'^\d{12}$').hasMatch(id) || store == null) return;
    try {
      await store!.saveDevice(id);
      await store!.audit('Device saved');
      final devices = await store!.devices();
      final audit = await store!.auditEntries();
      if (mounted)
        setState(() {
          saved = devices;
          auditEntries = audit;
        });
    } catch (e) {
      if (mounted) setState(() => storageError = 'Could not save device: $e');
    }
  }

  Future<void> _openTv() async {
    if (tvLoading || tv != null) return;
    setState(() {
      tvLoading = true;
      tvError = null;
    });
    TvService? service;
    try {
      service = TvService();
      await service.initialize();
      if (!mounted) {
        await service.dispose();
        return;
      }
      final state = ref.read(signalingProvider);
      state.tvHandler = service.dispatch;
      state.onSessionEnded = () {
        unawaited(service!.cancelPending().catchError((Object _) {}));
      };
      setState(() => tv = service);
    } catch (e) {
      await service?.dispose();
      if (mounted) setState(() => tvError = 'TV service unavailable: $e');
    } finally {
      if (mounted) setState(() => tvLoading = false);
    }
  }

  void _releaseMods() {
    final signaling = _signaling;
    for (final m in mods) {
      signaling.sendInput({'t': 'key', 'code': m, 'down': false});
    }
    mods.clear();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    if (lifecycle == AppLifecycleState.paused) setState(_releaseMods);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _releaseMods();
    final signaling = _signaling;
    signaling.tvHandler = null;
    signaling.onSessionEnded = null;
    signaling.onAudit = null;
    signaling.onSecretUsed = null;
    if (tv != null) unawaited(tv!.dispose());
    final connection = direct;
    if (connection != null) {
      signaling.onDirectEnded = null;
      unawaited(connection.stop().whenComplete(connection.dispose));
    }
    store?.close();
    endpoint.dispose();
    peer.dispose();
    outgoingFile.dispose();
    remoteText.dispose();
    unattendedSecret.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(signalingProvider);
    if (state.sessionId == null) {
      mods.clear(); // channel is gone; nothing to release
      tx = ty = .5;
    }
    if (state.incomingSession != null &&
        shownIncoming != state.incomingSession) {
      shownIncoming = state.incomingSession;
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        if (!mounted || state.incomingSession != shownIncoming) return;
        var preset = 'basic';
        var quality = 'balanced';
        String? sourceId;
        List<DesktopCapturerSource> sources = [];
        if (Platform.isWindows || Platform.isLinux) {
          try {
            sources = await desktopCapturer.getSources(
              types: [SourceType.Screen],
            );
          } catch (_) {
            /* OS picker remains available. */
          }
        }
        if (!mounted || state.incomingSession != shownIncoming) return;
        await showDialog<void>(
          context: context,
          barrierDismissible: false,
          builder: (context) => StatefulBuilder(
            builder: (context, setDialogState) => AlertDialog(
              title: const Text('Allow this device?'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Device ${state.incomingController} requests access. Screen capture requires a separate system prompt.',
                  ),
                  if (sources.isNotEmpty)
                    const Text(
                      'For remote input, choose a screen explicitly. Input is available only when the local display mapping is verified safe.',
                    ),
                  if (sources.isNotEmpty)
                    DropdownButton<String>(
                      value: sourceId,
                      isExpanded: true,
                      hint: const Text('System screen picker'),
                      onChanged: (value) =>
                          setDialogState(() => sourceId = value),
                      items: [
                        for (final source in sources)
                          DropdownMenuItem(
                            value: source.id,
                            child: Text(source.name),
                          ),
                      ],
                    ),
                  DropdownButton<String>(
                    value: quality,
                    isExpanded: true,
                    onChanged: (value) =>
                        setDialogState(() => quality = value!),
                    items: const [
                      DropdownMenuItem(
                        value: 'low',
                        child: Text('Low latency'),
                      ),
                      DropdownMenuItem(
                        value: 'balanced',
                        child: Text('Balanced'),
                      ),
                      DropdownMenuItem(
                        value: 'high',
                        child: Text('High quality'),
                      ),
                    ],
                  ),
                  DropdownButton<String>(
                    value: preset,
                    isExpanded: true,
                    onChanged: (value) => setDialogState(() => preset = value!),
                    items: const [
                      DropdownMenuItem(
                        value: 'basic',
                        child: Text('Basic - view only'),
                      ),
                      DropdownMenuItem(
                        value: 'normal',
                        child: Text('Normal - view and input'),
                      ),
                      DropdownMenuItem(
                        value: 'full',
                        child: Text('Full - elevated access'),
                      ),
                    ],
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () {
                    state.deny();
                    Navigator.pop(context);
                  },
                  child: const Text('Decline'),
                ),
                FilledButton(
                  onPressed: () async {
                    var confirmed = false;
                    if (preset == 'full') {
                      confirmed = await showDialog<bool>(
                            context: context,
                            builder: (context) => AlertDialog(
                              title: const Text('Confirm elevated access'),
                              content: const Text(
                                'Full access permits sensitive operations. Only approve a trusted device.',
                              ),
                              actions: [
                                TextButton(
                                  onPressed: () =>
                                      Navigator.pop(context, false),
                                  child: const Text('Cancel'),
                                ),
                                FilledButton(
                                  onPressed: () => Navigator.pop(context, true),
                                  child: const Text('Confirm full access'),
                                ),
                              ],
                            ),
                          ) ??
                          false;
                      if (!confirmed) return;
                    }
                    if (!context.mounted) return;
                    Navigator.pop(context);
                    await state.accept(
                      preset,
                      elevatedConfirmed: confirmed,
                      sourceId: sourceId,
                      quality: quality,
                    );
                  },
                  child: const Text('Allow'),
                ),
              ],
            ),
          ),
        );
      });
    }
    final fileOffer = state.fileOffer;
    final fileOfferSession = state.sessionId;
    if (fileOffer != null && shownFileOffer != fileOffer['id']) {
      shownFileOffer = fileOffer['id'] as String;
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        if (!mounted || state.fileOffer?['id'] != shownFileOffer) return;
        final directory = TextEditingController();
        final filename = TextEditingController(
          text: fileOffer['name'] as String,
        );
        await showDialog<void>(
          context: context,
          barrierDismissible: false,
          builder: (context) => AlertDialog(
            title: const Text('Receive file?'),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    'Requested: ${fileOffer['name']} (${fileOffer['size']} bytes). Choose a local destination; existing files will not be overwritten.',
                  ),
                  TextField(
                    controller: directory,
                    decoration: const InputDecoration(
                      labelText: 'Local destination directory',
                    ),
                  ),
                  TextField(
                    controller: filename,
                    decoration: const InputDecoration(
                      labelText: 'Local filename',
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () {
                  Navigator.pop(context);
                  state.answerFileOffer(
                    allow: false,
                    offerId: fileOffer['id'] as String,
                    offerSession: fileOfferSession!,
                  );
                },
                child: const Text('Decline'),
              ),
              FilledButton(
                onPressed: () {
                  final dir = directory.text.trim(),
                      name = filename.text.trim();
                  if (dir.isEmpty || name.isEmpty) return;
                  Navigator.pop(context);
                  state.answerFileOffer(
                    allow: true,
                    offerId: fileOffer['id'] as String,
                    offerSession: fileOfferSession!,
                    directory: dir,
                    filename: name,
                  );
                },
                child: const Text('Receive'),
              ),
            ],
          ),
        );
        directory.dispose();
        filename.dispose();
      });
    }
    final identity = Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('This device', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 12),
            SelectableText(state.deviceId ?? 'Connect to see your device ID'),
            const SizedBox(height: 8),
            Text('Status: ${state.status}'),
            if (Platform.isAndroid)
              TextButton(
                onPressed: () async {
                  final approved = await showDialog<bool>(
                    context: context,
                    builder: (context) => AlertDialog(
                      title: const Text('Accessibility access'),
                      content: const Text(
                        'Accessibility lets an approved remote controller perform input on this device during an active session. A visible notification remains while a session is active. You can revoke access at any time.',
                      ),
                      actions: [
                        TextButton(
                          onPressed: () => Navigator.pop(context, false),
                          child: const Text('Cancel'),
                        ),
                        FilledButton(
                          onPressed: () => Navigator.pop(context, true),
                          child: const Text('Open settings'),
                        ),
                      ],
                    ),
                  );
                  if (approved == true) await state.openAccessibilitySettings();
                },
                child: const Text('Set up Android input'),
              ),
            const SizedBox(height: 16),
            TextField(
              controller: endpoint,
              enabled: !state.connected,
              decoration: const InputDecoration(
                labelText: 'Signaling URL',
                hintText: 'wss://your-server/v1/ws',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: state.connected
                  ? () => state.disconnect()
                  : () => state.connect(endpoint.text.trim()),
              child: Text(state.connected ? 'Disconnect' : 'Go online'),
            ),
          ],
        ),
      ),
    );
    final connect = Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Connect to a device',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 12),
            const Text(
              'The other device must approve your request and screen capture.',
            ),
            const SizedBox(height: 16),
            TextField(
              controller: peer,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                labelText: '12-digit device ID',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            OutlinedButton(
              onPressed: store == null ? null : _saveDevice,
              child: const Text('Save device ID'),
            ),
            if (storageError != null) Text(storageError!),
            for (final id in saved)
              ListTile(
                title: Text(id),
                trailing: const Icon(Icons.chevron_right),
                onTap: () => peer.text = id,
              ),
            TextField(
              controller: unattendedSecret,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Unattended password (optional)',
              ),
            ),
            FilledButton.tonal(
              onPressed: state.connected && state.sessionId == null
                  ? () {
                      state.unattendedSecret = unattendedSecret.text;
                      state.request(peer.text.trim());
                    }
                  : null,
              child: const Text('Request access'),
            ),
            if (state.sessionId != null) ...[
              const SizedBox(height: 12),
              FilledButton(
                onPressed: state.end,
                style: FilledButton.styleFrom(
                  backgroundColor: Theme.of(context).colorScheme.error,
                ),
                child: const Text('End session'),
              ),
            ],
          ],
        ),
      ),
    );
    return Scaffold(
      appBar: AppBar(title: const Text('Remote Link')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (state.error != null)
              Card(
                color: Theme.of(context).colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(state.error!),
                ),
              ),
            if (state.reconnecting)
              Card(
                child: ListTile(
                  leading: const SizedBox.square(
                    dimension: 24,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  title: const Text('Reconnecting…'),
                  trailing: TextButton(
                    onPressed: state.cancelReconnect,
                    child: const Text('Cancel'),
                  ),
                ),
              ),
            LayoutBuilder(
              builder: (context, constraints) => constraints.maxWidth >= 720
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(child: identity),
                        Expanded(child: connect),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [identity, connect],
                    ),
            ),
            if (state.sessionId != null)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    children: [
                      Text(
                        state.target
                            ? 'Screen sharing active or awaiting permission'
                            : 'Remote screen',
                      ),
                      if (state.fileStatus != null) Text(state.fileStatus!),
                      if (state.notice != null) Text(state.notice!),
                      if (state.trustStatus != null) Text(state.trustStatus!),
                      if (state.canTrustController)
                        OutlinedButton(
                          onPressed: () async {
                            var allowFull = false;
                            final ok = await showDialog<bool>(
                              context: context,
                              builder: (context) => StatefulBuilder(
                                builder: (context, setDialogState) => AlertDialog(
                                  title: const Text('Trust this device?'),
                                  content: Column(
                                    mainAxisSize: MainAxisSize.min,
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        'It will connect without a prompt as "${state.trustablePreset(allowFull: allowFull)}" until you revoke it in Settings.',
                                      ),
                                      if (state.acceptedPreset == 'full')
                                        CheckboxListTile(
                                          contentPadding: EdgeInsets.zero,
                                          value: allowFull,
                                          onChanged: (v) => setDialogState(
                                            () => allowFull = v ?? false,
                                          ),
                                          title: const Text(
                                            'Allow full unattended access',
                                          ),
                                        ),
                                    ],
                                  ),
                                  actions: [
                                    TextButton(
                                      onPressed: () => Navigator.pop(context, false),
                                      child: const Text('Cancel'),
                                    ),
                                    FilledButton(
                                      onPressed: () => Navigator.pop(context, true),
                                      child: const Text('Trust'),
                                    ),
                                  ],
                                ),
                              ),
                            );
                            if (ok == true)
                              state.trustController(allowFull: allowFull);
                          },
                          child: const Text('Trust this device'),
                        ),
                      if (state.enrollRequested) ...[
                        const Text(
                          'The other device asks to trust this device for future unattended access.',
                        ),
                        Wrap(
                          spacing: 8,
                          children: [
                            FilledButton(
                              onPressed: () => state.answerEnroll(true),
                              child: const Text('Agree'),
                            ),
                            OutlinedButton(
                              onPressed: () => state.answerEnroll(false),
                              child: const Text('Decline'),
                            ),
                          ],
                        ),
                      ],
                      if (!state.target && state.monitors.length > 1)
                        DropdownButton<int>(
                          value: state.display,
                          isExpanded: true,
                          hint: const Text('Monitor (input target)'),
                          onChanged: state.selectDisplay,
                          items: [
                            for (final m in state.monitors)
                              DropdownMenuItem(
                                value: m.id,
                                child: Text(
                                  'Monitor ${m.id + 1} (${m.w}x${m.h})${m.primary ? ' - primary' : ''}',
                                ),
                              ),
                          ],
                        ),
                      if (!state.target) ...[
                        TextField(
                          controller: outgoingFile,
                          decoration: const InputDecoration(
                            labelText: 'Local file path (Full access required)',
                          ),
                        ),
                        OutlinedButton(
                          onPressed: () =>
                              state.sendFile(outgoingFile.text.trim()),
                          child: const Text('Offer file'),
                        ),
                      ],
                      if (!state.target)
                        OutlinedButton(
                          onPressed: state.sendClipboard,
                          child: const Text('Send clipboard text'),
                        ),
                      if (!state.target)
                        Wrap(
                          spacing: 8,
                          children: [
                            for (final code in const [
                              'ControlLeft',
                              'AltLeft',
                              'MetaLeft',
                            ])
                              FilterChip(
                                label: Text(
                                  code == 'MetaLeft'
                                      ? 'Win'
                                      : code.substring(0, code.length - 4),
                                ),
                                selected: mods.contains(code),
                                onSelected: (on) {
                                  state.sendInput({
                                    't': 'key',
                                    'code': code,
                                    'down': on,
                                  });
                                  setState(
                                    () =>
                                        on ? mods.add(code) : mods.remove(code),
                                  );
                                },
                              ),
                            for (final code in const [
                              'Escape',
                              'Tab',
                              'Enter',
                              'Backspace',
                              'ArrowUp',
                              'ArrowDown',
                              'ArrowLeft',
                              'ArrowRight',
                            ])
                              OutlinedButton(
                                onPressed: () {
                                  state.sendInput({
                                    't': 'key',
                                    'code': code,
                                    'down': true,
                                  });
                                  state.sendInput({
                                    't': 'key',
                                    'code': code,
                                    'down': false,
                                  });
                                  // Sticky modifiers apply to one key.
                                  setState(_releaseMods);
                                },
                                child: Text(code),
                              ),
                            OutlinedButton(
                              onPressed: state.sendSecureAttention,
                              child: const Text('Ctrl+Alt+Del'),
                            ),
                            PopupMenuButton<String>(
                              tooltip: 'More keys',
                              onSelected: (code) => _tapKey(state, code),
                              itemBuilder: (context) => [
                                for (final code in [
                                  for (var i = 1; i <= 12; i++) 'F$i',
                                  'Home',
                                  'End',
                                  'PageUp',
                                  'PageDown',
                                  'Delete',
                                  'Insert',
                                ])
                                  PopupMenuItem(value: code, child: Text(code)),
                              ],
                              child: const Padding(
                                padding: EdgeInsets.all(12),
                                child: Text('More keys'),
                              ),
                            ),
                          ],
                        ),
                      if (!state.target)
                        Row(
                          children: [
                            Expanded(
                              child: TextField(
                                controller: remoteText,
                                maxLength: 1024,
                                decoration: const InputDecoration(
                                  labelText: 'Type text on the remote device',
                                ),
                              ),
                            ),
                            IconButton(
                              tooltip: 'Send text',
                              icon: const Icon(Icons.send),
                              onPressed: () {
                                state.sendText(remoteText.text);
                                remoteText.clear();
                              },
                            ),
                          ],
                        ),
                      if (!state.target && state.hasAudio)
                        SwitchListTile(
                          title: const Text('Mute remote audio'),
                          value: state.muted,
                          onChanged: (_) => state.toggleMute(),
                        ),
                      if (!state.target)
                        SwitchListTile(
                          title: const Text('Trackpad mode'),
                          value: trackpad,
                          onChanged: (on) => setState(() {
                            trackpad = on;
                            tx = ty = .5;
                          }),
                        ),
                      if (!state.target && state.rendererReady)
                        AspectRatio(
                          aspectRatio: 16 / 9,
                          child: LayoutBuilder(
                            builder: (context, constraints) {
                              void click() {
                                for (final down in const [true, false]) {
                                  state.sendInput({
                                    't': 'mouse_btn',
                                    'b': 'left',
                                    'down': down,
                                  });
                                }
                                setState(_releaseMods);
                              }

                              return GestureDetector(
                                onTapDown: trackpad
                                    ? null
                                    : (details) {
                                        final point = mapVideoPointer(
                                          details.localPosition.dx,
                                          details.localPosition.dy,
                                          constraints.maxWidth,
                                          constraints.maxHeight,
                                          state.renderer.videoWidth.toDouble(),
                                          state.renderer.videoHeight.toDouble(),
                                        );
                                        if (point == null) return;
                                        state.sendInput({
                                          't': 'mouse_move',
                                          'x': point.x,
                                          'y': point.y,
                                        });
                                        click();
                                      },
                                onTap: trackpad ? click : null,
                                onPanUpdate: trackpad
                                    ? (details) {
                                        final vw = state.renderer.videoWidth,
                                            vh = state.renderer.videoHeight;
                                        if (constraints.maxWidth <= 0 ||
                                            constraints.maxHeight <= 0 ||
                                            vw <= 0 ||
                                            vh <= 0) {
                                          return;
                                        }
                                        // The protocol has no delta event, so integrate into an absolute position.
                                        // Deltas are scaled by the letterboxed video rect, as in mapVideoPointer.
                                        final scale = math.min(
                                          constraints.maxWidth / vw,
                                          constraints.maxHeight / vh,
                                        );
                                        tx = (tx + details.delta.dx / (vw * scale))
                                            .clamp(0.0, 1.0);
                                        ty = (ty + details.delta.dy / (vh * scale))
                                            .clamp(0.0, 1.0);
                                        state.sendInput({
                                          't': 'mouse_move',
                                          'x': tx,
                                          'y': ty,
                                        });
                                      }
                                    : null,
                                child: RTCVideoView(state.renderer),
                              );
                            },
                          ),
                        ),
                    ],
                  ),
                ),
              ),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: direct == null
                    ? Column(
                        children: [
                          const Text(
                            'Direct IP is off by default. It requires owner-controlled TLS credentials and explicit identity confirmation.',
                          ),
                          if (directError != null) Text(directError!),
                          OutlinedButton(
                            onPressed: () {
                              try {
                                final connection = DirectConnection(state);
                                state.onDirectEnded = connection.end;
                                setState(() {
                                  direct = connection;
                                  directError = null;
                                });
                              } catch (e) {
                                setState(
                                  () => directError =
                                      'Direct mode unavailable: $e',
                                );
                              }
                            },
                            child: const Text('Open direct IP controls'),
                          ),
                        ],
                      )
                    : DirectPanel(connection: direct!),
              ),
            ),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: tv == null
                    ? Column(
                        children: [
                          const Text(
                            'TV bridge uses only TVs configured locally by their owner.',
                          ),
                          if (tvError != null) Text(tvError!),
                          OutlinedButton(
                            onPressed: tvLoading ? null : _openTv,
                            child: const Text('Open TV controls'),
                          ),
                        ],
                      )
                    : TvPanel(
                        service: tv!,
                        remoteEnabled: !state.target && state.sessionId != null,
                        sendRemote: state.sendTv,
                      ),
              ),
            ),
            SettingsPanel(signaling: state),
            Card(
              child: ExpansionTile(
                title: const Text('Local audit'),
                children: [
                  if (auditEntries.isEmpty)
                    const ListTile(
                      title: Text('No local events recorded yet.'),
                    ),
                  for (final entry in auditEntries)
                    ListTile(title: Text(entry)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
