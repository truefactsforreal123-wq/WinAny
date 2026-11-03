import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

import 'signaling.dart';
import 'video_pointer.dart';

/// Full-screen remote view for the controller. Pops itself when the session ends.
class SessionView extends StatefulWidget {
  const SessionView({super.key, required this.signaling});
  final Signaling signaling;
  @override
  State<SessionView> createState() => _SessionViewState();
}

class _SessionViewState extends State<SessionView> with WidgetsBindingObserver {
  static final _mobile = Platform.isAndroid || Platform.isIOS;
  final mods = <String>{};
  bool trackpad = false;
  bool toolbar = true;
  double tx = .5, ty = .5;
  Timer? _hide;

  Signaling get state => widget.signaling;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    if (_mobile) {
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
      SystemChrome.setPreferredOrientations(DeviceOrientation.values);
    }
    _showToolbar();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycle) {
    if (lifecycle == AppLifecycleState.paused) setState(_releaseMods);
    if (lifecycle == AppLifecycleState.resumed && _mobile) {
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _hide?.cancel();
    _releaseMods();
    if (_mobile) {
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
      SystemChrome.setPreferredOrientations(
          const []); // back to platform default
    }
    super.dispose();
  }

  void _releaseMods() {
    for (final m in mods) {
      state.sendInput({'t': 'key', 'code': m, 'down': false});
    }
    mods.clear();
  }

  void _tapKey(String code) {
    for (final down in const [true, false]) {
      state.sendInput({'t': 'key', 'code': code, 'down': down});
    }
    setState(_releaseMods); // sticky modifiers apply to one key
  }

  void _showToolbar() {
    _hide?.cancel();
    setState(() => toolbar = true);
    _hide = Timer(const Duration(seconds: 3), () {
      if (mounted) setState(() => toolbar = false);
    });
  }

  Widget _video() => LayoutBuilder(
        builder: (context, constraints) {
          void click() {
            for (final down in const [true, false]) {
              state.sendInput({'t': 'mouse_btn', 'b': 'left', 'down': down});
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
                    tx = (tx + details.delta.dx / (vw * scale)).clamp(0.0, 1.0);
                    ty = (ty + details.delta.dy / (vh * scale)).clamp(0.0, 1.0);
                    state.sendInput({'t': 'mouse_move', 'x': tx, 'y': ty});
                  }
                : null,
            child: RTCVideoView(
              state.renderer,
              objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitContain,
            ),
          );
        },
      );

  Widget _bar() => Material(
        color: Colors.black87,
        borderRadius: BorderRadius.circular(8),
        child: SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          child: Theme(
            data: ThemeData.dark(),
            child: Row(
              children: [
                IconButton(
                  tooltip: 'Exit full screen',
                  icon: const Icon(Icons.fullscreen_exit),
                  onPressed: () => Navigator.of(context).maybePop(),
                ),
                IconButton(
                  tooltip: 'Disconnect',
                  icon: const Icon(Icons.call_end, color: Colors.redAccent),
                  onPressed: state.end,
                ),
                if (state.viewOnly)
                  const Padding(
                    padding: EdgeInsets.symmetric(horizontal: 8),
                    child: Text('View only'),
                  )
                else
                  IconButton(
                    tooltip: 'Trackpad mode',
                    isSelected: trackpad,
                    icon: const Icon(Icons.touch_app_outlined),
                    selectedIcon: const Icon(Icons.touch_app),
                    onPressed: () => setState(() {
                      trackpad = !trackpad;
                      tx = ty = .5;
                    }),
                  ),
                if (state.hasAudio)
                  IconButton(
                    tooltip: state.muted ? 'Unmute' : 'Mute remote audio',
                    icon:
                        Icon(state.muted ? Icons.volume_off : Icons.volume_up),
                    onPressed: state.toggleMute,
                  ),
                if (state.monitors.length > 1)
                  DropdownButton<int>(
                    value: state.display,
                    hint: const Text('Monitor'),
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
                if (!state.viewOnly) ...[
                  for (final code in const [
                    'ControlLeft',
                    'AltLeft',
                    'MetaLeft'
                  ])
                    Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 2),
                      child: FilterChip(
                        label: Text(
                          code == 'MetaLeft'
                              ? 'Win'
                              : code.substring(0, code.length - 4),
                        ),
                        selected: mods.contains(code),
                        onSelected: (on) {
                          state.sendInput(
                              {'t': 'key', 'code': code, 'down': on});
                          setState(
                            () => on ? mods.add(code) : mods.remove(code),
                          );
                        },
                      ),
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
                    TextButton(
                      onPressed: () => _tapKey(code),
                      child: Text(code),
                    ),
                  TextButton(
                    onPressed: state.sendSecureAttention,
                    child: const Text('Ctrl+Alt+Del'),
                  ),
                  PopupMenuButton<String>(
                    tooltip: 'More keys',
                    onSelected: _tapKey,
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
              ],
            ),
          ),
        ),
      );

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: state,
        builder: (context, _) {
          if (state.sessionId == null) {
            WidgetsBinding.instance.addPostFrameCallback((_) {
              if (!mounted) return;
              final route = ModalRoute.of(context);
              if (route == null) return;
              // maybePop would pop a popup or dialog on top instead of this route.
              if (route.isCurrent) {
                Navigator.of(context).pop();
              } else {
                Navigator.of(context).removeRoute(route);
              }
            });
          }
          return CallbackShortcuts(
            bindings: {
              const SingleActivator(LogicalKeyboardKey.escape): () =>
                  Navigator.of(context).maybePop(),
            },
            child: Focus(
              autofocus: true,
              child: Scaffold(
                backgroundColor: Colors.black,
                body: Stack(
                  children: [
                    SizedBox.expand(
                      child: state.rendererReady ? _video() : const SizedBox(),
                    ),
                    SafeArea(
                      child: Align(
                        alignment: Alignment.topCenter,
                        child: toolbar
                            ? _bar()
                            : IconButton(
                                tooltip: 'Show controls',
                                color: Colors.white70,
                                icon: const Icon(Icons.more_horiz),
                                onPressed: _showToolbar,
                              ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          );
        },
      );
}
