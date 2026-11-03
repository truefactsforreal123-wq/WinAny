part of 'tv_bridge.dart';

typedef AdbRunner =
    Future<ProcessResult> Function(String exe, List<String> args);

/// Fire TV / Android TV with ADB debugging on, via the `adb` CLI (desktop only).
/// Always an argument list, never a shell string; text is allow-listed because the
/// device-side `input` command is run through the TV's shell.
class AdbAdapter extends _Base {
  final AdbRunner run;
  AdbAdapter(super.host, super.approve, {AdbRunner? runner})
    : run = runner ?? ((e, a) => Process.run(e, a));
  @override
  Set<String> get capabilities => const {'pair', 'keys', 'text', 'apps'};
  String get _serial => '$host:5555';

  Future<String> _adb(List<String> args) async {
    await authorize();
    final ProcessResult r;
    try {
      r = await run('adb', args).timeout(const Duration(seconds: 30));
    } on ProcessException {
      throw StateError('adb not found: install Android platform-tools');
    }
    final out = '${r.stdout}${r.stderr}'.trim();
    if (r.exitCode != 0) throw StateError('adb failed: $out');
    return out;
  }

  Future<String> _shell(List<String> args) =>
      _adb(['-s', _serial, 'shell', ...args]);

  /// The owner must accept the RSA prompt on the TV; until then state is "unauthorized".
  @override
  Future<void> pair() async {
    final out = await _adb(['connect', _serial]);
    if (!out.contains('connected')) throw StateError('adb connect failed: $out');
    final state = await _adb(['-s', _serial, 'get-state']);
    if (state != 'device')
      throw StateError('Approve the debugging prompt on the TV');
  }

  @override
  Future<void> sendKey(String key) async {
    if (!AndroidTvAdapter.keyCodes.containsKey(key))
      throw ArgumentError('Unsupported key');
    await _shell(['input', 'keyevent', 'KEYCODE_$key']);
  }

  @override
  Future<void> sendText(String text) async {
    _text(text);
    if (text.length > 256 ||
        !RegExp(r'^[A-Za-z0-9 .,_@:/+=-]+$').hasMatch(text))
      throw ArgumentError('Unsupported characters in text');
    await _shell(['input', 'text', text.replaceAll(' ', '%s')]);
  }

  @override
  Future<void> launchApp(String appId) async {
    _app(appId);
    await _shell(['monkey', '-p', appId, '1']);
  }

  /// Installs the Tier A companion APK; the path must be a local file, not an option.
  Future<void> installApk(String path) async {
    if (path.isEmpty || path.startsWith('-') || !File(path).existsSync())
      throw ArgumentError('Invalid APK path');
    await _adb(['-s', _serial, 'install', '-r', path]);
  }
}
