import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:tv_bridge/tv_bridge.dart';

import 'native_core.dart';

/// Local configuration is never accepted from a remote request.
class TvService {
  TvService({NativeCore? core, FlutterSecureStorage? storage})
    : _core = core ?? NativeCore(),
      _storage = storage ?? const FlutterSecureStorage();
  final NativeCore _core;
  final FlutterSecureStorage _storage;
  final Map<String, Map<String, String>> _configs = {};
  final Map<String, TvAdapter> _adapters = {};
  Future<void>? _initializing;
  Future<void> _tail = Future.value();
  int _queued = 0;
  int _generation = 0;
  bool _disposed = false;
  static const _storageKey = 'tv.configs.v1';
  static const _lgManifest = <String, dynamic>{
    'manifestVersion': 1,
    'permissions': [
      'LAUNCH',
      'CONTROL_AUDIO',
      'CONTROL_POWER',
      'CONTROL_INPUT_TEXT',
      'CONTROL_MOUSE_AND_KEYBOARD',
    ],
  };
  static const _keys = <String, Map<String, String>>{
    'androidtv': {
      'up': 'DPAD_UP',
      'down': 'DPAD_DOWN',
      'left': 'DPAD_LEFT',
      'right': 'DPAD_RIGHT',
      'enter': 'DPAD_CENTER',
      'back': 'BACK',
      'home': 'HOME',
      'volume_up': 'VOLUME_UP',
      'volume_down': 'VOLUME_DOWN',
      'mute': 'MUTE',
      'power_off': 'POWER',
    },
    'firetv': {
      'up': 'DPAD_UP',
      'down': 'DPAD_DOWN',
      'left': 'DPAD_LEFT',
      'right': 'DPAD_RIGHT',
      'enter': 'DPAD_CENTER',
      'back': 'BACK',
      'home': 'HOME',
      'volume_up': 'VOLUME_UP',
      'volume_down': 'VOLUME_DOWN',
      'mute': 'MUTE',
      'power_off': 'POWER',
    },
    'vizio': {
      'up': 'UP',
      'down': 'DOWN',
      'left': 'LEFT',
      'right': 'RIGHT',
      'enter': 'OK',
      'back': 'BACK',
      'home': 'HOME',
      'volume_up': 'VOL_UP',
      'volume_down': 'VOL_DOWN',
      'mute': 'MUTE_TOGGLE',
      'power_off': 'POWER_OFF',
    },
    'samsung': {
      'up': 'KEY_UP',
      'down': 'KEY_DOWN',
      'left': 'KEY_LEFT',
      'right': 'KEY_RIGHT',
      'enter': 'KEY_ENTER',
      'back': 'KEY_RETURN',
      'home': 'KEY_HOME',
      'volume_up': 'KEY_VOLUP',
      'volume_down': 'KEY_VOLDOWN',
      'mute': 'KEY_MUTE',
      'power_off': 'KEY_POWEROFF',
    },
    'lg': {
      'up': 'up',
      'down': 'down',
      'left': 'left',
      'right': 'right',
      'enter': 'enter',
      'back': 'back',
      'home': 'home',
      'volume_up': 'volume_up',
      'volume_down': 'volume_down',
      'power_off': 'power_off',
    },
    'roku': {
      'up': 'Up',
      'down': 'Down',
      'left': 'Left',
      'right': 'Right',
      'enter': 'Select',
      'back': 'Back',
      'home': 'Home',
      'volume_up': 'VolumeUp',
      'volume_down': 'VolumeDown',
      'mute': 'VolumeMute',
      'power_off': 'PowerOff',
    },
  };

  Future<void> initialize() => _initializing ??= _load();
  Future<void> _load() async {
    if (_disposed) throw StateError('TV service closed');
    final raw = await _storage.read(key: _storageKey);
    if (raw == null) return;
    final decoded = jsonDecode(raw);
    if (decoded is! List || decoded.length > 100)
      throw StateError('Invalid TV configuration');
    for (final item in decoded) {
      if (item is! Map ||
          item['id'] is! String ||
          item['brand'] is! String ||
          item['host'] is! String ||
          item['pin'] is! String ||
          !_keys.containsKey(item['brand']) ||
          !RegExp(r'^[A-Za-z0-9_-]{16,32}$').hasMatch(item['id'] as String))
        throw StateError('Invalid TV configuration');
      final config = <String, String>{
        'id': item['id'] as String,
        'brand': item['brand'] as String,
        'host': item['host'] as String,
        'pin': item['pin'] as String,
      };
      if (_configs.containsKey(config['id']))
        throw StateError('Duplicate TV id');
      _configs[config['id']!] = config;
    }
  }

  Future<void> _save() => _storage.write(
    key: _storageKey,
    value: jsonEncode(_configs.values.toList()),
  );
  String _digest(List<int> der) {
    final output = _core.call({'op': 'sha256', 'data': base64Encode(der)});
    return base64Decode(output['sha256'] as String)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// Remote v2 needs a client cert the TV remembers. Pure Dart cannot create RSA certs, so
  /// generate once with the `openssl` CLI (desktop) and keep it in secure storage.
  Future<({String cert, String key})> _androidTvIdentity() async {
    var cert = await _storage.read(key: 'tv.androidtv.cert');
    var key = await _storage.read(key: 'tv.androidtv.key');
    if (cert != null && key != null) return (cert: cert, key: key);
    final dir = await Directory.systemTemp.createTemp('atv');
    try {
      final r = await Process.run('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', //
        '-keyout', '${dir.path}/k.pem', '-out', '${dir.path}/c.pem',
        '-days', '3650', '-subj', '/CN=atvremote',
      ]);
      if (r.exitCode != 0) throw StateError('openssl failed: ${r.stderr}');
      cert = await File('${dir.path}/c.pem').readAsString();
      key = await File('${dir.path}/k.pem').readAsString();
    } on ProcessException {
      throw StateError('Android TV needs a client certificate: install openssl');
    } finally {
      await dir.delete(recursive: true);
    }
    await _storage.write(key: 'tv.androidtv.cert', value: cert);
    await _storage.write(key: 'tv.androidtv.key', value: key);
    return (cert: cert, key: key);
  }

  TvAdapter _make(
    Map<String, String> config, [
    Future<String> Function()? readPin,
  ]) {
    readPin ??= () async => throw StateError('PIN entry unavailable');
    final host = config['host']!, id = config['id']!, pin = config['pin']!;
    Future<bool> approved(String address, String? fingerprint) async =>
        address == host &&
        (const {'roku', 'firetv'}.contains(config['brand'])
            ? fingerprint == null : fingerprint == pin);
    Future<String?> read(String _) => _storage.read(key: 'tv.credential.$id');
    Future<void> write(String _, String value) =>
        _storage.write(key: 'tv.credential.$id', value: value);
    switch (config['brand']) {
      case 'roku':
        return RokuAdapter(host, approved);
      case 'samsung':
        return SamsungAdapter(host, approved, pin, _digest, read, write);
      case 'lg':
        return LgAdapter(
          host,
          approved,
          pin,
          _digest,
          read,
          write,
          _lgManifest,
        );
      case 'androidtv':
        return AndroidTvAdapter(
          host,
          approved,
          pin,
          _digest,
          read,
          write,
          _androidTvIdentity,
          readPin,
        );
      case 'firetv':
        return AdbAdapter(host, approved);
      case 'vizio':
        return VizioAdapter(host, approved, pin, _digest, read, write, readPin);
      default:
        throw UnsupportedError('Unsupported TV brand');
    }
  }

  TvAdapter _adapter(String id) =>
      _adapters.putIfAbsent(id, () => _make(_configs[id]!));
  Future<T> _serial<T>(Future<T> Function(int generation) work) {
    if (_disposed) return Future.error(StateError('TV service closed'));
    if (_queued >= 16) return Future.error(StateError('TV command queue full'));
    _queued++;
    final generation = _generation;
    final task = _tail.then((_) async {
      if (_disposed || generation != _generation)
        throw StateError('TV command cancelled');
      await initialize();
      if (_disposed || generation != _generation)
        throw StateError('TV command cancelled');
      return work(generation);
    });
    _tail = task.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return task.whenComplete(() => _queued--);
  }

  /// Only call after explicit local owner confirmation of the address and pin.
  Future<void> pairLocal({
    required String brand,
    required String host,
    String? fingerprint,
    required bool confirmed,
    Future<String> Function()? readPin,
  }) => _serial((generation) async {
    if (!confirmed || !_keys.containsKey(brand))
      throw ArgumentError('Local confirmation and supported brand required');
    final pin = (fingerprint ?? '').trim().toLowerCase().replaceAll(':', '');
    if (!const {'roku', 'firetv'}.contains(brand) &&
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(pin))
      throw ArgumentError('Verified certificate SHA-256 required');
    if (_configs.length >= 100) throw StateError('TV limit reached');
    final random = Random.secure();
    final id = base64UrlEncode(
      List<int>.generate(16, (_) => random.nextInt(256)),
    ).replaceAll('=', '');
    final config = {'id': id, 'brand': brand, 'host': host.trim(), 'pin': pin};
    final adapter = _make(config, readPin);
    _adapters[id] = adapter;
    try {
      await adapter.pair();
      if (_disposed || generation != _generation)
        throw StateError('Pairing cancelled');
      _configs[id] = config;
      try {
        await _save();
      } catch (_) {
        _configs.remove(id);
        rethrow;
      }
    } catch (_) {
      _adapters.remove(id);
      await adapter.close();
      await _storage.delete(key: 'tv.credential.$id');
      rethrow;
    }
  });
  List<Map<String, dynamic>> _list() => _configs.values.map((c) {
    final a = _adapter(c['id']!);
    return <String, dynamic>{
      'id': c['id'],
      'brand': c['brand'],
      'capabilities': a.capabilities.toList(),
      'keys': _keys[c['brand']]!.keys.toList(),
      'screenView': false,
    };
  }).toList();
  void _validate(Map<String, dynamic> request) {
    final action = request['action'];
    if (action is! String ||
        !const {'list', 'key', 'state', 'text', 'app'}.contains(action))
      throw ArgumentError('Invalid TV action');
    final allowed = action == 'list'
        ? {'action'}
        : (action == 'state' ? {'action', 'id'} : {'action', 'id', 'value'});
    if (request.length != allowed.length ||
        request.keys.any((k) => !allowed.contains(k)))
      throw ArgumentError('Invalid TV request fields');
    if (action != 'list' &&
        (request['id'] is! String ||
            !RegExp(r'^[A-Za-z0-9_-]{16,32}$')
                .hasMatch(request['id'] as String)))
      throw ArgumentError('Invalid TV id');
    if (allowed.contains('value') &&
        (request['value'] is! String ||
            (request['value'] as String).isEmpty ||
            utf8.encode(request['value'] as String).length > 4096))
      throw ArgumentError('Invalid TV value');
  }

  Future<Map<String, dynamic>> dispatch(
    String sessionId,
    Map<String, dynamic> request,
  ) {
    request = Map<String, dynamic>.of(request);
    _validate(request);
    if (sessionId.isEmpty || sessionId.length > 128)
      throw ArgumentError('Invalid session');
    final action = request['action'] as String;
    final cap = action == 'text' || action == 'app' ? 'tv_apps' : 'tv_keys';
    _core.call({
      'op': 'session_check',
      'session_id': sessionId,
      'capability': cap,
    });
    return _serial((generation) async {
      _core.call({
        'op': 'session_check',
        'session_id': sessionId,
        'capability': cap,
      });
      return _execute(request, generation);
    });
  }

  Future<Map<String, dynamic>> localDispatch(Map<String, dynamic> request) {
    request = Map<String, dynamic>.of(request);
    _validate(request);
    return _serial((generation) => _execute(request, generation));
  }

  Future<Map<String, dynamic>> _execute(
    Map<String, dynamic> request,
    int generation,
  ) async {
    final action = request['action'] as String;
    if (action == 'list') return {'devices': _list(), 'screenView': false};
    final id = request['id'] as String;
    final config = _configs[id];
    if (config == null) throw StateError('Unknown TV id');
    final adapter = _adapter(id);
    switch (action) {
      case 'key':
        final key = _keys[config['brand']]![request['value']];
        if (key == null) throw UnsupportedError('Key unsupported by this TV');
        await adapter.sendKey(key);
      case 'text':
        await adapter.sendText(request['value'] as String);
      case 'app':
        await adapter.launchApp(request['value'] as String);
      case 'state':
        final state = await adapter.getState();
        if (_disposed || generation != _generation)
          throw StateError('TV command cancelled');
        return {'state': state};
    }
    if (_disposed || generation != _generation)
      throw StateError('TV command cancelled');
    return {
      'status': 'sent',
      'note': 'Transport accepted the command; physical execution is not confirmed.',
    };
  }

  /// Local-only: installs the companion APK on a paired Fire TV.
  Future<void> installApk(String id, String path) async {
    if (_configs[id]?['brand'] != 'firetv') throw StateError('Not a Fire TV');
    final a = _adapter(id);
    if (a is! AdbAdapter) throw StateError('Not an ADB adapter');
    await a.installApk(path);
  }

  /// Unverified LAN candidates; the owner still confirms the address before pairing.
  Future<List<Map<String, String>>> discover() async => [
    for (final d in await discoverTvs()) {'brand': d.brand, 'host': d.host},
  ];

  Future<void> cancelPending() async {
    _generation++;
    final closing = _adapters.values.toList();
    _adapters.clear();
    await Future.wait(closing.map((adapter) => adapter.close()));
  }

  Future<void> dispose() async {
    _disposed = true;
    await cancelPending();
  }
}
