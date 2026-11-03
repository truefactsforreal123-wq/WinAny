import 'dart:async';
import 'dart:convert';
import 'dart:io';

part 'adb.dart';
part 'androidtv.dart';
part 'vizio.dart';

/// A completed command means accepted by transport/device, not physical action.
abstract class TvAdapter {
  Set<String> get capabilities;
  Future<void> pair();
  Future<void> close();
  Future<void> sendKey(String key);
  Future<void> sendText(String text);
  Future<void> launchApp(String appId);
  Future<Map<String, dynamic>> getState();
}

typedef OwnerApproval = Future<bool> Function(String host, String? fingerprint);
typedef CredentialRead = Future<String?> Function(String host);
typedef CredentialWrite = Future<void> Function(String host, String credential);

/// Returns lowercase hexadecimal SHA-256 of the certificate DER using native core.
typedef CertificateDigest = String Function(List<int> der);

void _checkHost(String host) {
  final ip = InternetAddress.tryParse(host);
  if (ip == null || ip.type != InternetAddressType.IPv4)
    throw ArgumentError('Private IPv4 required');
  final b = ip.rawAddress;
  if (!(b[0] == 10 ||
      (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
      (b[0] == 192 && b[1] == 168))) {
    throw ArgumentError('Private IPv4 required');
  }
}

void _text(String s) {
  if (s.isEmpty || utf8.encode(s).length > 4096)
    throw ArgumentError('Invalid text');
}

void _app(String s) {
  if (!RegExp(r'^[A-Za-z0-9._-]{1,128}$').hasMatch(s))
    throw ArgumentError('Invalid app id');
}

abstract class _Base implements TvAdapter {
  final String host;
  final OwnerApproval approve;
  bool _approved = false;
  bool _closed = false;
  final _sockets = <WebSocket>{};
  final _clients = <HttpClient>{};
  @override
  Future<void> close() async {
    _closed = true;
    for (final client in _clients.toList()) {
      client.close(force: true);
    }
    await Future.wait(_sockets.toList().map((socket) => socket.close()));
    _sockets.clear();
    _clients.clear();
  }

  _Base(this.host, this.approve) {
    _checkHost(host);
  }
  Future<void> authorize([String? fingerprint]) async {
    if (_closed) throw StateError('Adapter closed');
    if (!_approved) {
      if (!await approve(host, fingerprint))
        throw StateError('Owner denied TV access');
      if (_closed) throw StateError('Adapter closed');
      _approved = true;
    }
  }

  @override
  Future<void> sendKey(String key) async =>
      throw UnsupportedError('Keys unsupported');
  @override
  Future<void> sendText(String text) async =>
      throw UnsupportedError('Text unsupported');
  @override
  Future<void> launchApp(String appId) async =>
      throw UnsupportedError('Apps unsupported');
  @override
  Future<Map<String, dynamic>> getState() async =>
      throw UnsupportedError('State unsupported');
}

/// Roku ECP is plaintext LAN HTTP. Roku's current policy restricts third-party ECP use.
class RokuAdapter extends _Base {
  RokuAdapter(super.host, super.approve);
  @override
  Set<String> get capabilities => const {
    'pair',
    'keys',
    'text',
    'apps',
    'state',
  };
  Future<String> _request(String method, String path, {String? literal}) async {
    await authorize();
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 3)
      ..findProxy = (_) => 'DIRECT';
    _clients.add(client);
    try {
      final req = await client
          .openUrl(
            method,
            Uri(
              scheme: 'http',
              host: host,
              port: 8060,
              pathSegments: [
                ...path.split('/').where((s) => s.isNotEmpty),
                if (literal != null) literal,
              ],
            ),
          )
          .timeout(const Duration(seconds: 5));
      req.followRedirects = false;
      final res = await req.close().timeout(const Duration(seconds: 5));
      if (res.statusCode < 200 || res.statusCode >= 300)
        throw HttpException('Roku HTTP ${res.statusCode}');
      final bytes = <int>[];
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      await for (final chunk in res.timeout(const Duration(seconds: 5))) {
        if (DateTime.now().isAfter(deadline))
          throw TimeoutException('Roku response deadline exceeded');
        bytes.addAll(chunk);
        if (bytes.length > 65536) throw StateError('Response too large');
      }
      return utf8.decode(bytes);
    } finally {
      _clients.remove(client);
      client.close(force: true);
    }
  }

  @override
  Future<void> pair() async {
    await _request('GET', '/query/device-info');
  }

  @override
  Future<void> sendKey(String key) async {
    const keys = {
      'Home',
      'Rev',
      'Fwd',
      'Play',
      'Select',
      'Left',
      'Right',
      'Down',
      'Up',
      'Back',
      'InstantReplay',
      'Info',
      'Backspace',
      'Search',
      'Enter',
      'VolumeDown',
      'VolumeMute',
      'VolumeUp',
      'PowerOff',
      'ChannelUp',
      'ChannelDown',
    };
    if (!keys.contains(key)) throw ArgumentError('Unsupported Roku key');
    await _request('POST', '/keypress/$key');
  }

  @override
  Future<void> sendText(String text) async {
    _text(text);
    if (text.runes.length > 256) throw ArgumentError('Roku text too long');
    for (final rune in text.runes) {
      await _request(
        'POST',
        '/keypress',
        literal: 'Lit_${String.fromCharCode(rune)}',
      );
    }
  }

  @override
  Future<void> launchApp(String appId) async {
    if (!RegExp(r'^\d{1,20}$').hasMatch(appId))
      throw ArgumentError('Invalid Roku app id');
    await _request('POST', '/launch/$appId');
  }

  @override
  Future<Map<String, dynamic>> getState() async => {
    'deviceInfoXml': await _request('GET', '/query/device-info'),
  };
}

abstract class _TlsAdapter extends _Base {
  final String fingerprint;
  final CertificateDigest digest;
  final CredentialRead readCredential;
  final CredentialWrite writeCredential;
  _TlsAdapter(
    super.host,
    super.approve,
    this.fingerprint,
    this.digest,
    this.readCredential,
    this.writeCredential,
  ) {
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(fingerprint))
      throw ArgumentError('Confirmed SHA-256 fingerprint required');
  }
  Future<WebSocket> connect(
    int port,
    String path, [
    Map<String, String>? query,
  ]) async {
    await authorize(fingerprint);
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
      ..connectionTimeout = const Duration(seconds: 5)
      ..findProxy = ((_) => 'DIRECT')
      ..badCertificateCallback = (cert, hostname, p) =>
          hostname == host && p == port && digest(cert.der) == fingerprint;
    _clients.add(client);
    try {
      // The empty trust store ensures even CA-trusted certificates pass through pin verification.
      final socket = await WebSocket.connect(
        Uri(
          scheme: 'wss',
          host: host,
          port: port,
          path: path,
          queryParameters: query,
        ).toString(),
        customClient: client,
      ).timeout(const Duration(seconds: 8));
      if (_closed) {
        await socket.close();
        throw StateError('Adapter closed');
      }
      _sockets.add(socket);
      socket.done.whenComplete(() {
        _sockets.remove(socket);
        _clients.remove(client);
        client.close(force: true);
      });
      return socket;
    } catch (_) {
      _clients.remove(client);
      client.close(force: true);
      rethrow;
    }
  }
}

class SamsungAdapter extends _TlsAdapter {
  SamsungAdapter(
    super.host,
    super.approve,
    super.fingerprint,
    super.digest,
    super.readCredential,
    super.writeCredential,
  );
  @override
  Set<String> get capabilities => const {'pair', 'keys'};
  Future<WebSocket> _open() async {
    final token = await readCredential(host);
    final ws = await connect(8002, '/api/v2/channels/samsung.remote.control', {
      'name': base64.encode(utf8.encode('TV Bridge')),
      if (token != null) 'token': token,
    });
    final completer = Completer<void>();
    late StreamSubscription sub;
    sub = ws.listen(
      (message) async {
        try {
          if (message is! String || utf8.encode(message).length > 65536)
            throw StateError('Invalid frame');
          final data = jsonDecode(message) as Map<String, dynamic>;
          if (data['event'] == 'ms.channel.unauthorized')
            throw StateError('Samsung pairing denied');
          if (data['event'] == 'ms.channel.connect') {
            final t = (data['data'] as Map?)?['token'];
            if (t is String && t.isNotEmpty) await writeCredential(host, t);
            if (!completer.isCompleted) completer.complete();
          }
        } catch (e, st) {
          if (!completer.isCompleted) completer.completeError(e, st);
        }
      },
      onError: (Object e, StackTrace st) {
        if (!completer.isCompleted) completer.completeError(e, st);
      },
      onDone: () {
        if (!completer.isCompleted)
          completer.completeError(StateError('Connection closed'));
      },
    );
    try {
      await completer.future.timeout(const Duration(seconds: 30));
      await sub.cancel();
      return ws;
    } catch (_) {
      await sub.cancel();
      await ws.close();
      rethrow;
    }
  }

  @override
  Future<void> pair() async {
    final ws = await _open();
    await ws.close();
  }

  @override
  Future<void> sendKey(String key) async {
    const keys = {
      'KEY_HOME',
      'KEY_RETURN',
      'KEY_UP',
      'KEY_DOWN',
      'KEY_LEFT',
      'KEY_RIGHT',
      'KEY_ENTER',
      'KEY_VOLUP',
      'KEY_VOLDOWN',
      'KEY_MUTE',
      'KEY_POWEROFF',
      'KEY_PLAY',
      'KEY_PAUSE',
    };
    if (!keys.contains(key)) throw ArgumentError('Unsupported Samsung key');
    final ws = await _open();
    try {
      ws.add(
        jsonEncode({
          'method': 'ms.remote.control',
          'params': {
            'Cmd': 'Click',
            'DataOfCmd': key,
            'Option': 'false',
            'TypeOfRemote': 'SendRemoteKey',
          },
        }),
      );
      await ws.close();
    } catch (_) {
      await ws.close();
      rethrow;
    }
  }
}

class UnsupportedTvAdapter implements TvAdapter {
  final String reason;
  UnsupportedTvAdapter(this.reason);
  @override
  Set<String> get capabilities => const {};
  Never _unsupported() => throw UnsupportedError(reason);
  @override
  Future<void> close() async {}
  @override
  Future<void> pair() async => _unsupported();
  @override
  Future<void> sendKey(String key) async => _unsupported();
  @override
  Future<void> sendText(String text) async => _unsupported();
  @override
  Future<void> launchApp(String appId) async => _unsupported();
  @override
  Future<Map<String, dynamic>> getState() async => _unsupported();
}

/// Apple TV needs HAP pairing (SRP + ChaCha20-Poly1305) and the Companion protocol (OPACK); not implemented.
class AppleTvAdapter extends UnsupportedTvAdapter {
  AppleTvAdapter()
    : super('Apple TV requires HAP pairing and the Companion protocol');
}

/// webOS registration manifest must be supplied by the application.
class LgAdapter extends _TlsAdapter {
  final Map<String, dynamic> manifest;
  LgAdapter(
    super.host,
    super.approve,
    super.fingerprint,
    super.digest,
    super.readCredential,
    super.writeCredential,
    this.manifest,
  );
  @override
  Set<String> get capabilities => const {
    'pair',
    'keys',
    'text',
    'apps',
    'state',
  };
  Future<Map<String, dynamic>> _exchange(
    String? uri,
    Map<String, dynamic> payload,
  ) async {
    final key = await readCredential(host);
    final ws = await connect(3001, '/');
    final result = Completer<Map<String, dynamic>>();
    var registered = false;
    var count = 0;
    final sub = ws.listen(
      (message) async {
        try {
          if (++count > 64 ||
              message is! String ||
              utf8.encode(message).length > 65536)
            throw StateError('Invalid webOS frame');
          final m = jsonDecode(message) as Map<String, dynamic>;
          if (m['type'] == 'error' &&
              (m['id'] == 'register' || m['id'] == 'request'))
            throw StateError('webOS error: ${m['error']}');
          if (m['type'] == 'registered' && m['id'] == 'register') {
            final k = (m['payload'] as Map?)?['client-key'];
            if (k is String && k.isNotEmpty) await writeCredential(host, k);
            registered = true;
            if (uri == null) {
              if (!result.isCompleted) result.complete({});
            } else {
              ws.add(
                jsonEncode({
                  'id': 'request',
                  'type': 'request',
                  'uri': uri,
                  'payload': payload,
                }),
              );
            }
          } else if (registered &&
              m['type'] == 'response' &&
              m['id'] == 'request') {
            final p = Map<String, dynamic>.from(m['payload'] as Map? ?? {});
            if (p['returnValue'] == false || p.containsKey('errorCode'))
              throw StateError('webOS request rejected');
            if (!result.isCompleted) result.complete(p);
          }
        } catch (e, st) {
          if (!result.isCompleted) result.completeError(e, st);
        }
      },
      onError: (Object e, StackTrace st) {
        if (!result.isCompleted) result.completeError(e, st);
      },
      onDone: () {
        if (!result.isCompleted)
          result.completeError(StateError('webOS disconnected'));
      },
    );
    try {
      ws.add(
        jsonEncode({
          'id': 'register',
          'type': 'register',
          'payload': {
            'pairingType': 'PROMPT',
            'manifest': manifest,
            if (key != null) 'client-key': key,
          },
        }),
      );
      return await result.future.timeout(const Duration(seconds: 30));
    } finally {
      await sub.cancel();
      await ws.close();
    }
  }

  @override
  Future<void> pair() async {
    await _exchange(null, {});
  }

  @override
  Future<void> sendKey(String key) async {
    const keys = {
      'volume_up': 'ssap://audio/volumeUp',
      'volume_down': 'ssap://audio/volumeDown',
      'power_off': 'ssap://system/turnOff',
    };
    final uri = keys[key];
    if (uri != null) {
      await _exchange(uri, {});
      return;
    }
    const buttons = {
      'up': 'UP',
      'down': 'DOWN',
      'left': 'LEFT',
      'right': 'RIGHT',
      'enter': 'ENTER',
      'back': 'BACK',
      'home': 'HOME',
    };
    final button = buttons[key];
    if (button == null) throw UnsupportedError('Unsupported LG key');
    final response = await _exchange(
      'ssap://com.webos.service.networkinput/getPointerInputSocket',
      {},
    );
    final value = response['socketPath'];
    if (value is! String || value.length > 2048)
      throw StateError('Invalid pointer URL');
    final pointer = Uri.tryParse(value);
    if (pointer == null ||
        pointer.scheme != 'wss' ||
        pointer.host != host ||
        pointer.port != 3001 ||
        pointer.userInfo.isNotEmpty ||
        pointer.hasQuery ||
        pointer.hasFragment ||
        pointer.path.isEmpty)
      throw StateError('Unsafe pointer URL');
    final socket = await connect(3001, pointer.path);
    try {
      socket.add('type:button\nname:$button\n\n');
    } finally {
      await socket.close();
    }
  }

  @override
  Future<void> sendText(String text) async {
    _text(text);
    await _exchange('ssap://com.webos.service.ime/insertText', {
      'text': text,
      'replace': 0,
    });
  }

  @override
  Future<void> launchApp(String appId) async {
    _app(appId);
    await _exchange('ssap://system.launcher/launch', {'id': appId});
  }

  @override
  Future<Map<String, dynamic>> getState() =>
      _exchange('ssap://audio/getVolume', {});
}

const _ssdpTargets = {
  'roku': 'roku:ecp',
  'samsung': 'urn:samsung.com:device:RemoteControlReceiver:1',
  'lg': 'urn:lge-com:service:webos-second-screen:1',
};
const _dialTarget = 'urn:dial-multiscreen-org:device:dial:1';
const _androidService = '_androidtvremote2._tcp.local';

/// Brand of an SSDP 200 response or mDNS answer, else null.
String? parseDiscovery(List<int> data) {
  if (data.length > 8192) return null;
  final text = ascii.decode(data, allowInvalid: true).toLowerCase();
  if (text.startsWith('http/1.1 200')) {
    for (final e in _ssdpTargets.entries) {
      if (text.contains(e.value.toLowerCase())) return e.key;
    }
    // DIAL is shared by many brands, so require the manufacturer in the headers too.
    if (text.contains(_dialTarget) && text.contains('vizio')) return 'vizio';
    if (text.contains(_dialTarget) &&
        RegExp(r'amazon|\baft\w*|fire').hasMatch(text)) {
      return 'firetv';
    }
    return null;
  }
  // DNS header: QR bit (0x80 of byte 2) marks a response; names are length-prefixed.
  if (data.length > 12 &&
      data[2] & 0x80 != 0 &&
      text.contains('_androidtvremote2'))
    return 'androidtv';
  return null;
}

List<int> _mdnsQuery() => [
  0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  for (final label in _androidService.split('.')) ...[
    label.length,
    ...ascii.encode(label),
  ],
  0, 0, 12, 0x80, 1, // PTR, class IN with unicast-response bit
];

/// SSDP/mDNS results are unverified candidate addresses, never device identities.
Future<List<({String brand, String host})>> discoverTvs() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  final found = <String, ({String brand, String host})>{};
  final done = Completer<void>();
  final timer = Timer(const Duration(seconds: 2), () {
    if (!done.isCompleted) done.complete();
  });
  final subscription = socket.listen(
    (event) {
      if (event != RawSocketEvent.read) return;
      Datagram? datagram;
      while ((datagram = socket.receive()) != null) {
        final d = datagram!;
        try {
          _checkHost(d.address.address);
          final brand = parseDiscovery(d.data);
          if (brand != null && found.length < 64)
            found['$brand ${d.address.address}'] = (
              brand: brand,
              host: d.address.address,
            );
        } catch (_) {}
      }
    },
    onError: (Object e, StackTrace st) {
      if (!done.isCompleted) done.completeError(e, st);
    },
  );
  try {
    // shortcut: default interface only, iterate NetworkInterface.list() if multi-NIC needed
    void send(List<int> data, String group, int port) {
      try {
        socket.send(data, InternetAddress(group), port);
      } on SocketException {
        // One protocol failing (e.g. no multicast route) must not stop the others.
      }
    }

    for (final st in [..._ssdpTargets.values, _dialTarget]) {
      send(
        ascii.encode(
          'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: $st\r\n\r\n',
        ),
        '239.255.255.250',
        1900,
      );
    }
    send(_mdnsQuery(), '224.0.0.251', 5353);
    await done.future;
    return found.values.toList();
  } finally {
    timer.cancel();
    await subscription.cancel();
    socket.close();
  }
}
