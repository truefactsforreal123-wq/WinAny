part of 'tv_bridge.dart';

/// SmartCast request: HTTPS PUT with JSON body; the pairing token goes in the AUTH header.
({String method, Uri uri, Map<String, String> headers, String body})
vizioRequest(
  String host,
  int port,
  String path,
  Map<String, dynamic> body, [
  String? token,
]) => (
  method: 'PUT',
  uri: Uri(scheme: 'https', host: host, port: port, path: path),
  headers: {
    'Content-Type': 'application/json',
    if (token != null) 'AUTH': token,
  },
  body: jsonEncode(body),
);

/// Vizio SmartCast: port 7345 (9000 on older models), self-signed cert pinned like Samsung/LG.
class VizioAdapter extends _TlsAdapter {
  final Future<String> Function() readPin;
  final int port;
  VizioAdapter(
    super.host,
    super.approve,
    super.fingerprint,
    super.digest,
    super.readCredential,
    super.writeCredential,
    this.readPin, {
    this.port = 7345,
  });
  static const _deviceId = 'tv-bridge';
  // (CODESET, CODE) pairs as used by pyvizio; unverified on real hardware.
  static const keyCodes = {
    'UP': (3, 8),
    'DOWN': (3, 0),
    'LEFT': (3, 1),
    'RIGHT': (3, 7),
    'OK': (3, 2),
    'BACK': (4, 0),
    'HOME': (4, 15),
    'VOL_UP': (5, 1),
    'VOL_DOWN': (5, 0),
    'MUTE_TOGGLE': (5, 4),
    'POWER_OFF': (11, 0),
  };
  @override
  Set<String> get capabilities => const {'pair', 'keys'};

  Future<Map<String, dynamic>> _call(
    String path,
    Map<String, dynamic> body, [
    String? token,
  ]) async {
    await authorize(fingerprint);
    final r = vizioRequest(host, port, path, body, token);
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false))
      ..connectionTimeout = const Duration(seconds: 5)
      ..findProxy = ((_) => 'DIRECT')
      ..badCertificateCallback = (cert, h, p) =>
          h == host && p == port && digest(cert.der) == fingerprint;
    _clients.add(client);
    try {
      final req = await client
          .openUrl(r.method, r.uri)
          .timeout(const Duration(seconds: 5));
      req.followRedirects = false;
      r.headers.forEach(req.headers.set);
      req.write(r.body);
      final res = await req.close().timeout(const Duration(seconds: 5));
      final bytes = await res
          .fold<List<int>>([], (a, c) {
            if (a.length + c.length > 65536)
              throw StateError('Response too large');
            return a..addAll(c);
          })
          .timeout(const Duration(seconds: 5));
      final j = jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
      if (res.statusCode < 200 ||
          res.statusCode >= 300 ||
          (j['STATUS'] as Map?)?['RESULT'] != 'SUCCESS')
        throw StateError('Vizio request rejected');
      return j;
    } finally {
      _clients.remove(client);
      client.close(force: true);
    }
  }

  @override
  Future<void> pair() async {
    final start = await _call('/pairing/start', {
      'DEVICE_NAME': 'TV Bridge',
      'DEVICE_ID': _deviceId,
    });
    final req = (start['ITEM'] as Map?)?['PAIRING_REQ_TOKEN'];
    if (req is! int) throw StateError('Invalid Vizio pairing response');
    final pin = (await readPin()).trim();
    if (!RegExp(r'^\d{4}$').hasMatch(pin))
      throw ArgumentError('Vizio PIN is 4 digits');
    final done = await _call('/pairing/pair', {
      'DEVICE_ID': _deviceId,
      'CHALLENGE_TYPE': 1,
      'RESPONSE_VALUE': pin,
      'PAIRING_REQ_TOKEN': req,
    });
    final auth = (done['ITEM'] as Map?)?['AUTH_TOKEN'];
    if (auth is! String || auth.isEmpty)
      throw StateError('Invalid Vizio pairing response');
    await writeCredential(host, auth);
  }

  @override
  Future<void> sendKey(String key) async {
    final k = keyCodes[key];
    if (k == null) throw ArgumentError('Unsupported Vizio key');
    final token = await readCredential(host);
    if (token == null) throw StateError('Vizio not paired');
    await _call('/key_command/', {
      'KEYLIST': [
        {'CODESET': k.$1, 'CODE': k.$2, 'ACTION': 'KEYPRESS'},
      ],
    }, token);
  }
}
