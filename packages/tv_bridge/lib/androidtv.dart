part of 'tv_bridge.dart';

// Minimal protobuf: only varint and length-delimited fields are needed by Remote v2.
List<int> pbVarint(int v) {
  final o = <int>[];
  for (; v > 0x7f; v >>= 7) {
    o.add(v & 0x7f | 0x80);
  }
  return o..add(v);
}

/// int -> varint field; String or List<int> -> length-delimited field.
List<int> pbField(int n, Object v) {
  if (v is int) return [...pbVarint(n << 3), ...pbVarint(v)];
  final b = v is String ? utf8.encode(v) : v as List<int>;
  return [...pbVarint(n << 3 | 2), ...pbVarint(b.length), ...b];
}

Map<int, List<Object>> pbDecode(List<int> d) {
  final out = <int, List<Object>>{};
  var i = 0;
  int varint() {
    var r = 0, s = 0;
    while (true) {
      if (i >= d.length || s > 56) throw const FormatException('Bad varint');
      final b = d[i++];
      r |= (b & 0x7f) << s;
      if (b < 0x80) return r;
      s += 7;
    }
  }

  while (i < d.length) {
    final tag = varint(), n = tag >> 3;
    if (tag & 7 == 0) {
      (out[n] ??= []).add(varint());
    } else if (tag & 7 == 2) {
      final l = varint();
      if (l > d.length - i) throw const FormatException('Truncated field');
      (out[n] ??= []).add(d.sublist(i, i + l));
      i += l;
    } else {
      throw const FormatException('Unsupported wire type');
    }
  }
  return out;
}

/// Removes and returns one varint-length-prefixed frame from [buf], or null if incomplete.
List<int>? pbTakeFrame(List<int> buf) {
  var len = 0, s = 0, i = 0;
  while (true) {
    if (i >= buf.length) return null;
    final b = buf[i++];
    len |= (b & 0x7f) << s;
    if (b < 0x80) break;
    if ((s += 7) > 21) throw const FormatException('Bad frame length');
  }
  if (len > 65536) throw const FormatException('Frame too large');
  if (buf.length - i < len) return null;
  final frame = buf.sublist(i, i + len);
  buf.removeRange(0, i + len);
  return frame;
}

List<int> pbFrame(List<int> msg) => [...pbVarint(msg.length), ...msg];

/// Polo pairing envelope: protocol_version 2, status OK, optional payload field.
List<int> atvPairingMessage([int? field, List<int> body = const []]) => [
  ...pbField(1, 2),
  ...pbField(2, 200),
  if (field != null) ...pbField(field, body),
];

List<int> _hexBytes(String s) => [
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];

List<int> _pemDer(String pem) {
  final m = RegExp(
    r'-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----',
  ).firstMatch(pem);
  if (m == null) throw ArgumentError('PEM certificate required');
  return base64.decode(m.group(1)!.replaceAll(RegExp(r'\s'), ''));
}

typedef _Tlv = ({int tag, int s, int e});

List<_Tlv> _der(List<int> d, int s, int e) {
  final out = <_Tlv>[];
  while (s < e) {
    if (s + 2 > e) throw const FormatException('Bad DER');
    final tag = d[s++];
    var len = d[s++];
    if (len & 0x80 != 0) {
      final n = len & 0x7f;
      if (n == 0 || n > 3 || s + n > e) throw const FormatException('Bad DER');
      len = 0;
      for (var k = 0; k < n; k++) {
        len = len << 8 | d[s++];
      }
    }
    if (len > e - s) throw const FormatException('Bad DER');
    out.add((tag: tag, s: s, e: s + len));
    s += len;
  }
  return out;
}

/// RSA modulus and exponent as minimal big-endian bytes from an X.509 DER certificate.
({List<int> n, List<int> e}) rsaPublicKey(List<int> cert) {
  final top = _der(cert, 0, cert.length).first;
  final tbs = _der(cert, top.s, top.e).first;
  final f = _der(cert, tbs.s, tbs.e);
  final spki = f[f.first.tag == 0xA0 ? 6 : 5]; // skip optional [0] version
  final bits = _der(cert, spki.s, spki.e)[1];
  final key = _der(cert, bits.s + 1, bits.e).first; // +1: unused-bits byte
  final ints = _der(cert, key.s, key.e);
  List<int> int_(_Tlv t) {
    var s = t.s;
    while (s < t.e - 1 && cert[s] == 0) {
      s++;
    }
    return cert.sublist(s, t.e);
  }

  return (n: int_(ints[0]), e: int_(ints[1]));
}

/// Secret = SHA-256(clientN | clientE | serverN | serverE | PIN[2:] bytes); PIN[0:2] is a check byte.
List<int> atvPairingSecret({
  required List<int> clientDer,
  required List<int> serverDer,
  required String code,
  required CertificateDigest digest,
}) {
  if (!RegExp(r'^[0-9a-fA-F]{6}$').hasMatch(code))
    throw ArgumentError('PIN must be 6 hex digits');
  final c = rsaPublicKey(clientDer), s = rsaPublicKey(serverDer);
  final h = _hexBytes(
    digest([...c.n, ...c.e, ...s.n, ...s.e, ..._hexBytes(code.substring(2))]),
  );
  if (h[0] != int.parse(code.substring(0, 2), radix: 16))
    throw StateError('Wrong PIN');
  return h;
}

class _PbConn {
  final SecureSocket socket;
  final _buf = <int>[];
  final _q = <Map<int, List<Object>>>[];
  Object? _err;
  bool _done = false;
  Completer<void>? _wake;
  _PbConn(this.socket) {
    void wake() {
      final w = _wake;
      _wake = null;
      if (w != null && !w.isCompleted) w.complete();
    }

    socket.listen(
      (d) {
        try {
          _buf.addAll(d);
          List<int>? f;
          while ((f = pbTakeFrame(_buf)) != null) {
            if (_q.length >= 64) throw StateError('Too many frames');
            _q.add(pbDecode(f!));
          }
        } catch (e) {
          _err = e;
        }
        wake();
      },
      onError: (Object e) {
        _err = e;
        wake();
      },
      onDone: () {
        _done = true;
        wake();
      },
      cancelOnError: true,
    );
  }
  Future<Map<int, List<Object>>> next([
    Duration timeout = const Duration(seconds: 15),
  ]) async {
    while (_q.isEmpty) {
      if (_err != null) throw _err!;
      if (_done) throw StateError('Connection closed');
      final w = _wake = Completer<void>();
      await w.future.timeout(timeout);
    }
    return _q.removeAt(0);
  }

  void send(List<int> msg) => socket.add(pbFrame(msg));
  void close() => socket.destroy();
}

/// Android TV Remote v2. The caller supplies a PEM client certificate and key via
/// [identity] (pure Dart cannot generate RSA certs); the TV remembers that cert after pairing.
class AndroidTvAdapter extends _TlsAdapter {
  final Future<({String cert, String key})> Function() identity;
  final Future<String> Function() readPin;
  final _secure = <SecureSocket>{};
  AndroidTvAdapter(
    super.host,
    super.approve,
    super.fingerprint,
    super.digest,
    super.readCredential,
    super.writeCredential,
    this.identity,
    this.readPin,
  );
  @override
  Set<String> get capabilities => const {'pair', 'keys', 'apps'};
  static const keyCodes = {
    'DPAD_UP': 19,
    'DPAD_DOWN': 20,
    'DPAD_LEFT': 21,
    'DPAD_RIGHT': 22,
    'DPAD_CENTER': 23,
    'BACK': 4,
    'HOME': 3,
    'VOLUME_UP': 24,
    'VOLUME_DOWN': 25,
    'MUTE': 164,
    'POWER': 26,
  };

  @override
  Future<void> close() async {
    await super.close();
    for (final s in _secure.toList()) {
      s.destroy();
    }
    _secure.clear();
  }

  Future<_PbConn> _open(int port, String cert, String key) async {
    await authorize(fingerprint);
    final ctx = SecurityContext(withTrustedRoots: false)
      ..useCertificateChainBytes(utf8.encode(cert))
      ..usePrivateKeyBytes(utf8.encode(key));
    final socket = await SecureSocket.connect(
      host,
      port,
      context: ctx,
      timeout: const Duration(seconds: 5),
      // The empty trust store makes every cert "bad", so only the pinned one passes.
      onBadCertificate: (c) => digest(c.der) == fingerprint,
    );
    if (_closed) {
      socket.destroy();
      throw StateError('Adapter closed');
    }
    _secure.add(socket);
    socket.done.whenComplete(() => _secure.remove(socket)).ignore();
    return _PbConn(socket);
  }

  @override
  Future<void> pair() async {
    final id = await identity();
    final c = await _open(6467, id.cert, id.key);
    try {
      Future<void> expect(int field) async {
        final m = await c.next();
        if (m[2]?.first != 200 || !m.containsKey(field))
          throw StateError('Android TV pairing rejected');
      }

      final enc = [
        ...pbField(1, 3),
        ...pbField(2, 6),
      ]; // hexadecimal, 6 symbols
      c.send(
        atvPairingMessage(10, [
          ...pbField(1, 'androidtvremote2'),
          ...pbField(2, 'atvremote'),
        ]),
      );
      await expect(11);
      c.send(atvPairingMessage(20, [...pbField(1, enc), ...pbField(3, 1)]));
      await expect(20);
      c.send(atvPairingMessage(30, [...pbField(1, enc), ...pbField(2, 1)]));
      await expect(31);
      final server = c.socket.peerCertificate;
      if (server == null) throw StateError('No TV certificate');
      final secret = atvPairingSecret(
        clientDer: _pemDer(id.cert),
        serverDer: server.der,
        code: (await readPin()).trim(),
        digest: digest,
      );
      c.send(atvPairingMessage(40, pbField(1, secret)));
      await expect(41);
      await writeCredential(host, 'paired');
    } finally {
      c.close();
    }
  }

  Future<void> _remote(Future<void> Function(_PbConn) act) async {
    if (await readCredential(host) == null)
      throw StateError('Android TV not paired');
    final id = await identity();
    final c = await _open(6466, id.cert, id.key);
    try {
      for (var i = 0; i < 64; i++) {
        final m = await c.next();
        if (m.containsKey(3)) throw StateError('Android TV remote error');
        if (m.containsKey(1)) {
          c.send(
            pbField(1, [
              ...pbField(1, 622), // feature bitmask
              ...pbField(2, [
                ...pbField(1, 'atvremote'),
                ...pbField(2, 'atvremote'),
                ...pbField(3, 1),
                ...pbField(4, '1'),
                ...pbField(5, 'atvremote'),
                ...pbField(6, '1.0.0'),
              ]),
            ]),
          );
        }
        if (m.containsKey(2)) c.send(pbField(2, pbField(1, 622)));
        if (m.containsKey(8)) {
          final ping = pbDecode(m[8]!.first as List<int>);
          c.send(pbField(9, pbField(1, (ping[1]?.first as int?) ?? 0)));
        }
        if (m.containsKey(40)) {
          await act(c);
          await c.socket.flush();
          return;
        }
      }
      throw StateError('Android TV did not become ready');
    } finally {
      c.close();
    }
  }

  @override
  Future<void> sendKey(String key) async {
    final code = keyCodes[key];
    if (code == null) throw ArgumentError('Unsupported Android TV key');
    // direction 3 = SHORT press
    await _remote(
      (c) async => c.send(pbField(10, [...pbField(1, code), ...pbField(2, 3)])),
    );
  }

  @override
  Future<void> launchApp(String appId) async {
    if (!RegExp(r'^[A-Za-z][A-Za-z0-9+.-]*://[^\s]{1,400}$').hasMatch(appId))
      throw ArgumentError('Deep link URI required');
    await _remote((c) async => c.send(pbField(90, pbField(1, appId))));
  }
}
