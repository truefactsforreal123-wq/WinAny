import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../lib/tv_bridge.dart';

Future<void> fail(Future<void> Function() f) async {
  try {
    await f();
  } catch (_) {
    return;
  }
  throw StateError('Expected failure');
}

Future<void> main() async {
  InternetAddress? ip;
  for (final i in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
    for (final a in i.addresses) {
      final b = a.rawAddress;
      if (b[0] == 10 ||
          (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
          (b[0] == 192 && b[1] == 168)) {
        ip = a;
        break;
      }
    }
    if (ip != null) break;
  }
  if (ip == null) {
    print('SKIP WSS: no private interface');
    return;
  }
  final dir = await Directory.systemTemp.createTemp('tv_bridge_test_');
  final openssl = r'C:\Program Files\Git\usr\bin\openssl.exe';
  Future<void> run(List<String> args) async {
    final p = await Process.run(openssl, args);
    if (p.exitCode != 0) throw StateError('openssl failed: ${p.stderr}');
  }

  final key = '${dir.path}/key.pem',
      cert = '${dir.path}/cert.pem',
      der = '${dir.path}/cert.der';
  await run([
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    key,
    '-out',
    cert,
    '-days',
    '1',
    '-subj',
    '/CN=test',
  ]);
  await run(['x509', '-in', cert, '-outform', 'der', '-out', der]);
  final result = await Process.run(openssl, [
    'x509',
    '-in',
    cert,
    '-noout',
    '-fingerprint',
    '-sha256',
  ]);
  final pin = (result.stdout as String)
      .trim()
      .split('=')
      .last
      .replaceAll(':', '')
      .toLowerCase();
  final certBytes = await File(der).readAsBytes();
  String digest(List<int> bytes) =>
      base64Encode(bytes) == base64Encode(certBytes) ? pin : '0' * 64;
  final context = SecurityContext()
    ..useCertificateChain(cert)
    ..usePrivateKey(key);
  final samsung = await HttpServer.bindSecure(ip, 8002, context);
  final lg = await HttpServer.bindSecure(ip, 3001, context);
  var samsungMode = 'ok', lgMode = 'ok';
  var token = '', clientKey = '', pointerMessage = '', samsungMessage = '';
  final samsungSub = samsung.listen((r) async {
    final ws = await WebSocketTransformer.upgrade(r);
    if (samsungMode == 'silent') {
      /* wait for client deadline */
    } else if (samsungMode == 'deny') {
      ws.add(jsonEncode({'event': 'ms.channel.unauthorized'}));
    } else if (samsungMode == 'bad') {
      ws.add('x' * 65537);
    } else {
      ws.add(
        jsonEncode({
          'event': 'ms.channel.connect',
          'data': {'token': 'samsung-token'},
        }),
      );
    }
    ws.listen((message) {
      samsungMessage = message as String;
    });
  });
  final lgSub = lg.listen((r) async {
    final ws = await WebSocketTransformer.upgrade(r);
    if (r.uri.path == '/pointer') {
      ws.listen((m) {
        pointerMessage = m as String;
      });
      return;
    }
    ws.listen((message) {
      final m = jsonDecode(message as String) as Map;
      if (m['type'] == 'register') {
        if (lgMode == 'bad') {
          ws.add('x' * 65537);
          return;
        }
        if (lgMode == 'deny') {
          ws.add(
            jsonEncode({'type': 'error', 'id': 'register', 'error': 'denied'}),
          );
          return;
        }
        ws.add(
          jsonEncode({
            'type': 'registered',
            'id': 'register',
            'payload': {'client-key': 'lg-key'},
          }),
        );
      } else if (m['id'] == 'request') {
        ws.add(
          jsonEncode({
            'type': 'response',
            'id': 'other',
            'payload': {'returnValue': false},
          }),
        );
        final path = lgMode == 'unsafe'
            ? 'wss://8.8.8.8:3001/pointer'
            : 'wss://${ip!.address}:3001/pointer';
        ws.add(
          jsonEncode({
            'type': 'response',
            'id': 'request',
            'payload': {'returnValue': true, 'socketPath': path, 'volume': 42},
          }),
        );
      }
    });
  });
  final s = SamsungAdapter(
    ip.address,
    (_, __) async => true,
    pin,
    digest,
    (_) async => token.isEmpty ? null : token,
    (_, v) async {
      token = v;
    },
  );
  final l = LgAdapter(
    ip.address,
    (_, __) async => true,
    pin,
    digest,
    (_) async => clientKey.isEmpty ? null : clientKey,
    (_, v) async {
      clientKey = v;
    },
    {},
  );
  try {
    await s.pair();
    if (token != 'samsung-token') throw StateError('Samsung token not saved');
    await s.sendKey('KEY_UP');
    await Future<void>.delayed(const Duration(milliseconds: 100));
    if (!samsungMessage.contains('KEY_UP'))
      throw StateError('Samsung key not sent');
    await l.pair();
    if (clientKey != 'lg-key') throw StateError('LG key not saved');
    final state = await l.getState();
    if (state['volume'] != 42) throw StateError('LG correlation failed');
    await l.sendKey('up');
    await Future<void>.delayed(const Duration(milliseconds: 100));
    if (pointerMessage != 'type:button\nname:UP\n\n')
      throw StateError('Pointer failed: $pointerMessage');
    lgMode = 'unsafe';
    await fail(() => l.sendKey('up'));
    lgMode = 'bad';
    await fail(() => l.pair());
    lgMode = 'deny';
    await fail(() => l.pair());
    samsungMode = 'deny';
    await fail(() => s.pair());
    samsungMode = 'silent';
    final watch = Stopwatch()..start();
    await fail(() => s.pair().timeout(const Duration(seconds: 35)));
    if (watch.elapsed < const Duration(seconds: 29) ||
        watch.elapsed > const Duration(seconds: 34))
      throw StateError('Unexpected pairing timeout');
    samsungMode = 'bad';
    await fail(() => s.pair());
    final mismatch = SamsungAdapter(
      ip.address,
      (_, __) async => true,
      '0' * 64,
      digest,
      (_) async => null,
      (_, __) async {},
    );
    await fail(() => mismatch.pair());
    await mismatch.close();
    await s.close();
    await fail(() => s.pair());
    print(
      'Fake WSS pairing, pin, bounds, correlation and pointer tests passed',
    );
  } finally {
    await s.close();
    await l.close();
    await samsungSub.cancel();
    await lgSub.cancel();
    await samsung.close(force: true);
    await lg.close(force: true);
    await dir.delete(recursive: true);
  }
}
