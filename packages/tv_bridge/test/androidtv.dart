import 'dart:async';
import 'dart:io';

import '../lib/tv_bridge.dart';
import 'util.dart';

/// Fake TV side: decodes frames from the client and hands each to [onFrame].
void serve(SecureSocket s, void Function(Map<int, List<Object>>) onFrame) {
  final buf = <int>[];
  s.listen((d) {
    buf.addAll(d);
    List<int>? f;
    while ((f = pbTakeFrame(buf)) != null) {
      onFrame(pbDecode(f!));
    }
  }, onError: (_) {});
}

Map<int, List<Object>> sub(Map<int, List<Object>> m, int field) =>
    pbDecode(m[field]!.first as List<int>);

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<void> main() async {
  // Encoding vectors (protobuf spec: field 1 varint 150 = 08 96 01).
  check(pbField(1, 150), [0x08, 0x96, 0x01]);
  check(pbField(2, 'testing'), [0x12, 7, ...'testing'.codeUnits]);
  check(pbVarint(300), [0xac, 0x02]);
  check(atvPairingMessage(10, [...pbField(1, 'a'), ...pbField(2, 'b')]), [
    0x08,
    2,
    0x10,
    0xc8,
    0x01,
    0x52,
    6,
    0x0a,
    1,
    0x61,
    0x12,
    1,
    0x62,
  ]);
  final d = pbDecode([0x08, 0x96, 0x01, 0x12, 2, 0x68, 0x69]);
  check(d[1]!.first, 150);
  check(d[2]!.first, [0x68, 0x69]);
  await fail(() async => pbDecode([0x12, 5, 1]));
  await fail(() async => pbDecode([0x0d, 1, 2, 3, 4])); // fixed32 unsupported
  final buf = [
    ...pbFrame([1, 2, 3]),
    5,
    1,
  ];
  check(pbTakeFrame(buf), [1, 2, 3]);
  check(pbTakeFrame(buf), null); // incomplete second frame stays buffered
  check(buf, [5, 1]);
  await fail(() async => pbTakeFrame([0x81, 0x80, 0x04])); // > 64 KiB

  final ip = await privateIp();
  if (ip == null) {
    print('SKIP Android TV: no private interface');
    return;
  }
  final dir = await Directory.systemTemp.createTemp('tv_bridge_atv_');
  final tv = makeCert(dir, 'tv'), client = makeCert(dir, 'client');
  final tvPin = sha256hex(tv.der);
  String digest(List<int> b) => sha256hex(b);

  // DER parser and pairing secret against openssl's modulus and sha256.
  final k = rsaPublicKey(tv.der);
  check(k.n, opensslModulus(dir, 'tv'));
  check(k.e, [1, 0, 1]);
  final hash = sha256hex([
    ...rsaPublicKey(client.der).n, 1, 0, 1, ...k.n, 1, 0, 1, 0xab, 0xcd, //
  ]);
  final code = '${hash.substring(0, 2)}abcd';
  final secret = atvPairingSecret(
    clientDer: client.der,
    serverDer: tv.der,
    code: code,
    digest: digest,
  );
  check(hex(secret), hash);
  final wrongByte = hex([(secret[0] + 1) % 256]);
  await fail(
    () async => atvPairingSecret(
      clientDer: client.der,
      serverDer: tv.der,
      code: '${wrongByte}abcd',
      digest: digest,
    ),
  );
  await fail(
    () async => atvPairingSecret(
      clientDer: client.der,
      serverDer: tv.der,
      code: '12345',
      digest: digest,
    ),
  );

  // Fake TV: pairing on 6467, remote on 6466.
  final ctx = SecurityContext()
    ..useCertificateChainBytes(tv.cert.codeUnits)
    ..usePrivateKeyBytes(tv.key.codeUnits);
  final pairing = await SecureServerSocket.bind(ip, 6467, ctx);
  final remote = await SecureServerSocket.bind(ip, 6466, ctx);
  final seen = <int>[];
  var secretOk = false;
  final got = <Map<int, List<Object>>>[];
  final conns = <SecureSocket>[];
  pairing.listen((s) {
    conns.add(s);
    serve(s, (m) {
      for (final f in [10, 20, 30, 40]) {
        if (!m.containsKey(f)) continue;
        seen.add(f);
        if (f == 40) {
          secretOk = '${sub(m, 40)[1]!.first}' == '$secret';
        }
        final reply = const {10: 11, 20: 20, 30: 31, 40: 41}[f]!;
        s.add(
          pbFrame(atvPairingMessage(reply, f == 10 ? pbField(1, 'tv') : [])),
        );
      }
    });
  }, onError: (_) {});
  remote.listen((s) {
    conns.add(s);
    s.add(pbFrame(pbField(1, pbField(1, 1)))); // configure
    s.add(pbFrame(pbField(2, pbField(1, 1)))); // set_active
    s.add(pbFrame(pbField(8, pbField(1, 5)))); // ping
    s.add(pbFrame(pbField(40, <int>[]))); // remote_start
    serve(s, got.add);
  }, onError: (_) {});

  var stored = '';
  var pinAsked = 0;
  AndroidTvAdapter make(String fp, String pinCode) => AndroidTvAdapter(
    ip.address,
    (_, __) async => true,
    fp,
    digest,
    (_) async => stored.isEmpty ? null : stored,
    (_, v) async => stored = v,
    () async => (cert: client.cert, key: client.key),
    () async {
      pinAsked++;
      return pinCode;
    },
  );
  final a = make(tvPin, code);
  try {
    await fail(() => a.sendKey('DPAD_UP')); // not paired yet
    await a.pair();
    check(seen, [10, 20, 30, 40]);
    check(secretOk, true);
    check(stored, 'paired');
    await a.sendKey('DPAD_UP');
    await a.launchApp('https://www.netflix.com/title');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final cfg = got.firstWhere((m) => m.containsKey(1));
    check(sub(cfg, 1)[1]!.first, 622);
    check(got.any((m) => m.containsKey(2)), true);
    check(sub(got.firstWhere((m) => m.containsKey(9)), 9)[1]!.first, 5);
    final inj = sub(got.firstWhere((m) => m.containsKey(10)), 10);
    check(inj[1]!.first, 19);
    check(inj[2]!.first, 3);
    final link = sub(got.firstWhere((m) => m.containsKey(90)), 90);
    check(
      String.fromCharCodes(link[1]!.first as List<int>),
      'https://www.netflix.com/title',
    );
    await fail(() => a.sendKey('NOPE'));
    await fail(() => a.launchApp('com.netflix.ninja'));
    await fail(() => make(tvPin, 'zzzzzz').pair()); // bad PIN format
    await fail(() => make('0' * 64, code).pair()); // pin mismatch
    check(
      pinAsked,
      2,
    ); // success and bad-format attempts; pin mismatch never gets that far
    await a.close();
    await fail(() => a.pair());
    print('Android TV protobuf, DER, pairing secret and fake TLS tests passed');
  } finally {
    await a.close();
    for (final c in conns) {
      c.destroy();
    }
    await pairing.close();
    await remote.close();
    await dir.delete(recursive: true);
  }
}
