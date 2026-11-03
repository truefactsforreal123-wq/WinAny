import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../lib/tv_bridge.dart';
import 'util.dart';

Future<void> main() async {
  final r = vizioRequest('10.0.0.5', 7345, '/key_command/', {'a': 1}, 'tok');
  check(r.method, 'PUT');
  check(r.uri, 'https://10.0.0.5:7345/key_command/');
  check(r.headers['AUTH'], 'tok');
  check(r.headers['Content-Type'], 'application/json');
  check(r.body, '{"a":1}');
  check(
    vizioRequest('10.0.0.5', 9000, '/pairing/start', {}).headers['AUTH'],
    null,
  );

  // SSDP: DIAL alone is not enough, manufacturer must be present.
  const st = 'urn:dial-multiscreen-org:device:dial:1';
  check(
    parseDiscovery(
      ascii.encode(
        'HTTP/1.1 200 OK\r\nST: $st\r\nSERVER: VIZIO SmartCast\r\n\r\n',
      ),
    ),
    'vizio',
  );
  check(
    parseDiscovery(ascii.encode('HTTP/1.1 200 OK\r\nST: $st\r\n\r\n')),
    null,
  );

  final ip = await privateIp();
  if (ip == null) {
    print('SKIP Vizio TLS: no private interface');
    return;
  }
  final dir = await Directory.systemTemp.createTemp('tv_bridge_vizio_');
  final tv = makeCert(dir, 'tv');
  final tvPin = sha256hex(tv.der);
  final ctx = SecurityContext()
    ..useCertificateChainBytes(tv.cert.codeUnits)
    ..usePrivateKeyBytes(tv.key.codeUnits);
  final server = await HttpServer.bindSecure(ip, 7345, ctx);
  final log = <String>[];
  final sub = server.listen((req) async {
    final body = jsonDecode(await utf8.decoder.bind(req).join()) as Map;
    final auth = req.headers.value('AUTH');
    log.add('${req.method} ${req.uri.path} ${auth ?? ''} ${jsonEncode(body)}');
    Map<String, dynamic> out = {
      'STATUS': {'RESULT': 'SUCCESS'},
    };
    if (req.uri.path == '/pairing/start') {
      out['ITEM'] = {'PAIRING_REQ_TOKEN': 77};
    } else if (req.uri.path == '/pairing/pair') {
      out['ITEM'] = {'AUTH_TOKEN': 'ZAUTH'};
      if (body['RESPONSE_VALUE'] != '1234' || body['PAIRING_REQ_TOKEN'] != 77) {
        out = {
          'STATUS': {'RESULT': 'BLOCKED'},
        };
      }
    } else if (auth != 'ZAUTH') {
      out = {
        'STATUS': {'RESULT': 'BLOCKED'},
      };
    }
    req.response.write(jsonEncode(out));
    await req.response.close();
  });
  var stored = '';
  VizioAdapter make(String fp, String pin) => VizioAdapter(
    ip.address,
    (_, __) async => true,
    fp,
    sha256hex,
    (_) async => stored.isEmpty ? null : stored,
    (_, v) async => stored = v,
    () async => pin,
  );
  final a = make(tvPin, '1234');
  try {
    await fail(() => a.sendKey('UP')); // not paired
    await a.pair();
    check(stored, 'ZAUTH');
    check(
      log.first,
      'PUT /pairing/start  {"DEVICE_NAME":"TV Bridge","DEVICE_ID":"tv-bridge"}',
    );
    check(
      log[1],
      'PUT /pairing/pair  {"DEVICE_ID":"tv-bridge","CHALLENGE_TYPE":1,"RESPONSE_VALUE":"1234","PAIRING_REQ_TOKEN":77}',
    );
    await a.sendKey('VOL_UP');
    check(
      log.last,
      'PUT /key_command/ ZAUTH {"KEYLIST":[{"CODESET":5,"CODE":1,"ACTION":"KEYPRESS"}]}',
    );
    await fail(() => a.sendKey('NOPE'));
    await fail(() => make(tvPin, '9999').pair()); // TV rejects PIN
    await fail(() => make(tvPin, 'abcd').pair()); // bad PIN format
    await fail(() => make('0' * 64, '1234').pair()); // pin mismatch
    await a.close();
    await fail(() => a.pair());
    print(
      'Vizio request builder, discovery and fake HTTPS pairing tests passed',
    );
  } finally {
    await a.close();
    await sub.cancel();
    await server.close(force: true);
    await dir.delete(recursive: true);
  }
}
