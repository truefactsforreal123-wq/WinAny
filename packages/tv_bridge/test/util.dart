import 'dart:io';

/// Shared helpers for fake-TV tests: private interface lookup and openssl certs.
Future<InternetAddress?> privateIp() async {
  for (final i in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
    for (final a in i.addresses) {
      final b = a.rawAddress;
      if (b[0] == 10 ||
          (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
          (b[0] == 192 && b[1] == 168)) {
        return a;
      }
    }
  }
  return null;
}

final opensslPath =
    File(r'C:\Program Files\Git\usr\bin\openssl.exe').existsSync()
    ? r'C:\Program Files\Git\usr\bin\openssl.exe'
    : 'openssl';

ProcessResult openssl(List<String> args) {
  final p = Process.runSync(opensslPath, args);
  if (p.exitCode != 0) throw StateError('openssl failed: ${p.stderr}');
  return p;
}

/// Self-signed RSA cert; returns PEM text, key PEM text and DER bytes.
({String cert, String key, List<int> der}) makeCert(Directory dir, String cn) {
  final k = '${dir.path}/$cn.key', c = '${dir.path}/$cn.pem';
  openssl([
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', k, //
    '-out', c, '-days', '1', '-subj', '/CN=$cn',
  ]);
  openssl(['x509', '-in', c, '-outform', 'der', '-out', '${dir.path}/$cn.der']);
  return (
    cert: File(c).readAsStringSync(),
    key: File(k).readAsStringSync(),
    der: File('${dir.path}/$cn.der').readAsBytesSync(),
  );
}

/// Independent SHA-256 oracle via openssl.
String sha256hex(List<int> data) {
  final f = File(
    '${Directory.systemTemp.path}/tv_bridge_sha_${data.length}.bin',
  )..writeAsBytesSync(data);
  try {
    return (openssl(['dgst', '-sha256', '-r', f.path]).stdout as String)
        .split(' ')
        .first;
  } finally {
    f.deleteSync();
  }
}

/// Modulus bytes via `openssl x509 -modulus`, independent of the DER parser.
List<int> opensslModulus(Directory dir, String cn) {
  final out =
      openssl([
            'x509', '-in', '${dir.path}/$cn.pem', '-noout', '-modulus', //
          ]).stdout
          as String;
  final hex = out.trim().split('=').last;
  return [
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ];
}

void check(Object? actual, Object? expected) {
  if ('$actual' != '$expected') {
    throw StateError('Expected $expected, got $actual');
  }
}

Future<void> fail(Future<void> Function() f) async {
  try {
    await f();
  } catch (_) {
    return;
  }
  throw StateError('Expected failure');
}
