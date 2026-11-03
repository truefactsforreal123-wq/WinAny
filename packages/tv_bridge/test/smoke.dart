import 'dart:async';
import 'dart:io';

import '../lib/tv_bridge.dart';

Future<void> expectFailure(FutureOr<void> Function() run) async {
  try {
    await run();
  } catch (_) {
    return;
  }
  throw StateError('Expected failure');
}

Future<void> main() async {
  await expectFailure(() => RokuAdapter('127.0.0.1', (_, __) async => true));
  await expectFailure(() => RokuAdapter('8.8.8.8', (_, __) async => true));
  await expectFailure(
    () => SamsungAdapter(
      '192.168.1.1',
      (_, __) async => true,
      'bad',
      (_) => '',
      (_) async => null,
      (_, __) async {},
    ),
  );
  final denied = RokuAdapter('192.168.1.1', (_, __) async => false);
  await expectFailure(() => denied.pair());
  await expectFailure(() => denied.sendKey('../bad'));
  await expectFailure(() => denied.launchApp('123?bad'));
  final unsupported = UnsupportedTvAdapter(
    'Android TV Remote v2 is not implemented',
  );
  assert(unsupported.capabilities.isEmpty);
  await expectFailure(() => unsupported.pair());
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
    print('Policy tests passed; no private interface for fake HTTP test');
    return;
  }
  final server = await HttpServer.bind(ip, 8060);
  final paths = <String>[];
  final subscription = server.listen((r) async {
    paths.add('${r.method} ${r.uri.path}');
    if (r.uri.path == '/keypress/Home') r.response.statusCode = 403;
    r.response.write('<device-info/>');
    await r.response.close();
  });
  try {
    final roku = RokuAdapter(ip.address, (_, __) async => true);
    await roku.pair();
    await roku.sendKey('Up');
    await roku.launchApp('123');
    await expectFailure(() => roku.sendKey('Home'));
    if (!paths.contains('POST /keypress/Up') ||
        !paths.contains('POST /launch/123'))
      throw StateError('Wrong paths: $paths');
    print('Policy and fake Roku HTTP tests passed');
  } finally {
    await subscription.cancel();
    await server.close(force: true);
  }
}
