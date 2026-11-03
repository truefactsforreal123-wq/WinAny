import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../lib/remote_transport.dart';

const helper = 'packages/remote_transport/test/crypto_helper.cjs';
Future<String> node(List<String> args) async {
  final result = await Process.run('node', [helper, ...args]);
  if (result.exitCode != 0) throw StateError('${result.stderr}');
  return (result.stdout as String).trim();
}

String b(List<int> x) => base64Encode(x);
Future<Identity> makeIdentity() async {
  final keys = jsonDecode(await node(['generate'])) as Map<String, dynamic>;
  return Identity(
    base64Decode(keys['public']),
    (data) async =>
        base64Decode(await node(['sign', keys['private'], b(data)])),
    (key, data, sig) async =>
        await node(['verify', b(key), b(data), b(sig)]) == 'true',
    (data) async => base64Decode(await node(['hash', b(data)])),
  );
}

Future<void> main() async {
  final dir = await Directory.systemTemp.createTemp('direct_tls_test_');
  DirectListener? listener;
  DirectSession? client;
  try {
    final cert = '${dir.path}/cert.pem', key = '${dir.path}/key.pem';
    final generated = await Process.run(
      r'C:\Program Files\Git\usr\bin\openssl.exe',
      [
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
        '/CN=localhost',
      ],
    );
    if (generated.exitCode != 0) throw StateError('${generated.stderr}');
    final fingerprint = await node(['cert', cert]);
    final context = SecurityContext()
      ..useCertificateChain(cert)
      ..usePrivateKey(key);
    final serverIdentity = await makeIdentity(),
        clientIdentity = await makeIdentity();
    final serverCode = Completer<String>(), clientCode = Completer<String>();
    final received = Completer<DirectSession>();
    listener = await DirectListener.start(
      enabled: true,
      address: InternetAddress.loopbackIPv4,
      port: 0,
      context: context,
      certificateFingerprint: fingerprint,
      identity: serverIdentity,
      accept: (_, code) async {
        serverCode.complete(code);
        if (await clientCode.future != code) throw StateError('code mismatch');
        return AccessRequest('basic');
      },
      onSession: received.complete,
    );
    client = await connectDirect(
      address: InternetAddress.loopbackIPv4,
      port: listener.port,
      identity: clientIdentity,
      enableFirstUse: true,
      approveCertificate: (certHash) async => certHash == fingerprint,
      confirmPeer: (_, __, code) async {
        clientCode.complete(code);
        return await serverCode.future == code;
      },
    ).timeout(const Duration(seconds: 20));
    final server = await received.future.timeout(const Duration(seconds: 5));
    if (client.access?.preset != 'basic' || client.access!.elevatedConfirmed)
      throw StateError('invalid basic metadata');
    if (server.comparisonCode != client.comparisonCode)
      throw StateError('code mismatch');
    await client.send({'type': 'offer', 'sdp': 'test'});
    if ((await server.receive())['sdp'] != 'test')
      throw StateError('frame mismatch');
    await server.send({'type': 'answer', 'sdp': 'reply'});
    if ((await client.receive())['sdp'] != 'reply')
      throw StateError('reverse frame mismatch');
    server.close();
    client.close();
    await listener.close();
    final fullReceived = Completer<DirectSession>();
    final fullListener = await DirectListener.start(
      enabled: true,
      address: InternetAddress.loopbackIPv4,
      port: 0,
      context: context,
      certificateFingerprint: fingerprint,
      identity: serverIdentity,
      accept: (_, __) async => AccessRequest('full', elevatedConfirmed: true),
      onSession: fullReceived.complete,
    );
    final fullClient = await connectDirect(
      address: InternetAddress.loopbackIPv4,
      port: fullListener.port,
      identity: clientIdentity,
      enableFirstUse: true,
      approveCertificate: (_) async => true,
      confirmPeer: (_, __, ___) async => true,
    ).timeout(const Duration(seconds: 20));
    final fullServer = await fullReceived.future;
    if (fullClient.access?.preset != 'full' ||
        fullClient.access!.elevatedConfirmed ||
        fullServer.access?.elevatedConfirmed != true)
      throw StateError('invalid full metadata');
    fullClient.close();
    fullServer.close();
    await fullListener.close();
    Future<void> blocked(
      String name, {
      String? certPin,
      String? keyPin,
      AccessRequest? access,
      bool approve = true,
      bool confirm = true,
    }) async {
      var handedOut = false;
      final candidate = await DirectListener.start(
        enabled: true,
        address: InternetAddress.loopbackIPv4,
        port: 0,
        context: context,
        certificateFingerprint: fingerprint,
        identity: serverIdentity,
        accept: (_, __) async => access,
        onSession: (_) {
          handedOut = true;
        },
      );
      var failed = false;
      try {
        final unexpected = await connectDirect(
          address: InternetAddress.loopbackIPv4,
          port: candidate.port,
          identity: clientIdentity,
          enableFirstUse: certPin == null,
          pinnedCertificate: certPin,
          pinnedKey: keyPin,
          approveCertificate: (_) async => approve,
          confirmPeer: (_, __, ___) async => confirm,
        ).timeout(const Duration(seconds: 20));
        unexpected.close();
      } catch (_) {
        failed = true;
      }
      await candidate.close();
      if (!failed || handedOut) throw StateError('$name was not blocked');
    }

    await blocked(
      'certificate pin mismatch',
      certPin: '0' * 64,
      keyPin: '0' * 64,
      access: AccessRequest('basic'),
    );
    await blocked(
      'key pin mismatch',
      certPin: fingerprint,
      keyPin: '0' * 64,
      access: AccessRequest('basic'),
    );
    await blocked(
      'certificate rejection',
      approve: false,
      access: AccessRequest('basic'),
    );
    await blocked('owner rejection');
    await blocked(
      'full without elevated confirmation',
      access: AccessRequest('full'),
    );
    await blocked(
      'client comparison rejection',
      confirm: false,
      access: AccessRequest('basic'),
    );
    print(
      'TLS loopback: real Ed25519 mutual proof, simultaneous comparison, consent and JSON frame passed',
    );
  } finally {
    client?.close();
    await listener?.close();
    await dir.delete(recursive: true);
  }
}
