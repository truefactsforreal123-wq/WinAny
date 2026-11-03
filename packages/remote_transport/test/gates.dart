import 'dart:io';

import '../lib/remote_transport.dart';

Future<void> main() async {
  var checks = 0;
  void check(bool condition) {
    if (!condition) throw StateError('check failed');
    checks++;
  }

  final identity = Identity(
    List.filled(32, 1),
    (_) async => List.filled(64, 0),
    (_, __, ___) async => false,
    (_) async => List.filled(32, 0),
  );
  try {
    AccessRequest('invalid');
    throw StateError('invalid preset accepted');
  } on ArgumentError {
    checks++;
  }
  try {
    AccessRequest('basic', permissions: {'x': true});
    throw StateError('invalid permissions accepted');
  } on ArgumentError {
    checks++;
  }
  try {
    await DirectListener.start(
      enabled: false,
      address: InternetAddress.loopbackIPv4,
      port: 0,
      context: SecurityContext(),
      certificateFingerprint: '0' * 64,
      identity: identity,
      accept: (_, __) async => null,
      onSession: (_) {},
    );
    throw StateError('disabled listener started');
  } on StateError catch (e) {
    check(e.message == 'direct mode disabled');
  }
  try {
    await connectDirect(
      address: InternetAddress.loopbackIPv4,
      port: 1,
      identity: identity,
      approveCertificate: (_) async => true,
      confirmPeer: (_, __, ___) async => true,
    );
    throw StateError('first use enabled');
  } on StateError catch (e) {
    check(e.message == 'first use disabled');
  }
  try {
    await connectDirect(
      address: InternetAddress.loopbackIPv4,
      port: 1,
      identity: identity,
      pinnedCertificate: 'x',
      approveCertificate: (_) async => true,
      confirmPeer: (_, __, ___) async => true,
    );
    throw StateError('partial pins accepted');
  } on ArgumentError {
    checks++;
  }
  print('$checks gate checks passed');
}
