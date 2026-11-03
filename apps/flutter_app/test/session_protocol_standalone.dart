import 'dart:convert';

import '../lib/session_protocol.dart';

void main() {
  assert(parseNonce(base64Encode(List.filled(32, 1))) != null);
  assert(parseNonce(base64Encode(List.filled(31, 1))) == null);
  assert(parseNonce(5) == null && parseNonce('!!') == null);

  final id = 'a' * 64;
  final good = jsonEncode([
    {'deviceId': id, 'controllerId': '123456789012', 'preset': 'normal'},
    {'deviceId': id, 'controllerId': '12', 'preset': 'normal'},
    {'deviceId': 'zz', 'controllerId': '123456789012', 'preset': 'normal'},
    {'deviceId': id, 'controllerId': '123456789012', 'preset': 'custom'},
    'junk',
  ]);
  final parsed = parseTrustedDevices(good);
  assert(parsed.length == 1 && parsed[id]!.preset == 'normal');
  assert(parseTrustedDevices('{').isEmpty && parseTrustedDevices(null).isEmpty);

  final key = base64Encode(List.filled(32, 2)),
      sig = base64Encode(List.filled(64, 3));
  assert(parseAuthReply({'public_key': key, 'signature': sig}) != null);
  assert(parseAuthReply({'public_key': key, 'signature': key}) == null);
  final ke1 = base64Encode(List.filled(ke1Length, 4));
  assert(
      parseAuthReply({'public_key': key, 'signature': sig, 'ke1': 1}) == null);
  assert(parseAuthReply({'public_key': key, 'signature': sig, 'ke1': key}) ==
      null);
  assert(
      parseAuthReply({'public_key': key, 'signature': sig, 'ke1': ke1})!.ke1 ==
          ke1);
  // OPAQUE messages: exact length only; long input is refused before decoding.
  final ke2 = base64Encode(List.filled(ke2Length, 5));
  assert(opaqueMessage(ke2, ke2Length) == ke2);
  assert(opaqueMessage(ke2, ke3Length) == null);
  assert(opaqueMessage('$ke2 ', ke2Length) == null);
  assert(opaqueMessage(base64Encode(List.filled(ke3Length, 6)), ke3Length) !=
      null);
  assert(opaqueMessage(null, ke3Length) == null);

  Map<String, dynamic> mon(int i) =>
      {'id': i, 'x': 0, 'y': 0, 'w': 1920, 'h': 1080, 'primary': i == 0};
  assert(parseMonitors([mon(0), mon(1)])!.length == 2);
  assert(parseMonitors([mon(0), mon(0)]) == null);
  assert(parseMonitors([mon(64)]) == null);
  assert(parseMonitors([
        {...mon(0), 'w': 0}
      ]) ==
      null);
  assert(parseMonitors('x') == null);
  assert(parseMonitors(List.generate(17, mon)) == null);

  assert(validRemoteText('héllo') == 'héllo');
  assert(validRemoteText('') == null && validRemoteText('a\nb') == null);
  assert(validRemoteText('a\u0000') == null &&
      validRemoteText('x' * 1025) == null);
  assert(validControllerId('123456789012') && !validControllerId('1234'));
  print('session protocol tests passed');
}
