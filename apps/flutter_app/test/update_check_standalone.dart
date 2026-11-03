import 'dart:convert';

import '../lib/update_check.dart';

Future<void> main() async {
  assert(isNewer('0.2.0', '0.1.9') && isNewer('1.0.0', '0.9.9'));
  assert(!isNewer('0.2.0', '0.2.0') && !isNewer('0.1.0', '0.2.0'));
  assert(base64Decode(kUpdatePublicKeyB64).length == 32);

  final file = utf8.encode('installer');
  // fake hash: 32 bytes of 7; fake verify accepts only signature "good"
  Future<List<int>> sha(List<int> d) async => List.filled(32, 7);
  final hex = '07' * 32;
  final sigGood = base64Encode(utf8.encode('good'));
  // fake verify: "signature" is valid only over the exact message for 1.2.3 / windows
  final signed = updateMessage('1.2.3', 'windows', List.filled(32, 7));
  Future<bool> verify(List<int> k, List<int> m, List<int> s) async =>
      utf8.decode(s) == 'good' &&
      k.length == 32 &&
      m.length == signed.length &&
      List.generate(m.length, (i) => m[i] == signed[i]).every((b) => b);
  Future<bool> run(Map<String, dynamic> m) =>
      verifyUpdate(file, {'version': '1.2.3', 'platform': 'windows', ...m},
          sha256: sha, verify: verify);

  assert(utf8.decode(signed.sublist(0, signed.length - 32)) ==
      'remote-link-update-v1\x001.2.3\x00windows\x00');
  assert(await run({'sha256': hex, 'signature': sigGood}));
  assert(await run({'sha256': hex.toUpperCase(), 'signature': sigGood}));
  assert(!await run({'sha256': hex, 'signature': sigGood, 'version': '1.2.4'}));
  assert(!await run({'sha256': hex, 'signature': sigGood, 'platform': 'linux'}));
  assert(!await run({'sha256': '00' * 32, 'signature': sigGood}));
  assert(!await run(
      {'sha256': hex, 'signature': base64Encode(utf8.encode('bad'))}));
  assert(!await run({'sha256': hex, 'signature': ''}));
  assert(!await run({'sha256': hex}));
  assert(!await run({'sha256': hex, 'signature': '!!notbase64'}));
  print('update_check ok');
}
