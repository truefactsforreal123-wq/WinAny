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
  Future<bool> verify(List<int> k, List<int> m, List<int> s) async =>
      utf8.decode(s) == 'good' && m.length == 32 && k.length == 32;
  Future<bool> run(Map<String, dynamic> m) =>
      verifyUpdate(file, m, sha256: sha, verify: verify);

  assert(await run({'sha256': hex, 'signature': sigGood}));
  assert(await run({'sha256': hex.toUpperCase(), 'signature': sigGood}));
  assert(!await run({'sha256': '00' * 32, 'signature': sigGood}));
  assert(!await run(
      {'sha256': hex, 'signature': base64Encode(utf8.encode('bad'))}));
  assert(!await run({'sha256': hex, 'signature': ''}));
  assert(!await run({'sha256': hex}));
  assert(!await run({'sha256': hex, 'signature': '!!notbase64'}));
  print('update_check ok');
}
