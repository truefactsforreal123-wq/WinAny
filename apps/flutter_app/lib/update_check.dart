import 'dart:convert';
import 'dart:io';

import 'native_core.dart';

/// Release Ed25519 public key (base64) that verifies update manifests. The private key stays offline.
const kUpdatePublicKeyB64 = 'WY0zIj8JdFNFx0JNzPFC2DPZENXZRPt+9XxAEXeSuSw=';

typedef Sha256Fn = Future<List<int>> Function(List<int> data);
typedef VerifyFn = Future<bool> Function(
    List<int> key, List<int> msg, List<int> sig);

/// Core-backed hash and Ed25519 verify (ring, via identity_verify).
Sha256Fn coreSha256([NativeCore? core]) {
  final c = core ?? NativeCore();
  return (d) async => base64Decode(
        c.call({'op': 'sha256', 'data': base64Encode(d)})['sha256'] as String,
      );
}

VerifyFn coreVerify([NativeCore? core]) {
  final c = core ?? NativeCore();
  return (k, m, s) async =>
      c.call({
        'op': 'identity_verify',
        'public_key': base64Encode(k),
        'message': base64Encode(m),
        'signature': base64Encode(s),
      })['valid'] ==
      true;
}

/// True if [a] is strictly newer than [b]; non-numeric parts count as 0.
bool isNewer(String a, String b) {
  List<int> p(String v) => [
        for (final s in v.split('+').first.split('-').first.split('.'))
          int.tryParse(s) ?? 0,
      ];
  final x = p(a), y = p(b);
  for (var i = 0; i < 3; i++) {
    final d = (i < x.length ? x[i] : 0) - (i < y.length ? y[i] : 0);
    if (d != 0) return d > 0;
  }
  return false;
}

/// Steps 3, 4 and 6 of packaging/UPDATE.md. True only if hash and signature both pass.
Future<bool> verifyUpdate(
  List<int> file,
  Map<String, dynamic> manifest, {
  required Sha256Fn sha256,
  required VerifyFn verify,
  String publicKeyB64 = kUpdatePublicKeyB64,
}) async {
  try {
    final expected = manifest['sha256'];
    final sig = manifest['signature'];
    if (expected is! String || sig is! String || sig.isEmpty) return false;
    final digest = await sha256(file);
    final hex = digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    if (digest.length != 32 || hex != expected.toLowerCase()) return false;
    return await verify(base64Decode(publicKeyB64), digest, base64Decode(sig));
  } catch (_) {
    return false;
  }
}

/// Returns the verified installer path if a newer version exists, else null. Throws on any failure.
/// The caller runs it (`/SILENT` on Windows) or prompts the user (Linux).
Future<String?> checkForUpdate({
  required Uri manifestUrl,
  required String currentVersion,
  required String platform,
  Sha256Fn? sha256,
  VerifyFn? verify,
}) async {
  if (manifestUrl.scheme != 'https') throw StateError('Manifest must be HTTPS');
  final hash = sha256 ?? coreSha256();
  final check = verify ?? coreVerify();
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 10);
  File? out;
  try {
    Future<List<int>> get(Uri u, int max) async {
      final res = await (await client.getUrl(u)).close();
      if (res.statusCode != 200) {
        throw HttpException('HTTP ${res.statusCode}', uri: u);
      }
      final b = <int>[];
      await for (final c in res) {
        b.addAll(c);
        if (b.length > max) throw StateError('Download too large');
      }
      return b;
    }

    final m = jsonDecode(utf8.decode(await get(manifestUrl, 65536)));
    if (m is! Map<String, dynamic> ||
        m['version'] is! String ||
        !RegExp(r'^\d+\.\d+\.\d+$').hasMatch(m['version'] as String) ||
        m['platform'] != platform ||
        m['url'] is! String) {
      throw const FormatException('Invalid update manifest');
    }
    if (!isNewer(m['version'] as String, currentVersion)) return null;
    final url = Uri.parse(m['url'] as String);
    if (url.scheme != 'https') throw StateError('Installer must be HTTPS');
    // shortcut: whole installer buffered in memory (capped 512 MB), stream-hash if installers grow.
    final bytes = await get(url, 512 << 20);
    if (!await verifyUpdate(bytes, m, sha256: hash, verify: check)) {
      throw StateError('Update verification failed');
    }
    final name = url.pathSegments.isEmpty ? '' : url.pathSegments.last;
    final e = name.split('.').last;
    final ext = RegExp(r'^[A-Za-z0-9]{1,8}$').hasMatch(e) ? e : 'bin';
    out = File(
      '${Directory.systemTemp.path}${Platform.pathSeparator}remotelink-update-${m['version']}.$ext',
    );
    await out.writeAsBytes(bytes, flush: true);
    return out.path;
  } catch (_) {
    if (out != null && await out.exists()) await out.delete();
    rethrow;
  } finally {
    client.close(force: true);
  }
}
