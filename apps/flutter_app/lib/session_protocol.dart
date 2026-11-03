import 'dart:convert';
import 'dart:typed_data';

Uint8List? _b64(Object? value, int length) {
  if (value is! String || value.length > (length + 2) ~/ 3 * 4) return null;
  try {
    final bytes = base64Decode(value);
    return bytes.length == length ? bytes : null;
  } catch (_) {
    return null;
  }
}

/// Validates a challenge nonce received from the peer (32 bytes, base64).
Uint8List? parseNonce(Object? value) => _b64(value, 32);

const trustPresets = {'basic', 'normal', 'full'};
final _controllerId = RegExp(r'^\d{12}$');
final _deviceId = RegExp(r'^[0-9a-f]{64}$');

class TrustedDevice {
  const TrustedDevice(this.deviceId, this.controllerId, this.preset);
  final String deviceId; // key fingerprint (core device id)
  final String controllerId; // signaling id, needed for server revoke
  final String preset;
  Map<String, String> toJson() => {
        'deviceId': deviceId,
        'controllerId': controllerId,
        'preset': preset,
      };
}

/// Stored data is untrusted: invalid entries are dropped.
Map<String, TrustedDevice> parseTrustedDevices(String? json) {
  final out = <String, TrustedDevice>{};
  if (json == null || json.length > 1 << 20) return out;
  try {
    final list = jsonDecode(json);
    if (list is! List) return out;
    for (final e in list.take(500)) {
      if (e is! Map ||
          e['deviceId'] is! String ||
          e['controllerId'] is! String ||
          e['preset'] is! String ||
          !_deviceId.hasMatch(e['deviceId'] as String) ||
          !_controllerId.hasMatch(e['controllerId'] as String) ||
          !trustPresets.contains(e['preset'])) {
        continue;
      }
      out[e['deviceId'] as String] = TrustedDevice(
        e['deviceId'] as String,
        e['controllerId'] as String,
        e['preset'] as String,
      );
    }
  } catch (_) {}
  return out;
}

bool validControllerId(Object? id) =>
    id is String && _controllerId.hasMatch(id);

/// OPAQUE message sizes (ristretto255, checked by the core tests).
const ke1Length = 96, ke2Length = 320, ke3Length = 64;

/// A base64 OPAQUE message of exactly [length] bytes, or null.
String? opaqueMessage(Object? value, int length) =>
    _b64(value, length) == null ? null : value as String;

/// A controller's reply to a challenge, validated. [ke1] starts the OPAQUE password login; the password is never sent.
class AuthReply {
  const AuthReply(this.publicKey, this.signature, this.ke1);
  final String publicKey, signature;
  final String? ke1;
}

AuthReply? parseAuthReply(Map<String, dynamic> m) {
  final ke1 = m['ke1'];
  if (_b64(m['public_key'], 32) == null ||
      _b64(m['signature'], 64) == null ||
      (ke1 != null && opaqueMessage(ke1, ke1Length) == null)) {
    return null;
  }
  return AuthReply(
    m['public_key'] as String,
    m['signature'] as String,
    ke1 as String?,
  );
}

class Monitor {
  const Monitor(this.id, this.w, this.h, this.primary);
  final int id, w, h;
  final bool primary;
}

/// Validates the monitor list a target reports; null if malformed.
List<Monitor>? parseMonitors(Object? raw) {
  if (raw is! List || raw.length > 16) return null;
  final out = <Monitor>[];
  final seen = <int>{};
  for (final e in raw) {
    if (e is! Map) return null;
    final id = e['id'], w = e['w'], h = e['h'];
    if (id is! int ||
        id < 0 ||
        id >= 64 || // core accepts display < 64
        !seen.add(id) ||
        w is! int ||
        h is! int ||
        w < 1 ||
        h < 1 ||
        w > 100000 ||
        h > 100000 ||
        e['x'] is! int ||
        e['y'] is! int ||
        e['primary'] is! bool) {
      return null;
    }
    out.add(Monitor(id, w, h, e['primary'] as bool));
  }
  return out;
}

/// Text typed into the remote: no control characters (Enter is a key).
String? validRemoteText(String text) => text.isEmpty ||
        text.length > 1024 ||
        text.runes.any((r) => r < 32 || r == 127 || (r >= 0x80 && r < 0xA0))
    ? null
    : text;
