import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

/// Target side: exactly one challenge per session; the nonce expires and answers are capped.
class ChallengeGate {
  ChallengeGate({this.ttl = defaultTtl, this.maxAttempts = defaultAttempts});
  static const defaultTtl = Duration(seconds: 20);
  static const defaultAttempts = 3;
  final Duration ttl;
  final int maxAttempts;
  Uint8List? _nonce;
  DateTime? _issuedAt;
  bool _issued = false;
  int attempts = 0;

  /// Returns [nonce] the first time only (never re-issued, e.g. on a repeated hello).
  Uint8List? issue(DateTime now, Uint8List nonce) {
    if (_issued) return null;
    _issued = true;
    _nonce = nonce;
    _issuedAt = now;
    return nonce;
  }

  /// The nonce to verify an answer against, or null if expired, closed or out of attempts.
  /// Every non-null result counts as one attempt.
  Uint8List? answer(DateTime now) {
    final nonce = _nonce;
    if (nonce == null ||
        now.difference(_issuedAt!) > ttl ||
        attempts >= maxAttempts) {
      return null;
    }
    attempts++;
    return nonce;
  }

  bool get exhausted => attempts >= maxAttempts;
  void close() => _nonce = null;

  /// Open and unexpired; counts no attempt (for the OPAQUE finish of an answer already counted).
  bool live(DateTime now) =>
      _nonce != null && now.difference(_issuedAt!) <= ttl;
}

/// Controller side: the one session this device requested itself.
class ControllerBinding {
  ControllerBinding(this.sessionId, this.targetId, this.startedAt);
  static const window = Duration(seconds: 30);
  final String sessionId, targetId;
  final DateTime startedAt;

  /// Sign only for our own session and target, only early in the session.
  bool allowsAuth(String session, String? target, DateTime now) =>
      session == sessionId &&
      (target == null || target == targetId) &&
      !now.isBefore(startedAt) &&
      now.difference(startedAt) <= window;
}

class _Lock {
  int failed = 0, level = 0;
  DateTime? until;
}

/// Per-controller lockout: 3 failed sessions lock for 1 minute, doubling up to 24 hours.
class Lockouts {
  static const sessionsPerLock = 3;
  static const maxEntries = 500;
  static const first = Duration(minutes: 1), cap = Duration(hours: 24);
  final Map<String, _Lock> _m = {};

  static Duration lockFor(int level) {
    final minutes = first.inMinutes * math.pow(2, math.min(level, 20)).toInt();
    return Duration(minutes: math.min(minutes, cap.inMinutes));
  }

  bool isLocked(String id, DateTime now) =>
      _m[id]?.until?.isAfter(now) ?? false;

  void recordFailedSession(String id, DateTime now) {
    if (!_m.containsKey(id) && _m.length >= maxEntries) {
      // Never evict an active lock (an attacker could flush it with fresh ids);
      // if all are locked the target-wide [PasswordBudget] still bounds guessing.
      final free = _m.keys.where((k) => !isLocked(k, now));
      if (free.isEmpty) return;
      _m.remove(free.first);
    }
    final e = _m.putIfAbsent(id, _Lock.new);
    if (++e.failed >= sessionsPerLock) {
      e.failed = 0;
      e.until = now.add(lockFor(e.level++));
    }
  }

  void reset(String id) => _m.remove(id);

  String toJson() => jsonEncode({
        for (final e in _m.entries)
          e.key: [
            e.value.failed,
            e.value.level,
            e.value.until?.millisecondsSinceEpoch
          ],
      });

  /// Stored data is untrusted: bad entries are dropped.
  static Lockouts fromJson(String? json) {
    final out = Lockouts();
    if (json == null || json.length > 1 << 20) return out;
    try {
      final m = jsonDecode(json);
      if (m is! Map) return out;
      for (final e in m.entries.take(maxEntries)) {
        final v = e.value;
        if (e.key is! String ||
            !RegExp(r'^\d{12}$').hasMatch(e.key as String) ||
            v is! List ||
            v.length != 3 ||
            v[0] is! int ||
            v[1] is! int ||
            (v[2] != null && v[2] is! int) ||
            (v[0] as int) < 0 ||
            (v[1] as int) < 0) {
          continue;
        }
        out._m[e.key as String] = _Lock()
          ..failed = math.min(v[0] as int, sessionsPerLock)
          ..level = math.min(v[1] as int, 40)
          ..until = v[2] == null
              ? null
              : DateTime.fromMillisecondsSinceEpoch(v[2] as int);
      }
    } catch (_) {}
    return out;
  }
}

/// Target-wide password budget across all controllers: 10 attempts per hour, then exponential
/// backoff (1 min doubling to 24 h). Blocks only the password path.
class PasswordBudget {
  static const perHour = 10;
  final List<int> _times = []; // ms since epoch of recent attempts
  int level = 0;
  DateTime? until;

  bool canAttempt(DateTime now) => !(until?.isAfter(now) ?? false);

  void record(DateTime now) {
    final u = until;
    if (u != null && now.difference(u) > Lockouts.cap)
      level = 0; // quiet for a day
    final cutoff =
        now.subtract(const Duration(hours: 1)).millisecondsSinceEpoch;
    _times.removeWhere((t) => t < cutoff);
    _times.add(now.millisecondsSinceEpoch);
    if (_times.length >= perHour) {
      _times.clear();
      until = now.add(Lockouts.lockFor(level++));
    }
  }

  /// A correct password: the owner is not an attacker.
  void succeeded() {
    _times.clear();
    level = 0;
    until = null;
  }

  String toJson() => jsonEncode({
        't': _times,
        'l': level,
        'u': until?.millisecondsSinceEpoch,
      });

  static PasswordBudget fromJson(String? json) {
    final out = PasswordBudget();
    if (json == null || json.length > 1 << 16) return out;
    try {
      final m = jsonDecode(json);
      if (m is! Map) return out;
      final t = m['t'], l = m['l'], u = m['u'];
      if (t is List && t.length < perHour && t.every((e) => e is int)) {
        out._times.addAll(t.cast<int>());
      }
      if (l is int && l >= 0) out.level = math.min(l, 40);
      if (u is int) out.until = DateTime.fromMillisecondsSinceEpoch(u);
    } catch (_) {}
    return out;
  }
}

/// Owner prompts: 1 per controller id per 10 minutes under a global cap of 20; trusted ids bypass.
/// Over the limit, requests are dropped without bothering the owner.
class PromptLimiter {
  static const globalMax = 20;
  static const window = Duration(minutes: 10);
  final Map<String, DateTime> _byId = {};
  final List<DateTime> _all = [];

  bool allow(DateTime now, String id, {bool trusted = false}) {
    if (trusted) return true;
    _all.removeWhere((t) => now.difference(t) >= window);
    _byId.removeWhere((_, t) => now.difference(t) >= window);
    if (_byId.containsKey(id) || _all.length >= globalMax) return false;
    _byId[id] = now;
    _all.add(now);
    return true;
  }
}

/// Keeps an auth-window expiry that lands during a verification, so the owner prompt is not lost.
class AuthWindow {
  bool verifying = false;
  bool _expired = false;

  /// The window timer fired; true if the owner prompt is due now.
  bool expire() {
    if (verifying) {
      _expired = true;
      return false;
    }
    return true;
  }

  /// A verification ended without granting; true if the window expired meanwhile.
  bool finishFailed() {
    verifying = false;
    final due = _expired;
    _expired = false;
    return due;
  }

  void finishOk() {
    verifying = false;
    _expired = false;
  }
}

final _fingerprint = RegExp(r'^sha-256 (?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$');

/// The single DTLS fingerprint of an SDP, as `sha-256 AB:CD:...`; null if absent, malformed or ambiguous.
String? dtlsFingerprint(String? sdp) {
  if (sdp == null || sdp.length > 60000) return null;
  String? found;
  for (final line in const LineSplitter().convert(sdp)) {
    if (!line.startsWith('a=fingerprint:')) continue;
    final value = line.substring(14).trim();
    if (!_fingerprint.hasMatch(value)) return null;
    final normal = 'sha-256 ${value.substring(8).toUpperCase()}';
    if (found != null && found != normal) return null;
    found = normal;
  }
  return found;
}

/// Standard padded base64 of a 32-byte key given as base64 or base64url (padding optional).
String? normalizeKey(Object? value) {
  if (value is! String || value.isEmpty || value.length > 64) return null;
  try {
    var s = value.replaceAll('-', '+').replaceAll('_', '/');
    s = s.padRight((s.length + 3) ~/ 4 * 4, '=');
    final bytes = base64Decode(s);
    return bytes.length == 32 ? base64Encode(bytes) : null;
  } catch (_) {
    return null;
  }
}
