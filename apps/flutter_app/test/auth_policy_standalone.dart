import 'dart:convert';
import 'dart:typed_data';

import '../lib/auth_policy.dart';

void main() {
  final t0 = DateTime(2026, 1, 1, 12);
  final nonce = Uint8List.fromList(List.filled(32, 9));

  // Target: single challenge, expiry, attempt cap.
  var gate = ChallengeGate();
  assert(gate.answer(t0) == null); // nothing issued yet
  assert(gate.issue(t0, nonce) == nonce);
  assert(gate.issue(t0, Uint8List(32)) == null); // never re-issued
  assert(gate.answer(t0.add(const Duration(seconds: 20))) == nonce);
  assert(gate.answer(t0.add(const Duration(seconds: 21))) == null); // expired
  gate = ChallengeGate()..issue(t0, nonce);
  for (var i = 0; i < gate.maxAttempts; i++) {
    assert(gate.answer(t0) == nonce);
  }
  assert(gate.exhausted && gate.answer(t0) == null);
  gate = ChallengeGate()..issue(t0, nonce);
  assert(gate.live(t0.add(const Duration(seconds: 20))) && gate.attempts == 0);
  assert(!gate.live(t0.add(const Duration(seconds: 21))));
  gate.close();
  assert(gate.answer(t0) == null && !gate.live(t0));
  assert(!ChallengeGate().live(t0));

  // Controller: only its own session/target, only early.
  final b = ControllerBinding('s1', '111111111111', t0);
  assert(
      b.allowsAuth('s1', '111111111111', t0.add(const Duration(seconds: 30))));
  assert(
      !b.allowsAuth('s2', '111111111111', t0)); // relayed from another session
  assert(!b.allowsAuth('s1', '222222222222', t0)); // wrong target
  assert(
      !b.allowsAuth('s1', '111111111111', t0.add(const Duration(seconds: 31))));
  assert(!b.allowsAuth(
      's1', '111111111111', t0.subtract(const Duration(seconds: 1))));

  // Lockout: 3 failed sessions -> 1 min, doubling, capped at 24 h, persisted.
  final l = Lockouts();
  const id = '123456789012';
  var now = t0;
  l.recordFailedSession(id, now);
  l.recordFailedSession(id, now);
  assert(!l.isLocked(id, now));
  l.recordFailedSession(id, now);
  assert(l.isLocked(id, now.add(const Duration(seconds: 59))));
  assert(!l.isLocked(id, now.add(const Duration(minutes: 1))));
  assert(!l.isLocked('999999999999', now));
  now = now.add(const Duration(minutes: 5));
  for (var i = 0; i < 3; i++) {
    l.recordFailedSession(id, now);
  }
  assert(l.isLocked(id, now.add(const Duration(minutes: 1, seconds: 59))));
  assert(!l.isLocked(id, now.add(const Duration(minutes: 2))));
  assert(Lockouts.lockFor(0) == const Duration(minutes: 1));
  assert(Lockouts.lockFor(3) == const Duration(minutes: 8));
  assert(Lockouts.lockFor(30) == const Duration(hours: 24));
  final back = Lockouts.fromJson(l.toJson()); // survives a restart
  assert(back.isLocked(id, now.add(const Duration(minutes: 1))));
  l.reset(id);
  assert(!l.isLocked(id, now));
  assert(Lockouts.fromJson('{').toJson() == '{}');
  assert(
      Lockouts.fromJson('{"bad":[1,2,3],"123456789012":["x",1,2]}').toJson() ==
          '{}');

  // DTLS fingerprints.
  final hex =
      List.generate(32, (i) => i.toRadixString(16).padLeft(2, '0')).join(':');
  final fp = 'sha-256 ${hex.toUpperCase()}';
  assert(dtlsFingerprint(
          'v=0\r\na=fingerprint:sha-256 $hex\r\nm=video\r\na=fingerprint:$fp\r\n') ==
      fp);
  assert(dtlsFingerprint('v=0\r\n') == null);
  assert(dtlsFingerprint('a=fingerprint:sha-1 AA:BB\r\n') == null);
  assert(dtlsFingerprint(
          'a=fingerprint:$fp\r\na=fingerprint:sha-256 ${List.filled(32, 'AA').join(':')}\r\n') ==
      null);

  // Keys: base64url (as the server stores them) and standard compare equal.
  final raw = List<int>.generate(32, (i) => 250 - i);
  final std = base64Encode(raw);
  final url = base64Url.encode(raw).replaceAll('=', '');
  assert(normalizeKey(url) == std && normalizeKey(std) == std);
  assert(normalizeKey(base64Encode(raw.sublist(1))) == null &&
      normalizeKey(5) == null);

  // Target-wide password budget: 10 per hour across controllers, then backoff; persisted.
  final pb = PasswordBudget();
  var bt = t0;
  for (var i = 0; i < 9; i++) {
    assert(pb.canAttempt(bt));
    pb.record(bt = bt.add(const Duration(minutes: 1)));
  }
  assert(pb.canAttempt(bt));
  pb.record(bt); // 10th attempt within the hour
  assert(!pb.canAttempt(bt.add(const Duration(seconds: 59))));
  assert(pb.canAttempt(bt.add(const Duration(minutes: 1))));
  final pbBack = PasswordBudget.fromJson(pb.toJson());
  assert(!pbBack
      .canAttempt(bt.add(const Duration(seconds: 59)))); // survives restart
  var ct = bt.add(const Duration(minutes: 2));
  for (var i = 0; i < 10; i++) {
    pb.record(ct);
  }
  assert(!pb
      .canAttempt(ct.add(const Duration(minutes: 1, seconds: 59)))); // doubled
  assert(pb.canAttempt(ct.add(const Duration(minutes: 2))));
  // attempts older than an hour fall out of the window
  final slow = PasswordBudget();
  for (var i = 0; i < 30; i++) {
    slow.record(t0.add(Duration(minutes: 7 * i)));
  }
  assert(slow.canAttempt(t0.add(const Duration(minutes: 7 * 30))));
  pb.succeeded();
  assert(pb.canAttempt(ct) && pb.level == 0);
  assert(PasswordBudget.fromJson('{"t":"x"}').canAttempt(t0));
  assert(PasswordBudget.fromJson('nope').canAttempt(t0));

  // A full lockout table never evicts an active lock.
  final full = Lockouts();
  for (var i = 0; i < Lockouts.maxEntries; i++) {
    final key = i.toString().padLeft(12, '0');
    for (var j = 0; j < 3; j++) {
      full.recordFailedSession(key, t0);
    }
  }
  full.recordFailedSession(
      '999999999999', t0); // table full of locked ids: ignored
  assert(
      full.isLocked('000000000000', t0) && !full.isLocked('999999999999', t0));
  assert(full.isLocked('000000000499', t0));
  final later = t0.add(const Duration(minutes: 2));
  full.recordFailedSession(
      '999999999999', later); // expired locks may be evicted
  full.recordFailedSession('999999999999', later);
  full.recordFailedSession('999999999999', later);
  assert(full.isLocked('999999999999', later));

  // Owner prompts: 1 per id per 10 minutes, global cap 20, trusted ids bypass.
  final pl = PromptLimiter();
  assert(pl.allow(t0, '000000000001'));
  assert(!pl.allow(t0.add(const Duration(minutes: 9)), '000000000001'));
  assert(pl.allow(t0.add(const Duration(minutes: 9)), '000000000002'));
  assert(pl.allow(
      t0.add(const Duration(minutes: 10, seconds: 1)), '000000000001'));
  for (var i = 0; i < 50; i++) {
    assert(pl.allow(t0, '300000000000', trusted: true)); // never counted
  }
  final pg = PromptLimiter();
  for (var i = 0; i < PromptLimiter.globalMax; i++) {
    assert(pg.allow(t0, i.toString().padLeft(12, '0')));
  }
  assert(!pg.allow(t0, '999999999999')); // global cap
  assert(pg.allow(t0, '999999999999', trusted: true));
  assert(pg.allow(t0.add(const Duration(minutes: 11)), '999999999999'));

  // An auth-window expiry during a verification is kept and surfaces when it fails.
  final w = AuthWindow();
  assert(w.expire()); // idle: prompt due immediately
  w.verifying = true;
  assert(!w.expire()); // mid-verification: remembered
  assert(w.finishFailed()); // failed verification -> prompt now
  w.verifying = true;
  assert(!w.finishFailed()); // no expiry meanwhile
  w.verifying = true;
  w.expire();
  w.finishOk(); // granted: nothing to show
  assert(!w.finishFailed());

  // Enroll gate: single answer within 60 s.
  final eg = ChallengeGate(ttl: const Duration(seconds: 60), maxAttempts: 1)
    ..issue(t0, nonce);
  assert(eg.answer(t0.add(const Duration(seconds: 45))) == nonce);
  assert(eg.answer(t0.add(const Duration(seconds: 46))) == null);
  print('auth policy tests passed');
}
