import 'dart:async';

import '../lib/session_owner.dart';

Future<void> main() async {
  final old = Object(), next = Object();
  var active = old;
  var generation = 0;
  final delayedSetup = Completer<void>();
  final started = generation;
  var newerEnded = false;
  final continuation = delayedSetup.future.catchError((Object _) {
    if (ownsSession(generation, started, active, old)) newerEnded = true;
  });
  generation++;
  active = next;
  delayedSetup.completeError(StateError('Old setup failed after Stop'));
  await continuation;
  assert(!newerEnded);
  assert(!ownsSession(generation, started, active, old));
  assert(ownsSession(generation, generation, active, next));
  assert(!ownsSession(generation, generation, null, next));
  print(
    'Session ownership checks passed: stale cleanup cannot end a newer session.',
  );
}
