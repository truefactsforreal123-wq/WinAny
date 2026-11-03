import '../lib/capture_policy.dart';

void main() {
  var opens = 0;
  void requestCapture(void Function() check) {
    if (captureAuthorized(check)) opens++;
  }

  requestCapture(() => throw StateError('View disabled by owner'));
  assert(opens == 0);
  requestCapture(() => throw StateError('Native permission state unavailable'));
  assert(opens == 0);
  requestCapture(() {});
  assert(opens == 1);
  print('Capture permission checks passed: denial/error never open capture.');
}
