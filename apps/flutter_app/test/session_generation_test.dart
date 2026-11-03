import 'package:flutter_test/flutter_test.dart';
import 'package:remote_link/session_generation.dart';

void main() {
  test('revocation invalidates an in-flight session generation', () {
    final generations = SessionGeneration();
    final previous = generations.current;
    expect(generations.isCurrent(previous), isTrue);
    generations.invalidate();
    expect(generations.isCurrent(previous), isFalse);
    expect(generations.isCurrent(generations.current), isTrue);
  });
}
