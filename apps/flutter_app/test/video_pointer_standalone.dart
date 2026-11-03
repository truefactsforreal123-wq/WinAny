import '../lib/video_pointer.dart';

void main() {
  assert(mapVideoPointer(5, 50, 200, 100, 100, 100) == null);
  final p = mapVideoPointer(100, 50, 200, 100, 100, 100)!;
  assert(p.x == .5 && p.y == .5);
  assert(mapVideoPointer(0, 0, 0, 100, 100, 100) == null);
  print('letterbox pointer tests passed');
}
