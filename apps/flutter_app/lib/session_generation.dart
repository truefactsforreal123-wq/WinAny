/// Invalidates in-flight asynchronous work when its owning session ends.
class SessionGeneration {
  int _value = 0;
  int get current => _value;
  bool isCurrent(int generation) => generation == _value;
  void invalidate() => _value++;
}
