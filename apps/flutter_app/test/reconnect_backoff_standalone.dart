import '../lib/reconnect_backoff.dart';

void main() {
  final seconds = [
    for (var i = 0; i < 7; i++) reconnectDelay(i)!.inSeconds,
  ];
  assert(seconds.join(',') == '1,2,4,8,16,30,30');
  assert(reconnectDelay(reconnectMaxAttempts - 1) != null);
  assert(reconnectDelay(reconnectMaxAttempts) == null);
  var total = 0;
  for (var i = 0; i < reconnectMaxAttempts; i++) {
    total += reconnectDelay(i)!.inSeconds;
  }
  assert(total >= 240 && total <= 420);
  print('reconnect backoff tests passed');
}
