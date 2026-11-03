import 'dart:io';

import '../lib/tv_bridge.dart';
import 'util.dart';

Future<void> main() async {
  final calls = <List<String>>[];
  Future<ProcessResult> fake(String exe, List<String> a) async {
    if (exe != 'adb') throw StateError('bad exe');
    calls.add(a);
    return ProcessResult(
      0,
      0,
      a.contains('get-state') ? 'device' : 'connected to 10.0.0.5:5555',
      '',
    );
  }

  Future<bool> yes(String _, String? __) async => true;
  final t = AdbAdapter('10.0.0.5', yes, runner: fake);
  await t.pair();
  check(calls[0], '[connect, 10.0.0.5:5555]');
  check(calls[1], '[-s, 10.0.0.5:5555, get-state]');
  calls.clear();
  await t.sendKey('DPAD_UP');
  check(
    calls[0],
    '[-s, 10.0.0.5:5555, shell, input, keyevent, KEYCODE_DPAD_UP]',
  );
  calls.clear();
  await t.sendText('a b@c.d');
  check(calls[0], '[-s, 10.0.0.5:5555, shell, input, text, a%sb@c.d]');
  calls.clear();
  await t.launchApp('com.netflix.ninja');
  check(
    calls[0],
    '[-s, 10.0.0.5:5555, shell, monkey, -p, com.netflix.ninja, 1]',
  );
  await fail(() => t.sendKey('X'));
  for (final s in [r'a;b', r'$(id)', 'a`b`', 'a|b', 'a&b', "a'b", 'a\nb', '']) {
    await fail(() => t.sendText(s));
  }
  await fail(() => t.launchApp('a;b'));
  await fail(() => t.installApk('-s'));
  await fail(() async => AdbAdapter('8.8.8.8', yes));
  await fail(
    () => AdbAdapter(
      '10.0.0.5',
      (_, __) async => false,
      runner: fake,
    ).sendKey('HOME'),
  );
  final missing = AdbAdapter(
    '10.0.0.5',
    yes,
    runner: (e, a) async => throw ProcessException(e, a),
  );
  try {
    await missing.pair();
    throw 'no error';
  } on StateError catch (e) {
    check(e.message.contains('platform-tools'), true);
  }
  print('adb ok');
}
