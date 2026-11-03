import 'dart:io';

import '../lib/file_sender.dart';

Future<void> main() async {
  final dir = await Directory.systemTemp.createTemp('remote-file-test-');
  try {
    final source = File('${dir.path}/source.txt');
    await source.writeAsString('abc');
    final ops = <String>[];
    final sent = <Map<String, dynamic>>[];
    late FileSenderProtocol sender;
    sender = FileSenderProtocol(
      (m) {
        ops.add(m['op'] as String);
        switch (m['op']) {
          case 'hash_begin':
            return {'handle': 'h'};
          case 'sha256':
          case 'hash_finish':
            return {'sha256': 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='};
          default:
            return {};
        }
      },
      (message) async {
        sent.add(message);
        final offset = message['t'] == 'offer'
            ? 0
            : message['t'] == 'chunk'
            ? 3
            : 4;
        sender.acknowledge(message['id'] as String, offset, true);
      },
    );
    await sender.transfer(source.path);
    assert(sent.map((e) => e['t']).join(',') == 'offer,chunk,finish');
    assert(ops.join(',') == 'hash_begin,hash_update,sha256,hash_finish');
    assert(!sent.any((m) => m.containsKey('directory')));
    final cancelledOps = <String>[];
    late FileSenderProtocol cancelled;
    cancelled = FileSenderProtocol(
      (m) {
        cancelledOps.add(m['op'] as String);
        return m['op'] == 'hash_begin' ? {'handle': 'cancelled'} : {};
      },
      (message) async {
        cancelled.cancel();
      },
    );
    try {
      await cancelled.transfer(source.path);
      assert(false, 'Cancellation must fail');
    } on StateError {}
    assert(cancelledOps.join(',') == 'hash_begin,hash_cancel');
    await source.delete();
    print('file sender checks passed');
  } finally {
    await dir.delete();
  }
}
