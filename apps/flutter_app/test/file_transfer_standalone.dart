import '../lib/file_transfer.dart';

void main() {
  final calls = <Map<String, dynamic>>[];
  final receiver = FileReceiverProtocol('owner-session', (m) {
    calls.add(m);
    return {};
  });
  receiver.begin(
    id: 't1',
    directory: '/owner/selected',
    filename: 'safe.txt',
    length: 3,
  );
  assert(calls.first['directory'] == '/owner/selected');
  try {
    receiver.chunk(
      id: 't1',
      at: 1,
      data: 'YWJj',
      sha256: 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=',
    );
    throw StateError('out-of-order accepted');
  } on StateError catch (e) {
    assert(e.message != 'out-of-order accepted');
  }
  assert(
    receiver.chunk(
          id: 't1',
          at: 0,
          data: 'YWJj',
          sha256: 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=',
        ) ==
        3,
  );
  receiver.finish(
    id: 't1',
    sha256: 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=',
  );
  assert(calls.every((m) => m['session_id'] == 'owner-session'));
  assert(receiver.transferId == null);
  try {
    receiver.begin(id: 'bad/id', directory: '/local', filename: 'x', length: 1);
    assert(false, 'invalid transfer ID must be rejected');
  } on StateError {}
  try {
    receiver.begin(
      id: 'big',
      directory: '/local',
      filename: 'x',
      length: 1073741825,
    );
    assert(false, 'oversized transfer must be rejected');
  } on StateError {}
  print('file protocol tests passed');
}
