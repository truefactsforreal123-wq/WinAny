import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

/// Local-only sender. Exactly one bounded chunk is in flight at any time.
class FileSenderProtocol {
  FileSenderProtocol(this.core, this.send);
  final Map<String, dynamic> Function(Map<String, dynamic>) core;
  final Future<void> Function(Map<String, dynamic>) send;
  Completer<void>? _ack;
  String? _expectedId;
  int? _expectedOffset;
  bool _cancelled = false;
  void acknowledge(String id, int offset, bool accepted) {
    final pending = _ack;
    if (pending == null ||
        pending.isCompleted ||
        id != _expectedId ||
        offset != _expectedOffset)
      return;
    if (accepted) {
      pending.complete();
    } else {
      pending.completeError(StateError('File transfer declined'));
    }
  }

  void cancel() {
    _cancelled = true;
    final pending = _ack;
    if (pending != null && !pending.isCompleted)
      pending.completeError(StateError('File transfer cancelled'));
  }

  Future<void> _step(
    Map<String, dynamic> message,
    String id,
    int offset,
  ) async {
    if (_cancelled) throw StateError('File transfer cancelled');
    _expectedId = id;
    _expectedOffset = offset;
    final pending = Completer<void>();
    _ack = pending;
    try {
      await Future.wait([
        send(message),
        pending.future.timeout(const Duration(seconds: 60)),
      ]);
    } finally {
      if (identical(_ack, pending)) _ack = null;
    }
  }

  Future<void> transfer(String path) async {
    final file = File(path);
    final size = await file.length();
    if (size > 1073741824) throw StateError('File exceeds 1 GiB');
    final name = file.uri.pathSegments.where((s) => s.isNotEmpty).last;
    if (name.isEmpty || name.length > 255) throw StateError('Invalid filename');
    final id = List.generate(
      16,
      (_) => Random.secure().nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    String? handle;
    RandomAccessFile? stream;
    try {
      handle = core({'op': 'hash_begin'})['handle'] as String;
      await _step({'t': 'offer', 'id': id, 'name': name, 'size': size}, id, 0);
      stream = await file.open();
      var offset = 0;
      while (offset < size) {
        if (_cancelled) throw StateError('File transfer cancelled');
        final data = await stream.read(min(16384, size - offset));
        if (data.isEmpty)
          throw StateError('Source file changed during transfer');
        final encoded = base64Encode(data);
        core({'op': 'hash_update', 'handle': handle, 'data': encoded});
        final hash =
            core({'op': 'sha256', 'data': encoded})['sha256'] as String;
        final next = offset + data.length;
        await _step(
          {
            't': 'chunk',
            'id': id,
            'offset': offset,
            'data': encoded,
            'sha256': hash,
          },
          id,
          next,
        );
        offset = next;
      }
      final hash =
          core({'op': 'hash_finish', 'handle': handle})['sha256'] as String;
      handle = null;
      await _step({'t': 'finish', 'id': id, 'sha256': hash}, id, size + 1);
    } finally {
      await stream?.close();
      if (handle != null) {
        try {
          core({'op': 'hash_cancel', 'handle': handle});
        } catch (_) {}
      }
    }
  }
}
