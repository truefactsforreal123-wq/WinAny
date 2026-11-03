import 'dart:convert';

/// Target-side transfer state. All native requests are assembled here, never
/// forwarded from peer JSON. The directory and filename come from local UI.
class FileReceiverProtocol {
  FileReceiverProtocol(this.session, this.core);
  final String session;
  final Map<String, dynamic> Function(Map<String, dynamic>) core;
  String? transferId;
  int size = 0;
  int offset = 0;
  void begin({
    required String id,
    required String directory,
    required String filename,
    required int length,
  }) {
    if (transferId != null ||
        !RegExp(r'^[a-zA-Z0-9_-]{1,100}$').hasMatch(id) ||
        length < 0 ||
        length > 1073741824 ||
        directory.isEmpty ||
        filename.isEmpty)
      throw StateError('Invalid file offer');
    core({
      'op': 'file_begin',
      'session_id': session,
      'transfer_id': id,
      'directory': directory,
      'filename': filename,
      'size': length,
    });
    transferId = id;
    size = length;
    offset = 0;
  }

  int chunk({
    required String id,
    required int at,
    required String data,
    required String sha256,
  }) {
    if (id != transferId ||
        at != offset ||
        data.length > 21848 ||
        sha256.length != 44)
      throw StateError('Invalid file chunk');
    final bytes = base64Decode(data);
    if (bytes.isEmpty ||
        bytes.length > 16384 ||
        offset + bytes.length > size ||
        base64Decode(sha256).length != 32)
      throw StateError('Invalid file chunk bounds');
    core({
      'op': 'file_chunk',
      'session_id': session,
      'transfer_id': id,
      'offset': at,
      'data': data,
      'sha256': sha256,
    });
    offset += bytes.length;
    return offset;
  }

  void finish({required String id, required String sha256}) {
    if (id != transferId ||
        offset != size ||
        sha256.length != 44 ||
        base64Decode(sha256).length != 32)
      throw StateError('Invalid file completion');
    core({
      'op': 'file_finish',
      'session_id': session,
      'transfer_id': id,
      'sha256': sha256,
    });
    transferId = null;
  }
}
