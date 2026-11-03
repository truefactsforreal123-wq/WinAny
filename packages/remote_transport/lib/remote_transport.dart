import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

typedef Digest = Future<List<int>> Function(List<int> data);
typedef Sign = Future<List<int>> Function(List<int> data);
typedef Verify = Future<bool> Function(
  List<int> key,
  List<int> data,
  List<int> signature,
);
typedef ApproveCertificate = Future<bool> Function(
  String certificateFingerprint,
);
typedef ConfirmPeer = Future<bool> Function(
  String certificateFingerprint,
  String keyFingerprint,
  String comparisonCode,
);
typedef AcceptSession = Future<AccessRequest?> Function(
  String peerKeyFingerprint,
  String comparisonCode,
);

class Identity {
  Identity(this.publicKey, this.sign, this.verify, this.sha256) {
    if (publicKey.length != 32)
      throw ArgumentError('Ed25519 public key must be 32 bytes');
  }
  final List<int> publicKey;
  final Sign sign;
  final Verify verify;
  final Digest sha256;
}

class AccessRequest {
  AccessRequest(
    this.preset, {
    this.permissions = const {},
    this.elevatedConfirmed = false,
  }) {
    if (!{'basic', 'normal', 'full', 'custom'}.contains(preset))
      throw ArgumentError('invalid preset');
    if (preset != 'custom' && permissions.isNotEmpty)
      throw ArgumentError('permissions only for custom');
  }
  final String preset;
  final Map<String, bool> permissions;

  /// This value must be supplied by trusted local UI, never the remote peer.
  final bool elevatedConfirmed;
}

String _b(List<int> data) => base64Encode(data);
List<int> _decode(Object? value, int length) {
  if (value is! String || value.length > 512)
    throw const FormatException('invalid binary');
  final bytes = base64Decode(value);
  if (bytes.length != length)
    throw const FormatException('invalid binary length');
  return bytes;
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
List<int> _random() {
  final r = Random.secure();
  return List.generate(32, (_) => r.nextInt(256));
}

Future<List<int>> _hash(Identity id, List<int> data) async {
  final digest = await id.sha256(data);
  if (digest.length != 32) throw StateError('invalid SHA-256 result');
  return digest;
}

List<int> _proof(
  String role,
  String cert,
  String serverKey,
  String clientKey,
  String serverNonce,
  String clientNonce,
) => utf8.encode(
  jsonEncode([
    'remote-direct-v1',
    role,
    cert,
    serverKey,
    clientKey,
    serverNonce,
    clientNonce,
  ]),
);

/// A length-prefixed JSON stream. Only SDP/ICE objects should be passed by callers.
class DirectSession {
  DirectSession._(
    this._wire,
    this.peerKeyFingerprint,
    this.comparisonCode,
    this.access,
  );
  final _Wire _wire;
  final String peerKeyFingerprint;
  final String comparisonCode;
  final AccessRequest? access;
  Future<void> send(Map<String, Object?> message) => _wire.send(message);
  Future<Map<String, dynamic>> receive() => _wire.read();
  void close() => _wire.close();
  Future<void> get done => _wire.done;
}

class _Wire {
  _Wire(this.socket) : _iterator = StreamIterator(socket);
  final SecureSocket socket;
  final StreamIterator<List<int>> _iterator;
  final List<int> _buffer = [];
  final Completer<void> _closed = Completer<void>();
  bool _reading = false;
  int _frames = 0;
  DateTime _window = DateTime.now();
  Future<void> get done => _closed.future;
  Future<void> send(Map<String, Object?> value) async {
    final data = utf8.encode(jsonEncode(value));
    if (data.isEmpty || data.length > 65536)
      throw const FormatException('frame too large');
    final header = ByteData(4)..setUint32(0, data.length);
    socket.add(header.buffer.asUint8List());
    socket.add(data);
    await socket.flush().timeout(const Duration(seconds: 10));
  }

  Future<Map<String, dynamic>> read({
    Duration timeout = const Duration(seconds: 30),
  }) async {
    if (_reading) throw StateError('concurrent reads');
    _reading = true;
    try {
      final now = DateTime.now();
      if (now.difference(_window) >= const Duration(seconds: 1)) {
        _window = now;
        _frames = 0;
      }
      if (++_frames > 30) throw const FormatException('frame rate exceeded');
      Future<void> fill(int n) async {
        while (_buffer.length < n) {
          if (!await _iterator.moveNext().timeout(timeout))
            throw const SocketException('peer closed');
          final chunk = _iterator.current;
          if (_buffer.length + chunk.length > 131076)
            throw const FormatException('buffer exceeded');
          _buffer.addAll(chunk);
        }
      }

      await fill(4);
      final size = ByteData.sublistView(
        Uint8List.fromList(_buffer.sublist(0, 4)),
      ).getUint32(0);
      if (size == 0 || size > 65536)
        throw const FormatException('invalid frame size');
      await fill(4 + size);
      final value = jsonDecode(utf8.decode(_buffer.sublist(4, 4 + size)));
      _buffer.removeRange(0, 4 + size);
      if (value is! Map<String, dynamic>)
        throw const FormatException('expected object');
      return value;
    } catch (_) {
      close();
      rethrow;
    } finally {
      _reading = false;
    }
  }

  void close() {
    socket.destroy();
    _iterator.cancel();
    if (!_closed.isCompleted) _closed.complete();
  }
}

/// Connect only to an owner-selected numeric address. Pin storage is local and trusted.
Future<DirectSession> connectDirect({
  required InternetAddress address,
  required int port,
  required Identity identity,
  String? pinnedCertificate,
  String? pinnedKey,
  bool enableFirstUse = false,
  required ApproveCertificate approveCertificate,
  required ConfirmPeer confirmPeer,
}) async {
  if ((pinnedCertificate == null) != (pinnedKey == null))
    throw ArgumentError('both pins required');
  if (pinnedKey == null && !enableFirstUse)
    throw StateError('first use disabled');
  final socket = await SecureSocket.connect(
    address,
    port,
    timeout: const Duration(seconds: 10),
    onBadCertificate: (_) => enableFirstUse || pinnedCertificate != null,
  );
  final wire = _Wire(socket);
  try {
    final cert = socket.peerCertificate;
    if (cert == null) throw StateError('missing certificate');
    final certHash = _hex(await _hash(identity, cert.der));
    if (pinnedCertificate != null && pinnedCertificate != certHash)
      throw StateError('certificate pin mismatch');
    if (!await approveCertificate(certHash)
        .timeout(const Duration(seconds: 60)))
      throw StateError('certificate not approved');
    final hello = await wire.read().timeout(const Duration(seconds: 30));
    if (hello['type'] != 'hello') throw const FormatException('expected hello');
    final serverKey = _decode(hello['key'], 32);
    final serverNonce = _decode(hello['nonce'], 32);
    final keyHash = _hex(await _hash(identity, serverKey));
    if (pinnedKey != null && pinnedKey != keyHash)
      throw StateError('key pin mismatch');
    final clientNonce = _random();
    final transcript = _proof(
      'server',
      certHash,
      _b(serverKey),
      _b(identity.publicKey),
      _b(serverNonce),
      _b(clientNonce),
    );
    final code = _hex(await _hash(identity, transcript)).substring(0, 12);
    await wire.send({
      'type': 'challenge',
      'key': _b(identity.publicKey),
      'nonce': _b(clientNonce),
    });
    final proof = await wire.read();
    if (proof['type'] != 'proof' ||
        !await identity.verify(
          serverKey,
          transcript,
          _decode(proof['signature'], 64),
        ))
      throw StateError('server proof failed');
    final clientProof = _proof(
      'client',
      certHash,
      _b(serverKey),
      _b(identity.publicKey),
      _b(serverNonce),
      _b(clientNonce),
    );
    await wire.send({
      'type': 'proof',
      'signature': _b(await identity.sign(clientProof)),
    });
    if (!await confirmPeer(
      certHash,
      keyHash,
      code,
    ).timeout(const Duration(seconds: 60)))
      throw StateError('peer not confirmed');
    await wire.send({'type': 'confirmed'});
    final accepted = await wire.read(timeout: const Duration(seconds: 90));
    if (accepted['type'] != 'accepted') throw StateError('session rejected');
    final preset = accepted['preset'];
    final rawPermissions = accepted['permissions'];
    const allowed = {
      'view',
      'input',
      'clipboard_text',
      'clipboard_images',
      'clipboard_files',
      'file_transfer',
      'audio',
      'lock',
      'power',
      'elevated',
      'tv_keys',
      'tv_apps',
      'adb',
    };
    if (preset is! String ||
        !{'basic', 'normal', 'full', 'custom'}.contains(preset) ||
        rawPermissions is! Map<String, dynamic> ||
        rawPermissions.keys.any((key) => !allowed.contains(key)) ||
        rawPermissions.values.any((value) => value is! bool) ||
        (preset != 'custom' && rawPermissions.isNotEmpty))
      throw const FormatException('invalid access metadata');
    final access = AccessRequest(
      preset,
      permissions: rawPermissions.cast<String, bool>(),
    );
    return DirectSession._(wire, keyHash, code, access);
  } catch (_) {
    wire.close();
    rethrow;
  }
}

/// Explicitly started listener. The certificate fingerprint must be SHA-256 of
/// the DER certificate configured in [context], calculated by trusted code.
class DirectListener {
  DirectListener._(
    this._server,
    this._identity,
    this._certificateFingerprint,
    this._accept,
    this._onSession,
  ) {
    _subscription = _server.listen(_incoming, onError: (_) {});
  }
  final SecureServerSocket _server;
  final Identity _identity;
  final String _certificateFingerprint;
  final AcceptSession _accept;
  final void Function(DirectSession) _onSession;
  late final StreamSubscription<SecureSocket> _subscription;
  final Map<String, List<DateTime>> _failures = {};
  bool _busy = false;
  bool _closed = false;
  _Wire? _current;
  int get port => _server.port;

  static Future<DirectListener> start({
    required bool enabled,
    required InternetAddress address,
    required int port,
    required SecurityContext context,
    required String certificateFingerprint,
    required Identity identity,
    required AcceptSession accept,
    required void Function(DirectSession) onSession,
  }) async {
    if (!enabled) throw StateError('direct mode disabled');
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(certificateFingerprint))
      throw ArgumentError('invalid certificate fingerprint');
    final server = await SecureServerSocket.bind(
      address,
      port,
      context,
      backlog: 16,
    );
    return DirectListener._(
      server,
      identity,
      certificateFingerprint,
      accept,
      onSession,
    );
  }

  void _incoming(SecureSocket socket) {
    final address = socket.remoteAddress.address;
    final now = DateTime.now();
    _failures.removeWhere((_, times) {
      times.removeWhere((t) => now.difference(t) > const Duration(minutes: 5));
      return times.isEmpty;
    });
    if (_closed ||
        _busy ||
        (_failures[address]?.length ?? 0) >= 5 ||
        _failures.length >= 1024) {
      socket.destroy();
      return;
    }
    _busy = true;
    final wire = _Wire(socket);
    _current = wire;
    () async {
      try {
        final serverNonce = _random();
        await wire.send({
          'type': 'hello',
          'key': _b(_identity.publicKey),
          'nonce': _b(serverNonce),
        });
        final challenge = await wire.read(timeout: const Duration(seconds: 90));
        if (challenge['type'] != 'challenge')
          throw const FormatException('expected challenge');
        final clientKey = _decode(challenge['key'], 32);
        final clientNonce = _decode(challenge['nonce'], 32);
        final transcript = _proof(
          'server',
          _certificateFingerprint,
          _b(_identity.publicKey),
          _b(clientKey),
          _b(serverNonce),
          _b(clientNonce),
        );
        final code = _hex(await _hash(_identity, transcript)).substring(0, 12);
        await wire.send({
          'type': 'proof',
          'signature': _b(await _identity.sign(transcript)),
        });
        final proof = await wire.read();
        final clientProof = _proof(
          'client',
          _certificateFingerprint,
          _b(_identity.publicKey),
          _b(clientKey),
          _b(serverNonce),
          _b(clientNonce),
        );
        if (proof['type'] != 'proof' ||
            !await _identity.verify(
              clientKey,
              clientProof,
              _decode(proof['signature'], 64),
            ))
          throw StateError('client proof failed');
        final keyHash = _hex(await _hash(_identity, clientKey));
        final access = await _accept(
          keyHash,
          code,
        ).timeout(const Duration(seconds: 60));
        if (access == null ||
            ((access.preset == 'full' ||
                    (access.preset == 'custom' &&
                        access.permissions.values.any((v) => v))) &&
                !access.elevatedConfirmed))
          throw StateError('session rejected');
        if (_closed) throw StateError('listener closed');
        final confirmation = await wire.read(
          timeout: const Duration(seconds: 90),
        );
        if (confirmation['type'] != 'confirmed')
          throw StateError('peer not confirmed');
        await wire.send({
          'type': 'accepted',
          'preset': access.preset,
          'permissions': access.permissions,
        });
        final session = DirectSession._(wire, keyHash, code, access);
        _onSession(session);
        await wire.done;
      } catch (_) {
        if (!_closed) (_failures[address] ??= []).add(DateTime.now());
        wire.close();
      } finally {
        _current = null;
        _busy = false;
      }
    }();
  }

  Future<void> close() async {
    _closed = true;
    _current?.close();
    await _subscription.cancel();
    await _server.close();
  }
}
