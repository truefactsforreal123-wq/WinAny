import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:remote_transport/remote_transport.dart';

import 'native_core.dart';
import 'device_identity.dart';
import 'session_owner.dart';
import 'upnp.dart';

/// Implemented by Signaling. begin must atomically reserve its single-session
/// slot, authorize target access locally, and start WebRTC with no ICE servers.
abstract class DirectBridge {
  Future<void> begin({
    required bool target,
    required AccessRequest? access,
    required Future<void> Function(String, Map<String, dynamic>) sendSignal,
  });
  Future<void> signal(String kind, Map<String, dynamic> data);
  Future<void> end();
}

class DirectConnection extends ChangeNotifier {
  DirectConnection(
    this.bridge, {
    NativeCore? core,
    FlutterSecureStorage? storage,
  })  : _core = core ?? NativeCore(),
        _storage = storage ?? const FlutterSecureStorage();
  final DirectBridge bridge;
  final NativeCore _core;
  final FlutterSecureStorage _storage;
  DirectListener? _listener;
  DirectSession? _session;
  bool _busy = false;
  int _generation = 0;
  String status = 'Direct mode off';
  String? error;
  UpnpMapping? _upnp;
  String? get externalAddress => _upnp?.external;
  bool get listening => _listener != null;
  bool get busy => _busy;
  bool get active => _session != null;

  Future<Identity> _identity() async {
    final identity = await DeviceIdentity.loadOrCreate(_core, _storage);
    final privateKey = identity.privateKey;
    final publicKey = identity.publicKey;
    return Identity(
      base64Decode(publicKey),
      (data) async => base64Decode(
        _core.call({
          'op': 'identity_sign',
          'private_key_pkcs8': privateKey,
          'message': base64Encode(data),
        })['signature'] as String,
      ),
      (key, data, sig) async =>
          _core.call({
            'op': 'identity_verify',
            'public_key': base64Encode(key),
            'message': base64Encode(data),
            'signature': base64Encode(sig),
          })['valid'] ==
          true,
      (data) async => base64Decode(
        _core.call({'op': 'sha256', 'data': base64Encode(data)})['sha256']
            as String,
      ),
    );
  }

  String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  String _pinKey(InternetAddress address, int port) =>
      'direct.pin.${address.address}:$port';

  Future<void> listen({
    required InternetAddress address,
    required int port,
    required String certificatePemPath,
    required String privateKeyPemPath,
    required String certificateDerPath,
    required AcceptSession accept,
    bool upnp = false,
  }) async {
    if (_busy || listening || active)
      throw StateError('Direct connection is busy');
    _busy = true;
    final generation = _generation;
    notifyListeners();
    try {
      final id = await _identity();
      final der = await File(certificateDerPath).readAsBytes();
      if (der.isEmpty || der.length > 262144)
        throw StateError('Invalid DER certificate size');
      final fingerprint = _hex(await id.sha256(der));
      final context = SecurityContext()
        ..useCertificateChain(certificatePemPath)
        ..usePrivateKey(privateKeyPemPath);
      late final DirectListener listener;
      listener = await DirectListener.start(
        enabled: true,
        address: address,
        port: port,
        context: context,
        certificateFingerprint: fingerprint,
        identity: id,
        accept: accept,
        onSession: (session) {
          if (_listener != listener) {
            session.close();
            return;
          }
          unawaited(
            _adopt(
              session,
              target: true,
              generation: _generation,
            ).catchError((Object _) {}),
          );
        },
      );
      if (generation != _generation) {
        await listener.close();
        return;
      }
      _listener = listener;
      status = 'Listening on ${address.address}:${listener.port}';
      error = null;
      if (upnp) {
        try {
          _upnp = await UpnpMapping.map(listener.port);
          if (_upnp == null) error = 'UPnP: no gateway found';
        } catch (e) {
          error = 'UPnP failed: $e';
        }
      }
    } catch (e) {
      error = 'Direct listener failed: $e';
      rethrow;
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  Future<void> connect({
    required InternetAddress address,
    required int port,
    required ApproveCertificate approveCertificate,
    required ConfirmPeer confirmPeer,
  }) async {
    if (_busy || listening || active)
      throw StateError('Direct connection is busy');
    _busy = true;
    final generation = _generation;
    notifyListeners();
    DirectSession? session;
    try {
      final identity = await _identity();
      final key = _pinKey(address, port);
      final stored = await _storage.read(key: key);
      final pins =
          stored == null ? null : jsonDecode(stored) as Map<String, dynamic>;
      if (pins != null && (pins['cert'] is! String || pins['key'] is! String))
        throw StateError('Invalid stored pin');
      String? certFingerprint, keyFingerprint;
      session = await connectDirect(
        address: address,
        port: port,
        identity: identity,
        pinnedCertificate: pins?['cert'] as String?,
        pinnedKey: pins?['key'] as String?,
        enableFirstUse: pins == null,
        approveCertificate: approveCertificate,
        confirmPeer: (cert, peerKey, code) async {
          final accepted = await confirmPeer(cert, peerKey, code);
          if (accepted) {
            certFingerprint = cert;
            keyFingerprint = peerKey;
          }
          return accepted;
        },
      );
      if (generation != _generation) {
        session.close();
        return;
      }
      await _adopt(session, target: false, generation: generation);
      if (_session != session || generation != _generation) return;
      if (pins == null)
        await _storage.write(
          key: key,
          value: jsonEncode({'cert': certFingerprint!, 'key': keyFingerprint!}),
        );
    } catch (e) {
      session?.close();
      error = 'Direct connection failed: $e';
      rethrow;
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  Future<void> _adopt(
    DirectSession session, {
    required bool target,
    required int generation,
  }) async {
    if (generation != _generation || _session != null) {
      session.close();
      return;
    }
    _session = session;
    try {
      await bridge.begin(
        target: target,
        access: session.access,
        sendSignal: sendSignal,
      );
      if (generation != _generation || _session != session) return;
      status = 'Direct session active';
      error = null;
      notifyListeners();
      unawaited(_receive(session, generation));
    } catch (e) {
      if (ownsSession(_generation, generation, _session, session)) {
        error = 'Direct session setup failed: $e';
        await end();
      } else {
        session.close();
      }
      rethrow;
    }
  }

  Future<void> _receive(DirectSession session, int generation) async {
    try {
      while (generation == _generation && _session == session) {
        final message = await session.receive();
        if (!ownsSession(_generation, generation, _session, session)) return;
        final kind = message['kind'];
        final data = message['data'];
        if (message['type'] != 'signal' ||
            kind is! String ||
            data is! Map<String, dynamic> ||
            !_validSignal(kind, data))
          throw const FormatException('Invalid direct signal');
        await bridge.signal(kind, data);
      }
    } catch (_) {
      if (generation == _generation && _session == session) await end();
    }
  }

  Future<void> sendSignal(String kind, Map<String, dynamic> data) async {
    final session = _session;
    if (session == null || !_validSignal(kind, data))
      throw StateError('Invalid or unavailable direct signal');
    await session.send({'type': 'signal', 'kind': kind, 'data': data});
  }

  bool _validSignal(String kind, Map<String, dynamic> data) {
    if (kind == 'ice') {
      final candidate = data['candidate'];
      return candidate is String &&
          candidate.length <= 4096 &&
          RegExp(
            r'^candidate:\S+\s+\d+\s+(udp|tcp)\s+\d+\s+\S+\s+\d+\s+typ\s+(host|srflx|prflx)\b',
            caseSensitive: false,
          ).hasMatch(candidate) &&
          (data['sdpMid'] == null || data['sdpMid'] is String) &&
          (data['sdpMLineIndex'] == null || data['sdpMLineIndex'] is int);
    }
    if (kind == 'offer' || kind == 'answer') {
      final sdp = data['sdp'];
      return data['type'] == kind &&
          sdp is String &&
          sdp.length <= 60000 &&
          !RegExp(r'(?im)^a=candidate:.*\btyp\s+relay\b').hasMatch(sdp);
    }
    return false;
  }

  Future<void> end() async {
    _generation++;
    final session = _session;
    _session = null;
    session?.close();
    if (session != null) await bridge.end();
    status = listening ? 'Listening on ${_listener!.port}' : 'Direct mode off';
    notifyListeners();
  }

  Future<void> stop() async {
    await end();
    final listener = _listener;
    _listener = null;
    await listener?.close();
    final mapping = _upnp;
    _upnp = null;
    try {
      await mapping?.remove();
    } catch (_) {}
    status = 'Direct mode off';
    notifyListeners();
  }
}
