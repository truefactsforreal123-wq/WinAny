import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'native_core.dart';

class DeviceIdentity {
  const DeviceIdentity(this.privateKey, this.publicKey);
  final String privateKey;
  final String publicKey;
  static Future<DeviceIdentity>? _pending;

  /// Both cloud and direct callers must use this helper to serialize creation.
  /// One JSON record avoids exposing a half-written new identity.
  static Future<DeviceIdentity> loadOrCreate(
    NativeCore core,
    FlutterSecureStorage storage,
  ) {
    final existing = _pending;
    if (existing != null) return existing;
    final operation = _load(core, storage);
    _pending = operation;
    operation.then<void>(
      (_) {
        if (identical(_pending, operation)) _pending = null;
      },
      onError: (Object _, StackTrace __) {
        if (identical(_pending, operation)) _pending = null;
      },
    );
    return operation;
  }

  static Future<DeviceIdentity> _load(
    NativeCore core,
    FlutterSecureStorage storage,
  ) async {
    final stored = await storage.read(key: 'identity.v1');
    if (stored != null) {
      final value = jsonDecode(stored);
      if (value is! Map<String, dynamic> ||
          value['private'] is! String ||
          value['public'] is! String)
        throw StateError('Stored identity is invalid; recovery required');
      return _validate(value['private'] as String, value['public'] as String);
    }
    var privateKey = await storage.read(key: 'identity.private');
    var publicKey = await storage.read(key: 'identity.public');
    if ((privateKey == null) != (publicKey == null))
      throw StateError('Stored identity is incomplete; recovery required');
    if (privateKey == null) {
      final generated = core.call({'op': 'identity_generate'});
      privateKey = generated['private_key_pkcs8'] as String;
      publicKey = generated['public_key'] as String;
    }
    final identity = _validate(privateKey, publicKey!);
    await storage.write(
      key: 'identity.v1',
      value: jsonEncode({
        'private': identity.privateKey,
        'public': identity.publicKey,
      }),
    );
    return identity;
  }

  static DeviceIdentity _validate(String privateKey, String publicKey) {
    try {
      if (base64Decode(privateKey).isEmpty ||
          base64Decode(publicKey).length != 32)
        throw const FormatException();
    } catch (_) {
      throw StateError('Stored identity is invalid; recovery required');
    }
    return DeviceIdentity(privateKey, publicKey);
  }
}
