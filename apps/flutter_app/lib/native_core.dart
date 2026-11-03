import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

typedef _CallNative = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _CallDart = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _FreeNative = Void Function(Pointer<Utf8>);
typedef _FreeDart = void Function(Pointer<Utf8>);

/// Only trusted, locally constructed requests may cross this boundary.
class NativeCore {
  NativeCore()
    : _library = Platform.isWindows
          ? DynamicLibrary.open('remote_core.dll')
          : Platform.isAndroid
          ? DynamicLibrary.open('libremote_core.so')
          : DynamicLibrary.open('libremote_core.so');
  final DynamicLibrary _library;

  /// For slow ops (OPAQUE/Argon2): runs a fresh binding off the UI isolate. The request must be JSON-like.
  static Future<Map<String, dynamic>> callOffUi(Map<String, dynamic> request) =>
      Isolate.run(() => NativeCore().call(request));
  Map<String, dynamic> call(Map<String, dynamic> request) {
    final call = _library.lookupFunction<_CallNative, _CallDart>(
      'remote_core_call',
    );
    final free = _library.lookupFunction<_FreeNative, _FreeDart>(
      'remote_core_free',
    );
    final input = jsonEncode(request).toNativeUtf8();
    Pointer<Utf8> output = nullptr;
    try {
      output = call(input);
      if (output == nullptr)
        throw StateError('Native core returned no response');
      final response =
          jsonDecode(output.toDartString()) as Map<String, dynamic>;
      if (response['ok'] != true) throw StateError('${response['error']}');
      return response['result'] as Map<String, dynamic>;
    } finally {
      calloc.free(input);
      if (output != nullptr) free(output);
    }
  }
}
