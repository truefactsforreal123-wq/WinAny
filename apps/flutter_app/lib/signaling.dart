import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:remote_transport/remote_transport.dart';

import 'direct_connection.dart';
import 'device_identity.dart';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'native_core.dart';
import 'capture_policy.dart';
import 'file_transfer.dart';
import 'file_sender.dart';
import 'session_generation.dart';
import 'reconnect_backoff.dart';
import 'session_protocol.dart';
import 'auth_policy.dart';

import 'package:flutter_webrtc/flutter_webrtc.dart';

String _url64(String standard) =>
    standard.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

class Signaling extends ChangeNotifier implements DirectBridge {
  Signaling() {
    if (Platform.isAndroid) {
      _android.setMethodCallHandler((call) async {
        if (call.method == 'sessionRevoked') end();
      });
    }
  }
  static const _android = MethodChannel('remote_link/android');
  Timer? _expiry;
  final _storage = const FlutterSecureStorage();
  NativeCore? _core;
  WebSocket? _socket;
  String status = 'Disconnected';
  String? deviceId, sessionId, incomingController, incomingSession;
  String? error;
  bool target = false;
  bool _requestPending = false;
  bool _cloudConnecting = false;
  bool _direct = false;
  Future<void> Function(String, Map<String, dynamic>)? _directSend;
  Future<void> Function()? onDirectEnded;
  bool _accepting = false;
  RTCPeerConnection? _pc;
  RTCDataChannel? _channel;
  RTCDataChannel? _files;
  RTCDataChannel? _tv;
  Future<Map<String, dynamic>> Function(
    String sessionId,
    Map<String, dynamic> request,
  )? tvHandler;
  final Map<int, Completer<Map<String, dynamic>>> _tvPending = {};
  final List<DateTime> _tvSent = [], _tvReceived = [];
  int _tvNextId = 0;
  int _tvInFlight = 0;
  int _tvLastReceivedId = 0;
  void Function()? onSessionEnded;
  FileReceiverProtocol? _fileReceiver;
  FileSenderProtocol? _fileSender;
  Map<String, dynamic>? fileOffer;
  String? fileStatus;
  MediaStream? _capture;
  RTCRtpSender? _videoSender;
  final renderer = RTCVideoRenderer();
  bool rendererReady = false;
  bool _remoteDescriptionSet = false;
  bool _peerReady = false;
  bool _startingPeer = false;
  bool _viewOnly = false;

  /// True when input is off for this session (target: accessibility off; controller: told by target).
  bool get viewOnly => _viewOnly;
  final _generation = SessionGeneration();
  final List<Map<String, dynamic>> _queuedSignals = [];
  final List<RTCIceCandidate> _pendingIce = [];
  String? _acceptedPreset;
  Map<String, bool> _directPermissions = {};
  String? _captureSource;
  String _quality = 'balanced';
  bool _desktopInputSafe = false;
  String? _endpoint; // set while the user wants to stay online
  Timer? _retry, _iceRetry;
  bool _reconnecting = false;
  int _attempt = 0, _iceAttempt = 0;
  // Trust, unattended access, resume and monitors.
  Map<String, TrustedDevice> _trusted = {};
  List<TrustedDevice> get trusted => _trusted.values.toList();
  String? _unattendedRecord; // OPAQUE server setup + registration record (not password-equivalent)
  String unattendedPreset = 'normal';
  bool get unattendedEnabled => _unattendedRecord != null;
  String? trustError, trustStatus, notice, unattendedNotice;
  String? unattendedSecret; // controller side: typed by the user; only OPAQUE messages derived from it are sent
  void Function()? onSecretUsed;
  void Function(String)? onAudit;
  bool _trustLoaded = false;
  DeviceIdentity? _identity;
  final List<String> _revokeQueue = []; // persisted; entries leave on the server's ack
  Lockouts _lockouts = Lockouts();
  ({String state, Map<String, String> fields})? _serverLogin; // target: waiting for KE3
  ({String state, String password, Map<String, String> fields})? _clientLogin; // controller: waiting for KE2
  String? _controllerId, _controllerKey; // target: signaling id and server-registered key of the controller
  bool _authPending = false; // target: black stream and basic grant until the controller authenticates
  ChallengeGate? _gate;
  bool _failCounted = false, _viaPassword = false, _relayOnly = false;
  AuthWindow _window = AuthWindow();
  PasswordBudget _budget = PasswordBudget();
  final PromptLimiter _prompts = PromptLimiter();
  ChallengeGate? _enrollGate; // target: owner asked to trust; waiting for the controller's signed proof
  String? _enrollPreset;
  Uint8List? _enrollChallenge; // controller: nonce the target wants signed once the user agrees
  Timer? _secretTimer;
  ControllerBinding? _binding; // controller: the one session this device requested
  String? _requestTarget;
  int _answers = 0;
  bool enrollRequested = false; // controller: target asks to trust this device
  String? _remoteFp; // peer DTLS fingerprint, pinned for the whole session
  Timer? _authTimer, _resumeTimer;
  String? _resumeSession; // our signaling socket dropped; resume after re-auth
  bool _peerDown = false;
  List<Monitor> monitors = [];
  int? display;
  MediaStreamTrack? _remoteAudio;
  bool muted = false;
  bool _switching = false;
  bool _captureServiceOn = false;
  int? _pendingDisplay, _targetDisplay; // target: queued switch; screen currently captured
  bool get hasAudio => _remoteAudio != null;
  bool get reconnecting =>
      _reconnecting || _iceRetry != null || _resumeSession != null || _peerDown;
  bool get canTrustController =>
      target &&
      !_direct &&
      !_authPending &&
      sessionId != null &&
      _channel != null &&
      _controllerId != null &&
      _controllerKey != null &&
      trustPresets.contains(_acceptedPreset) &&
      !_trusted.values.any((d) => d.controllerId == _controllerId);
  bool get connected => _socket != null && deviceId != null;
  bool get canSendFiles =>
      !target &&
      sessionId != null &&
      _files != null &&
      _permits('file_transfer') &&
      _fileSender == null;

  bool _permits(String capability) {
    if (_direct && _acceptedPreset == 'custom')
      return _directPermissions[capability] == true;
    if (capability == 'file_transfer') return _acceptedPreset == 'full';
    if (capability == 'input' || capability == 'clipboard_text')
      return _acceptedPreset == 'normal' || _acceptedPreset == 'full';
    return false;
  }

  @override
  Future<void> begin({
    required bool target,
    required AccessRequest? access,
    required Future<void> Function(String, Map<String, dynamic>) sendSignal,
  }) async {
    if (_direct ||
        _cloudConnecting ||
        _reconnecting ||
        _requestPending ||
        _accepting ||
        sessionId != null ||
        incomingSession != null)
      throw StateError('Another session or connection is pending');
    if (access == null)
      throw StateError('Direct session has no access metadata');
    final random = Random.secure();
    final id = List.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
    _direct = true;
    this.target = target;
    sessionId = id;
    _directSend = sendSignal;
    _acceptedPreset = access.preset;
    _directPermissions = Map.of(access.permissions);
    final generation = _generation.current;
    final previousSocket = _socket;
    _socket = null;
    deviceId = null;
    try {
      await previousSocket?.close();
      if (!_generation.isCurrent(generation) || sessionId != id)
        throw StateError('Session ended');
      _core ??= NativeCore();
      if (target) {
        final inputAllowed = _permits('input');
        if ((Platform.isWindows || Platform.isLinux) && inputAllowed) {
          final sources = await desktopCapturer.getSources(
            types: [SourceType.Screen],
          );
          if (!_generation.isCurrent(generation) || sessionId != id)
            throw StateError('Session ended');
          final display = _core!.call({'op': 'input_display'});
          if (display['desktop_input_safe'] != true || sources.length != 1)
            throw StateError('Direct input requires one safely mapped screen');
          _desktopInputSafe = true;
          _captureSource = sources.single.id;
        }
        _core!.call({
          'op': 'session_accept',
          'session_id': id,
          'accepted': true,
          'preset': access.preset,
          if (access.preset == 'custom') 'permissions': access.permissions,
          'elevated_confirmed': access.elevatedConfirmed,
        });
        if (Platform.isAndroid) {
          final granted = await _android.invokeMethod<bool>(
                'requestNotificationPermission',
              ) ??
              false;
          if (!granted || !_generation.isCurrent(generation) || sessionId != id)
            throw StateError('Session notification permission required');
          final ok = await _androidInputOrViewOnly(inputAllowed);
          await _android.invokeMethod('acceptSession', {
            'sessionId': id,
            'input': ok,
            'clipboardText': ok,
            'confirmed': true,
          });
          if (!_generation.isCurrent(generation) || sessionId != id) {
            await _android.invokeMethod('revokeSession');
            throw StateError('Session ended');
          }
        }
      }
      _expiry = Timer(const Duration(hours: 1), end);
      status = 'Negotiating direct connection';
      notifyListeners();
      await _startPeer([]);
      if (!_generation.isCurrent(generation) || sessionId != id || !_peerReady)
        throw StateError('Direct WebRTC setup failed');
    } catch (_) {
      if (_generation.isCurrent(generation) && sessionId == id) await end();
      rethrow;
    }
  }

  @override
  Future<void> signal(String kind, Map<String, dynamic> data) async {
    if (!_direct || sessionId == null || !_validDirectSignal(kind, data))
      throw StateError('Invalid direct signal');
    if ((kind == 'offer' && !target) || (kind == 'answer' && target))
      throw StateError('Unexpected direct signal role');
    await _handleSignal({'sessionId': sessionId, 'kind': kind, 'data': data});
  }

  /// Android: input needs the local accessibility service. If it is off, keep the session view-only.
  Future<bool> _androidInputOrViewOnly(bool input) async {
    if (!input || !Platform.isAndroid) return input;
    try {
      if (await _android.invokeMethod<bool>('isAccessibilityEnabled') == true)
        return true;
    } catch (_) {}
    _viewOnly = true;
    notice =
        'View only: turn on Remote Link in Accessibility settings to allow control.';
    onAudit?.call('Input not allowed: accessibility service is off (view only)');
    notifyListeners();
    return false; // the UI offers openAccessibilitySettings() on a button
  }

  Future<void> openAccessibilitySettings() async {
    if (!Platform.isAndroid) return;
    try {
      await _android.invokeMethod('openAccessibilitySettings', {
        'disclosureAccepted': true,
      });
    } catch (e) {
      error = 'Unable to open accessibility settings: $e';
      notifyListeners();
    }
  }

  /// Loads persisted trust and the unattended verifier into the core. Safe to call repeatedly.
  Future<void> loadTrust() async {
    if (_trustLoaded) return;
    try {
      _core ??= NativeCore();
      final policies = await _storage.read(key: 'trust.policies');
      if (policies != null) {
        try {
          _core!.call({'op': 'trust_import', 'json': policies});
        } catch (_) {
          // Old (v1) or corrupt trust data is rejected by the core: start empty.
          await _storage.delete(key: 'trust.policies');
          await _storage.delete(key: 'trust.devices');
          onAudit?.call('Stored trusted devices were invalid and were cleared');
        }
      }
      final listed = (_core!.call({'op': 'trust_list'})['devices'] as List)
          .map((d) => (d as Map)['device_id'])
          .toSet();
      _trusted = {
        for (final e in parseTrustedDevices(
          await _storage.read(key: 'trust.devices'),
        ).entries)
          if (listed.contains(e.key)) e.key: e.value,
      };
      if (await _storage.read(key: 'unattended.hash') != null) {
        // v2 PBKDF2 hashes are password-equivalent: drop them, never fall back to v2.
        await _storage.delete(key: 'unattended.hash');
        unattendedNotice = 'Set the unattended password again';
        onAudit?.call('Old unattended password removed; it must be set again');
      }
      _unattendedRecord = await _storage.read(key: 'unattended.record');
      if (_unattendedRecord != null) {
        final preset = await _storage.read(key: 'unattended.preset');
        if (preset == 'basic' || preset == 'normal') unattendedPreset = preset!;
      }
      _lockouts = Lockouts.fromJson(await _storage.read(key: 'unattended.lockout'));
      _budget = PasswordBudget.fromJson(await _storage.read(key: 'unattended.budget'));
      try {
        final queued = jsonDecode(await _storage.read(key: 'revoke.queue') ?? '[]');
        if (queued is List)
          _revokeQueue
            ..clear()
            ..addAll(queued.whereType<String>().where(validControllerId).take(1000));
      } catch (_) {}
      _trustLoaded = true;
      trustError = null;
    } catch (e) {
      trustError = 'Trust store unavailable: $e';
    }
    notifyListeners();
  }

  Future<void> _saveTrust() async {
    await _storage.write(
      key: 'trust.policies',
      value: _core!.call({'op': 'trust_export'})['json'] as String,
    );
    await _storage.write(
      key: 'trust.devices',
      value: jsonEncode(_trusted.values.map((d) => d.toJson()).toList()),
    );
  }

  Future<void> setUnattended(String password, String preset) async {
    await loadTrust();
    if (!_trustLoaded || (preset != 'basic' && preset != 'normal'))
      throw StateError(trustError ?? 'Invalid preset');
    // OPAQUE registration (Argon2) runs off the UI isolate.
    final record = (await NativeCore.callOffUi({
      'op': 'unattended_password_set',
      'password': password,
    }))['record'] as String;
    await _storage.write(key: 'unattended.record', value: record);
    await _storage.write(key: 'unattended.preset', value: preset);
    _unattendedRecord = record;
    _serverLogin = null; // a pending login belongs to the old record
    unattendedNotice = null;
    unattendedPreset = preset;
    onAudit?.call('Unattended access enabled ($preset)');
    notifyListeners();
  }

  Future<void> clearUnattended() async {
    await _storage.delete(key: 'unattended.record');
    await _storage.delete(key: 'unattended.preset');
    _unattendedRecord = null;
    _serverLogin = null;
    unattendedPreset = 'normal';
    onAudit?.call('Unattended access disabled');
    if (target && _viaPassword && sessionId != null) await end();
    notifyListeners();
  }

  Future<void> revokeTrusted(TrustedDevice device) async {
    _core!.call({'op': 'trust_revoke', 'device_id': device.deviceId});
    _trusted.remove(device.deviceId);
    await _saveTrust();
    if (!_revokeQueue.contains(device.controllerId))
      _revokeQueue.add(device.controllerId);
    await _saveRevokeQueue();
    _flushRevokes();
    onAudit?.call('Trusted device revoked: ${device.controllerId}');
    if (target && sessionId != null && _controllerId == device.controllerId)
      await end();
    notifyListeners();
  }

  void _dropSecret() {
    _secretTimer?.cancel();
    unattendedSecret = null;
    onSecretUsed?.call();
  }

  Future<void> _saveBudget() => _storage
      .write(key: 'unattended.budget', value: _budget.toJson())
      .catchError((Object _) {});

  Future<void> _saveRevokeQueue() =>
      _storage.write(key: 'revoke.queue', value: jsonEncode(_revokeQueue));

  void _flushRevokes() {
    if (!connected) return;
    for (final id in _revokeQueue) {
      _send({'type': 'revoke', 'controllerId': id});
    }
  }

  Future<void> connect(String endpoint) async {
    if (_socket != null || _cloudConnecting || _direct) {
      _reconnecting = false;
      return;
    }
    _cloudConnecting = true;
    try {
      final uri = Uri.parse(endpoint);
      if (uri.scheme != 'wss' || uri.host.isEmpty)
        throw const FormatException('A wss:// URL is required');
      _endpoint = endpoint;
      _core ??= NativeCore();
      await loadTrust();
      final identity = await DeviceIdentity.loadOrCreate(_core!, _storage);
      _identity = identity;
      final privateKey = identity.privateKey;
      final publicKey = identity.publicKey;
      final existingId = await _storage.read(key: 'identity.deviceId');
      status = 'Connecting';
      error = null;
      notifyListeners();
      final ws = await WebSocket.connect(endpoint);
      if (_endpoint != endpoint) {
        await ws.close(); // cancelled while connecting
        return;
      }
      _socket = ws;
      ws.listen(
        (raw) async {
          if (!identical(_socket, ws)) return;
          try {
            if (raw is! String)
              throw const FormatException(
                'Unexpected binary signaling message',
              );
            final m = jsonDecode(raw) as Map<String, dynamic>;
            switch (m['type']) {
              case 'challenge':
                final message = base64Encode(
                  utf8.encode('remote-signaling-v1:${m['nonce']}'),
                );
                final signed = _core!.call({
                  'op': 'identity_sign',
                  'private_key_pkcs8': privateKey,
                  'message': message,
                });
                ws.add(
                  jsonEncode(
                    existingId == null
                        ? {
                            'type': 'register',
                            'publicKey': _url64(publicKey),
                            'signature': _url64(signed['signature'] as String),
                          }
                        : {
                            'type': 'authenticate',
                            'deviceId': existingId,
                            'signature': _url64(signed['signature'] as String),
                          },
                  ),
                );
                break;
              case 'authenticated':
                deviceId = m['deviceId'] as String;
                await _storage.write(key: 'identity.deviceId', value: deviceId);
                status = 'Online';
                _attempt = 0;
                _reconnecting = false;
                _flushRevokes();
                if (_resumeSession != null)
                  _send({'type': 'resume', 'sessionId': _resumeSession});
                break;
              case 'requested':
                if (!_requestPending ||
                    sessionId != null ||
                    incomingSession != null ||
                    _accepting) {
                  _send({'type': 'end', 'sessionId': m['sessionId']});
                  break;
                }
                _requestPending = false;
                sessionId = m['sessionId'] as String;
                target = false;
                _binding = ControllerBinding(
                  sessionId!,
                  _requestTarget ?? '',
                  DateTime.now(),
                );
                _secretTimer?.cancel();
                _secretTimer = Timer(ControllerBinding.window, _dropSecret);
                status = 'Waiting for consent';
                break;
              case 'incoming':
                if (sessionId != null ||
                    incomingSession != null ||
                    _requestPending ||
                    _accepting) {
                  _send({'type': 'deny', 'sessionId': m['sessionId']});
                  break;
                }
                if (m['sessionId'] is! String || !validControllerId(m['controllerId'])) {
                  _send({'type': 'deny', 'sessionId': m['sessionId']});
                  break;
                }
                final from = m['controllerId'] as String;
                final key = normalizeKey(m['controllerPublicKey']);
                final locked = _lockouts.isLocked(from, DateTime.now());
                if (locked)
                  onAudit?.call('Unattended access locked for $from; asking owner');
                // Without the server-registered key nothing can be verified: ask the owner.
                if (key != null &&
                    !locked &&
                    (unattendedEnabled ||
                        _trusted.values.any((d) => d.controllerId == from))) {
                  await _autoAccept(m['sessionId'] as String, from, key);
                } else if (!_prompts.allow(
                  DateTime.now(),
                  from,
                  trusted: _trusted.values.any((d) => d.controllerId == from),
                )) {
                  // Prompt flood: drop without bothering the owner.
                  _send({'type': 'deny', 'sessionId': m['sessionId']});
                  onAudit?.call('Request from $from dropped: too many prompts');
                } else {
                  incomingSession = m['sessionId'] as String;
                  incomingController = from;
                  _controllerKey = key;
                }
                break;
              case 'accepted':
                if (sessionId == null || m['sessionId'] != sessionId) break;
                _acceptedPreset = m['preset'] as String;
                status = 'Negotiating';
                final expiresAt = m['expiresAt'] as int?;
                if (expiresAt == null) {
                  error = 'Session expiry missing';
                  end();
                  break;
                }
                _expiry?.cancel();
                {
                  final remaining = DateTime.fromMillisecondsSinceEpoch(
                    expiresAt,
                  ).difference(DateTime.now());
                  _expiry = Timer(
                    remaining.isNegative ? Duration.zero : remaining,
                    end,
                  );
                }
                _send({'type': 'turn', 'sessionId': sessionId});
                break;
              case 'turn':
                if (m['sessionId'] == sessionId)
                  await _startPeer(
                    (m['iceServers'] as List).cast<Map<String, dynamic>>(),
                  );
                break;
              case 'signal':
                if (m['sessionId'] == sessionId) await _handleSignal(m);
                break;
              case 'denied':
              case 'ended':
                if (m['sessionId'] != sessionId) break;
                _revoke();
                status = 'Session ended';
                break;
              case 'peer_down':
                if (m['sessionId'] == sessionId && m['resumeBy'] is int) {
                  _peerDown = true;
                  status = 'Reconnecting…';
                }
                break;
              case 'peer_resumed':
                if (m['sessionId'] == sessionId && _peerDown) {
                  _peerDown = false;
                  status = 'Connection: resuming';
                  if (!target) _scheduleIceRestart();
                }
                break;
              case 'resumed':
                if (m['sessionId'] == sessionId && _resumeSession == sessionId) {
                  _resumeSession = null;
                  _resumeTimer?.cancel();
                  status = 'Connection: resuming';
                  // Permissions stay as they were; nothing is granted again.
                  if (!target) _scheduleIceRestart();
                }
                break;
              case 'unrevoked':
                if (validControllerId(m['controllerId']))
                  onAudit?.call('Server block lifted for ${m['controllerId']}');
                break;
              case 'revoked':
                if (validControllerId(m['controllerId'])) {
                  _revokeQueue.remove(m['controllerId']);
                  unawaited(_saveRevokeQueue().catchError((Object _) {}));
                  onAudit?.call('Revoked at server: ${m['controllerId']}');
                }
                break;
              case 'revoked_attempt':
                if (validControllerId(m['controllerId']))
                  onAudit?.call(
                    'Blocked request from revoked device ${m['controllerId']}',
                  );
                break;
              case 'error':
                if (_resumeSession != null && m['code'] == 'invalid') {
                  _resumeSession = null;
                  _revoke();
                  status = 'Session ended';
                  error = 'Session could not be resumed';
                  break;
                }
                if (_requestPending) _dropSecret();
                _requestPending = false;
                error = 'Signaling error: ${m['code']}';
                if (status == 'Negotiating' && _pc == null)
                  await _startPeer([]);
                break;
            }
            notifyListeners();
          } catch (e) {
            error = 'Invalid signaling response: $e';
            notifyListeners();
          }
        },
        onError: (Object e) {
          if (!identical(_socket, ws)) return;
          error = 'Connection failed: $e';
          _closed(retry: true);
        },
        onDone: () {
          if (identical(_socket, ws)) _closed(retry: true);
        },
      );
    } catch (e) {
      error = 'Unable to connect: $e';
      status = 'Disconnected';
      if (_reconnecting) {
        _scheduleReconnect();
      } else {
        _endpoint = null;
      }
      notifyListeners();
    } finally {
      _cloudConnecting = false;
    }
  }

  void request(String id) {
    if (_direct ||
        sessionId != null ||
        incomingSession != null ||
        _requestPending ||
        _accepting) {
      error = 'A session or request is already pending.';
      _dropSecret();
      notifyListeners();
      return;
    }
    if (!connected || !RegExp(r'^\d{12}$').hasMatch(id)) {
      error = 'Enter a 12-digit device ID while online.';
      _dropSecret();
      notifyListeners();
      return;
    }
    _requestPending = true;
    _requestTarget = id;
    _send({'type': 'request', 'targetId': id});
    status = 'Requesting';
    notifyListeners();
  }

  Future<void> accept(
    String preset, {
    required bool elevatedConfirmed,
    String? sourceId,
    String quality = 'balanced',
  }) async {
    final id = incomingSession;
    // After failed unattended authentication the same session is offered to the owner.
    final late = _authPending && id != null && id == sessionId;
    if (id == null ||
        (sessionId != null && !late) ||
        _requestPending ||
        _accepting) return;
    _accepting = true;
    if (!late) {
      _captureSource = sourceId;
      _quality = quality;
    }
    final generation = _generation.current;
    target = true;
    sessionId = id;
    _controllerId = incomingController;
    incomingSession = null;
    incomingController = null;
    try {
      if (!await _authorize(
        id,
        preset,
        elevatedConfirmed,
        late ? _captureSource : sourceId,
        generation,
      )) return;
      if (late) {
        await _applyGrant(preset);
        onAudit?.call('Access allowed by owner after unattended check');
      } else {
        _send({
          'type': 'accept',
          'sessionId': id,
          'preset': preset,
          if (preset == 'full') 'confirmed': elevatedConfirmed,
        });
        status = 'Waiting for capture permission';
      }
      notifyListeners();
    } catch (e) {
      try {
        _core?.call({'op': 'session_revoke', 'session_id': id});
      } catch (_) {}
      if (_generation.isCurrent(generation) && sessionId == id) {
        if (late) {
          end();
        } else {
          _send({'type': 'deny', 'sessionId': id});
          _revoke();
        }
        error = 'Could not authorize session: $e';
        notifyListeners();
      }
    } finally {
      // A stale accept must not clear the flag of a newer one (_revoke already reset it).
      if (_generation.isCurrent(generation)) _accepting = false;
    }
  }

  /// Android: the foreground capture service must run while MediaProjection is used.
  Future<bool> _captureService(bool start) async {
    if (!Platform.isAndroid || _captureServiceOn == start) return true;
    try {
      await _android.invokeMethod(start ? 'startCaptureService' : 'stopCaptureService');
      _captureServiceOn = start;
      return true;
    } catch (e) {
      onAudit?.call('Capture service ${start ? 'start' : 'stop'} failed: $e');
      return false;
    }
  }

  /// Windows system-audio loopback (flutter_webrtc `audio: true`), only if the core grants audio.
  /// Tracks stay disabled until auth completes, like the video track.
  bool _audioAllowed(String? session) =>
      Platform.isWindows &&
      captureAuthorized(
        () => _core!.call({
          'op': 'session_check',
          'session_id': session,
          'capability': 'audio',
        }),
      );

  /// Local target-side grant: display mapping, core permissions, Android service.
  /// Returns false when the session ended meanwhile.
  Future<bool> _authorize(
    String id,
    String preset,
    bool elevatedConfirmed,
    String? sourceId,
    int generation, {
    Map<String, dynamic>? permissions,
  }) async {
    final input = permissions == null
        ? preset != 'basic'
        : permissions['input'] == true;
    // Display mapping is local target authority, never peer-provided.
    if ((Platform.isWindows || Platform.isLinux) && input) {
      if (sourceId == null)
        throw StateError('Choose a screen explicitly to allow input');
      final screens = await desktopCapturer.getSources(
        types: [SourceType.Screen],
      );
      if (!_generation.isCurrent(generation) || sessionId != id) return false;
      if (!screens.any((source) => source.id == sourceId))
        throw StateError('Selected screen is no longer available');
      final display = _core!.call({'op': 'input_display'});
      if (display['desktop_input_safe'] != true)
        throw StateError(
          '${display['reason'] ?? 'Desktop input mapping is unavailable'}',
        );
      _desktopInputSafe = true;
    }
    // Called only by the local consent dialog or after verified unattended authentication.
    _core!.call({
      'op': 'session_accept',
      'session_id': id,
      'accepted': true,
      'preset': permissions == null ? preset : 'custom',
      if (permissions != null) 'permissions': permissions,
      'elevated_confirmed': elevatedConfirmed,
    });
    if (Platform.isAndroid) {
      final notifications = await _android.invokeMethod<bool>(
            'requestNotificationPermission',
          ) ??
          false;
      if (!notifications)
        throw StateError(
          'Enable session notifications before allowing access',
        );
      if (!_generation.isCurrent(generation) || sessionId != id) return false;
      final inputOk = await _androidInputOrViewOnly(input);
      if (!_generation.isCurrent(generation) || sessionId != id) return false;
      await _android.invokeMethod('acceptSession', {
        'sessionId': id,
        'input': inputOk,
        'clipboardText': inputOk,
        'confirmed': true,
      });
    }
    if (!_generation.isCurrent(generation) || sessionId != id) {
      if (Platform.isAndroid) await _android.invokeMethod('revokeSession');
      return false;
    }
    return true;
  }

  /// Unattended path: the server accept is only a signaling channel; the core grants
  /// view-only, the stream stays black and ICE is relay-only until the controller authenticates.
  Future<void> _autoAccept(String id, String from, String key) async {
    String? screen;
    if (Platform.isWindows || Platform.isLinux) {
      try {
        final sources = await desktopCapturer.getSources(
          types: [SourceType.Screen],
        );
        if (sources.length == 1) screen = sources.single.id;
      } catch (_) {}
    }
    if (sessionId != null || incomingSession != null || _requestPending) {
      _send({'type': 'deny', 'sessionId': id}); // became busy while enumerating screens
      return;
    }
    incomingSession = id;
    incomingController = from;
    _controllerKey = key;
    _authPending = true;
    _relayOnly = true; // keep relay after auth (shortcut: no ICE restart to direct)
    await accept('basic', elevatedConfirmed: false, sourceId: screen);
    if (sessionId == null) {
      _authPending = false;
      _relayOnly = false;
      return;
    }
    _gate = ChallengeGate();
    _authTimer?.cancel();
    _authTimer = Timer(
      ChallengeGate.defaultTtl,
      () {
        if (_window.expire()) _authFailed();
      },
    );
  }

  /// Auth window over or no credentials: ask the owner; no answer in 60 s ends the session.
  void _authFailed() {
    if (!_authPending || sessionId == null || incomingSession != null) return;
    _authTimer?.cancel();
    _gate?.close();
    final who = _controllerId ?? '';
    if (!_prompts.allow(
      DateTime.now(),
      who,
      trusted: _trusted.values.any((d) => d.controllerId == who),
    )) {
      onAudit?.call('Request from $_controllerId dropped: too many prompts');
      end();
      return;
    }
    onAudit?.call('Unattended authentication not completed; asking owner');
    incomingSession = sessionId;
    incomingController = _controllerId;
    final session = sessionId;
    _authTimer = Timer(const Duration(seconds: 60), () {
      if (_authPending && sessionId == session && incomingSession == session) {
        error = 'Nobody answered the access request';
        end();
      }
    });
    notifyListeners();
  }

  Future<void> _applyGrant(String preset) async {
    _authTimer?.cancel();
    _gate?.close();
    _authPending = false;
    incomingSession = null;
    incomingController = null;
    _acceptedPreset = preset;
    final audio = _audioAllowed(sessionId); // the granted permissions decide
    for (final track in _capture?.getTracks() ?? <MediaStreamTrack>[]) {
      track.enabled = track.kind != 'audio' || audio;
    }
    status = 'Connection: granted';
    await _channel?.send(
      RTCDataChannelMessage(jsonEncode({'t': 'auth_result', 'preset': preset})),
    );
  }

  /// One challenge per session; [ChallengeGate] refuses a second one.
  void _issueChallenge() {
    final gate = _gate, id = sessionId, me = deviceId;
    if (gate == null || id == null || me == null) return;
    final random = Random.secure();
    final nonce = gate.issue(
      DateTime.now(),
      Uint8List.fromList(List.generate(32, (_) => random.nextInt(256))),
    );
    if (nonce == null) return;
    final password =
        _unattendedRecord != null && _budget.canAttempt(DateTime.now());
    _sendControl({
      't': 'auth_challenge',
      'nonce': base64Encode(nonce),
      'session_id': id,
      'target_id': me,
      if (password) 'password': true,
    });
  }

  /// The preset a trust entry would get: capped at normal unless [allowFull].
  String? trustablePreset({bool allowFull = false}) {
    final p = _acceptedPreset;
    if (p == null || !trustPresets.contains(p)) return null;
    return p == 'full' && !allowFull ? 'normal' : p;
  }

  String? get acceptedPreset => _acceptedPreset;

  /// Target: owner chose "Trust this device" after an attended accept. The controller must
  /// sign a fresh nonce (bound to this session and connection) once its user agrees.
  void trustController({bool allowFull = false}) {
    final id = sessionId, me = deviceId;
    if (!canTrustController || id == null || me == null) return;
    final random = Random.secure();
    final gate = ChallengeGate(ttl: const Duration(seconds: 60), maxAttempts: 1);
    final nonce = gate.issue(
      DateTime.now(),
      Uint8List.fromList(List.generate(32, (_) => random.nextInt(256))),
    );
    if (nonce == null) return;
    _enrollGate = gate;
    _enrollPreset = trustablePreset(allowFull: allowFull);
    _sendControl({
      't': 'enroll_request',
      'nonce': base64Encode(nonce),
      'session_id': id,
      'target_id': me,
    });
    trustStatus = 'Waiting for the other device to agree';
    notifyListeners();
  }

  Map<String, String> _proofFields(
    String purpose,
    String session,
    String targetId,
    String controllerId,
    Uint8List nonce,
    ({String controller, String target}) fps,
  ) => {
    'purpose': purpose,
    'session_id': session,
    'target_id': targetId,
    'controller_id': controllerId,
    'nonce': base64Encode(nonce),
    'controller_dtls_fp': fps.controller,
    'target_dtls_fp': fps.target,
  };

  /// Controller: the user answered the target's request to trust this device.
  Future<void> answerEnroll(bool allow) async {
    final identity = _identity, binding = _binding, nonce = _enrollChallenge;
    final me = deviceId, id = sessionId;
    if (!enrollRequested ||
        identity == null ||
        binding == null ||
        nonce == null ||
        me == null ||
        id == null) return;
    enrollRequested = false;
    _enrollChallenge = null;
    notifyListeners();
    if (!allow) return;
    try {
      final fps = await _fingerprints();
      if (fps == null) throw StateError('connection fingerprints unavailable');
      final signed = _core!.call({
        'op': 'unattended_proof_sign',
        'private_key_pkcs8': identity.privateKey,
        ..._proofFields('enroll', id, binding.targetId, me, nonce, fps),
      });
      if (sessionId != id) return;
      _sendControl({
        't': 'enroll',
        'public_key': identity.publicKey,
        'signature': signed['signature'],
      });
    } catch (e) {
      error = 'Could not answer the trust request: $e';
      notifyListeners();
    }
  }

  /// Target: verify the controller's signed proof with the server-registered key, then trust it.
  Future<void> _onEnroll(Map<String, dynamic> event) async {
    final preset = _enrollPreset, from = _controllerId, key = _controllerKey;
    final me = deviceId, session = sessionId;
    final nonce = _enrollGate?.answer(DateTime.now());
    _enrollGate = null; // single use
    if (nonce == null ||
        preset == null ||
        from == null ||
        key == null ||
        me == null ||
        session == null ||
        !canTrustController) return;
    final reply = parseAuthReply(event);
    final replyKey = normalizeKey(reply?.publicKey);
    try {
      if (reply == null || replyKey != key)
        throw StateError('device key does not match its registered key');
      final fps = await _fingerprints();
      if (fps == null || sessionId != session)
        throw StateError('connection fingerprints unavailable');
      _core!.call({
        'op': 'proof_verify',
        'public_key': replyKey,
        'expected_public_key': key,
        ..._proofFields('enroll', session, me, from, nonce, fps),
        'signature': reply.signature,
      });
      if (!connected) throw StateError('go online to trust this device');
      // A controller revoked earlier is blocked at the server until unrevoked.
      _revokeQueue.remove(from);
      await _saveRevokeQueue();
      _send({'type': 'unrevoke', 'controllerId': from});
      final id = _core!.call({
        'op': 'trust_set',
        'public_key': key,
        'controller_id': from,
        'preset': preset,
        'owner_confirmed': true,
        if (preset == 'full') 'elevated_confirmed': true,
      })['device_id'] as String;
      _trusted[id] = TrustedDevice(id, from, preset);
      await _saveTrust();
      trustStatus = 'Device trusted ($preset)';
      onAudit?.call('Device trusted: $from ($preset)');
    } catch (e) {
      trustStatus = 'Could not trust this device: $e';
    }
    notifyListeners();
  }

  /// DTLS fingerprints (controller, target) of the live connection, from the SDPs.
  Future<({String controller, String target})?> _fingerprints() async {
    final pc = _pc, remote = _remoteFp;
    final local = dtlsFingerprint((await pc?.getLocalDescription())?.sdp);
    if (local == null || remote == null) return null;
    return target
        ? (controller: remote, target: local)
        : (controller: local, target: remote);
  }

  void _recordFail(String from) {
    if (_failCounted) return;
    _failCounted = true;
    _lockouts.recordFailedSession(from, DateTime.now());
    unawaited(
      _storage
          .write(key: 'unattended.lockout', value: _lockouts.toJson())
          .catchError((Object _) {}),
    );
  }

  /// `auth`: trusted-key proof and/or OPAQUE KE1. `auth_finish`: OPAQUE KE3 for the KE2 we sent.
  Future<void> _onAuth(Map<String, dynamic> event, String session) async {
    final gate = _gate, from = _controllerId, key = _controllerKey;
    final me = deviceId;
    final finish = event['t'] == 'auth_finish', login = _serverLogin;
    if (finish) _serverLogin = null; // single use
    if (!_authPending ||
        sessionId != session ||
        _window.verifying ||
        gate == null ||
        from == null ||
        key == null ||
        me == null) return;
    final now = DateTime.now();
    final nonce = finish ? null : gate.answer(now);
    // Expired, closed or out of attempts; a finish needs our pending KE2 and counts no new attempt.
    if (finish ? login == null || !gate.live(now) : nonce == null) return;
    _window.verifying = true;
    try {
      final reply = finish ? null : parseAuthReply(event);
      Map<String, dynamic>? permissions;
      String? preset;
      var how = '';
      if (finish) {
        final ke3 = opaqueMessage(event['ke3'], ke3Length);
        try {
          if (ke3 != null &&
              _unattendedRecord != null &&
              _core!.call({
                    'op': 'unattended_login_verify',
                    'state': login!.state,
                    'ke3': ke3,
                    ...login.fields,
                  })['valid'] ==
                  true) {
            preset = unattendedPreset;
            _viaPassword = true;
            _budget.succeeded();
            _saveBudget();
            how = 'Unattended password';
          }
        } catch (_) {}
      } else {
        final fps = await _fingerprints();
        if (!_authPending || sessionId != session) return;
        if (fps == null) {
          error = 'Could not bind authentication to the connection';
          await end();
          return;
        }
        final fields = _proofFields('auth', session, me, from, nonce!, fps);
        final replyKey = normalizeKey(reply?.publicKey);
        if (reply != null && replyKey != null) {
          try {
            // The core only trusts the server-registered key, bound to this controller id.
            final verified = _core!.call({
              'op': 'trust_verify',
              'public_key': replyKey,
              'expected_public_key': key,
              ...fields,
              'signature': reply.signature,
            });
            permissions = (verified['permissions'] as Map).cast<String, dynamic>();
            how = 'Trusted device';
          } catch (_) {}
        }
        // Only a KE1 signed by the controller's registered key may spend the target-wide budget;
        // unsigned ones are counted against that controller alone (see _recordFail below).
        var signed = false;
        if (permissions == null && reply?.ke1 != null && replyKey != null) {
          try {
            _core!.call({
              'op': 'auth_signature_verify',
              'public_key': replyKey,
              'expected_public_key': key,
              ...fields,
              'signature': reply!.signature,
            });
            signed = true;
          } catch (_) {}
        }
        if (permissions == null &&
            reply?.ke1 != null &&
            _unattendedRecord != null &&
            signed) {
          if (!_budget.canAttempt(now)) {
            onAudit?.call('Password attempt refused: target-wide budget used up');
          } else {
            _budget.record(now); // counted and persisted before answering, so a crash cannot reset it
            await _saveBudget();
            if (!_authPending || sessionId != session) return;
            try {
              final r = _core!.call({
                'op': 'unattended_login_respond',
                'record': _unattendedRecord,
                'ke1': reply!.ke1,
                ...fields,
              });
              // Counted as failed until KE3 proves the password: a controller with a wrong one just stops.
              _recordFail(from);
              _serverLogin = (state: r['state'] as String, fields: fields);
              _sendControl({'t': 'auth_opaque', 'ke2': r['ke2']});
              return;
            } catch (_) {}
          }
        }
      }
      if (!_authPending || sessionId != session) return;
      if (permissions == null && preset == null) {
        final guessed = finish ||
            reply?.ke1 != null ||
            _trusted.values.any((d) => d.controllerId == from);
        onAudit?.call(
          'Unattended authentication failed for $from (${gate.attempts}/${gate.maxAttempts})',
        );
        if (guessed) _recordFail(from);
        if (gate.exhausted) {
          error = 'Too many failed attempts';
          await end();
        } else if (!guessed) {
          _authFailed(); // no credentials at all: ask the owner now
        }
        return;
      }
      // Never elevated unless the stored policy says so; the core's answer is the only grant source.
      final label = permissions == null
          ? preset!
          : permissions['elevated'] == true
              ? 'full'
              : permissions['input'] == true
                  ? 'normal'
                  : 'basic';
      final generation = _generation.current;
      _gate?.close();
      _authTimer?.cancel();
      try {
        if (!await _authorize(
          session,
          label,
          permissions != null && _sensitive(permissions),
          _captureSource,
          generation,
          permissions: permissions,
        )) return;
        _lockouts.reset(from);
        unawaited(
          _storage
              .write(key: 'unattended.lockout', value: _lockouts.toJson())
              .catchError((Object _) {}),
        );
        await _applyGrant(label);
        onAudit?.call('$how accepted for $from ($label)');
      } catch (e) {
        error = 'Could not authorize session: $e';
        await end();
      }
    } finally {
      // An auth-window expiry that landed mid-verification must not be lost.
      if (_window.finishFailed() &&
          _authPending &&
          sessionId == session &&
          incomingSession == null) {
        _authFailed();
      }
      notifyListeners();
    }
  }

  static bool _sensitive(Map<String, dynamic> p) => const [
        'clipboard_files',
        'file_transfer',
        'lock',
        'power',
        'elevated',
        'adb',
      ].any((k) => p[k] == true);

  Future<void> _startPeer(List<Map<String, dynamic>> servers) async {
    if (_pc != null || _startingPeer || sessionId == null) return;
    _startingPeer = true;
    final startingSession = sessionId;
    final generation = _generation.current;
    bool live() =>
        _generation.isCurrent(generation) && sessionId == startingSession;
    try {
      if (!rendererReady) {
        await renderer.initialize();
        rendererReady = true;
        if (!live()) return;
      }
      final pc = await createPeerConnection({
        'iceServers': servers,
        'sdpSemantics': 'unified-plan',
        if (_relayOnly) 'iceTransportPolicy': 'relay', // no host IPs before auth
      });
      if (!live()) {
        await pc.close();
        return;
      }
      _pc = pc;
      pc.onIceCandidate = (candidate) {
        if (live() &&
            candidate.candidate != null &&
            (!_relayOnly || candidate.candidate!.contains(' typ relay')))
          _signal('ice', {
            'candidate': candidate.candidate,
            'sdpMid': candidate.sdpMid,
            'sdpMLineIndex': candidate.sdpMLineIndex,
          });
      };
      pc.onConnectionState = (value) {
        if (!live()) return;
        status = 'Connection: $value';
        if (value == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
          _iceRetry?.cancel();
          _iceRetry = null;
          _iceAttempt = 0;
        } else if (!target &&
            !_direct &&
            (value == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
                value ==
                    RTCPeerConnectionState
                        .RTCPeerConnectionStateDisconnected)) {
          _scheduleIceRestart();
        }
        notifyListeners();
      };
      pc.onTrack = (event) {
        if (live() && event.streams.isNotEmpty) {
          renderer.srcObject = event.streams.first;
          if (event.track.kind == 'audio') {
            _remoteAudio = event.track;
            event.track.enabled = !muted;
          }
          notifyListeners();
        }
      };
      pc.onDataChannel = (channel) {
        if (live() && target && channel.label == 'input' && _channel == null) {
          _attachChannel(channel, startingSession!, generation);
        } else if (live() &&
            target &&
            channel.label == 'files' &&
            _files == null) {
          _attachFiles(channel, startingSession!, generation);
        } else if (live() && target && channel.label == 'tv' && _tv == null) {
          _attachTv(channel, startingSession!, generation);
        } else {
          channel.close();
        }
      };
      if (target &&
          captureAuthorized(
            () => _core!.call({
              'op': 'session_check',
              'session_id': startingSession,
              'capability': 'view',
            }),
          )) {
        if (Platform.isAndroid) {
          // Android 14+: projection consent first, then the mediaProjection foreground service, then capture.
          bool consent = false;
          try {
            consent = await Helper.requestCapturePermission();
          } catch (_) {}
          if (!live()) return;
          if (!consent) throw StateError('Screen capture permission was denied');
          if (!await _captureService(true))
            throw StateError('Screen capture service failed to start');
          if (!live()) return;
        }
        final capture = await navigator.mediaDevices.getDisplayMedia({
          'video': _captureSource == null
              ? true
              : {
                  'deviceId': {'exact': _captureSource},
                  'optional': [
                    {'frameRate': 30.0},
                  ],
                },
          'audio': _audioAllowed(startingSession),
        });
        if (!live()) {
          for (final track in capture.getTracks()) {
            await track.stop();
          }
          await capture.dispose();
          return;
        }
        _capture = capture;
        for (final track in capture.getTracks()) {
          track.enabled = !_authPending; // black until the controller authenticates
          final sender = await pc.addTrack(track, capture);
          if (!live()) return;
          if (track.kind == 'video') _videoSender = sender; // encodings exist only after negotiation
        }
      } else if (!target) {
        await pc.addTransceiver(
          kind: RTCRtpMediaType.RTCRtpMediaTypeVideo,
          init: RTCRtpTransceiverInit(direction: TransceiverDirection.RecvOnly),
        );
        if (!live()) return;
        await pc.addTransceiver(
          kind: RTCRtpMediaType.RTCRtpMediaTypeAudio,
          init: RTCRtpTransceiverInit(direction: TransceiverDirection.RecvOnly),
        );
        if (!live()) return;
        final channel = await pc.createDataChannel(
          'input',
          RTCDataChannelInit(),
        );
        if (!live()) {
          await channel.close();
          return;
        }
        _attachChannel(channel, startingSession!, generation);
        final files = await pc.createDataChannel('files', RTCDataChannelInit());
        if (!live()) {
          await files.close();
          return;
        }
        _attachFiles(files, startingSession, generation);
        final tv = await pc.createDataChannel('tv', RTCDataChannelInit());
        if (!live()) {
          await tv.close();
          return;
        }
        _attachTv(tv, startingSession, generation);
        final offer = await pc.createOffer();
        if (!live()) return;
        await pc.setLocalDescription(offer);
        if (!live()) return;
        _signal('offer', {'sdp': offer.sdp, 'type': offer.type});
      }
      if (!live()) return;
      _peerReady = true;
      for (final signal in List<Map<String, dynamic>>.from(_queuedSignals)) {
        await _handleSignal(signal);
        if (!live()) return;
      }
      _queuedSignals.clear();
      notifyListeners();
    } catch (e) {
      if (!live()) return;
      error = 'Media setup failed: $e';
      end();
      notifyListeners();
    } finally {
      // A newer session owns the flag once this run's generation is stale (_revoke reset it).
      if (_generation.isCurrent(generation)) _startingPeer = false;
    }
  }

  /// Sender bitrate cap for the chosen quality, set after setLocalDescription.
  /// Steps down 5M -> 2M -> 800k when rejected; never a user-visible error.
  Future<void> _applyQuality() async {
    final sender = _videoSender;
    if (sender == null) return;
    final generation = _generation.current;
    final bitrates = _quality == 'low'
        ? [800000]
        : _quality == 'high'
            ? [5000000, 2000000, 800000]
            : [2000000, 800000];
    for (final bitrate in bitrates) {
      if (!_generation.isCurrent(generation) || _videoSender != sender) return;
      try {
        final parameters = sender.parameters;
        final encodings = parameters.encodings;
        if (encodings == null || encodings.isEmpty) {
          onAudit?.call('Video quality controls unavailable on this device');
          return;
        }
        for (final encoding in encodings) {
          encoding.maxBitrate = bitrate;
          encoding.maxFramerate = _quality == 'low' ? 20 : 30;
        }
        if (await sender.setParameters(parameters)) return;
      } catch (_) {}
    }
    if (_generation.isCurrent(generation))
      onAudit?.call('Video quality controls were rejected; using encoder defaults');
  }

  bool _validDirectSignal(String kind, Map<String, dynamic> data) {
    if (kind == 'ice') {
      final candidate = data['candidate'];
      return candidate is String &&
          candidate.length <= 4096 &&
          RegExp(
            r'^candidate:\S+\s+\d+\s+(udp|tcp)\s+\d+\s+\S+\s+\d+\s+typ\s+(host|srflx|prflx)\b',
            caseSensitive: false,
          ).hasMatch(candidate);
    }
    final sdp = data['sdp'];
    return (kind == 'offer' || kind == 'answer') &&
        data['type'] == kind &&
        sdp is String &&
        sdp.length <= 60000 &&
        !RegExp(r'(?im)^a=candidate:.*\btyp\s+relay\b').hasMatch(sdp);
  }

  void _signal(String kind, Map<String, dynamic> data) {
    if (sessionId == null) return;
    if (_direct) {
      if (!_validDirectSignal(kind, data)) return;
      final generation = _generation.current;
      unawaited(
        _directSend!(kind, data).catchError((Object e) {
          if (_generation.isCurrent(generation)) {
            error = 'Direct signaling failed: $e';
            end();
          }
        }),
      );
    } else {
      _send({
        'type': 'signal',
        'sessionId': sessionId,
        'kind': kind,
        'data': data,
      });
    }
  }

  Future<void> _handleSignal(Map<String, dynamic> message) async {
    final pc = _pc;
    final boundSession = sessionId;
    final generation = _generation.current;
    bool live() =>
        _generation.isCurrent(generation) &&
        sessionId == boundSession &&
        _pc == pc;
    if (pc == null || !_peerReady) {
      _queuedSignals.add(message);
      return;
    }
    final data = message['data'] as Map<String, dynamic>;
    if (message['kind'] == 'ice') {
      final candidate = RTCIceCandidate(
        data['candidate'] as String?,
        data['sdpMid'] as String?,
        data['sdpMLineIndex'] as int?,
      );
      if (_remoteDescriptionSet) {
        await pc.addCandidate(candidate);
      } else {
        _pendingIce.add(candidate);
      }
    } else if (message['kind'] == 'offer' && target ||
        message['kind'] == 'answer' && !target) {
      final fp = dtlsFingerprint(data['sdp'] as String?);
      if (fp == null || (_remoteFp != null && fp != _remoteFp)) {
        onAudit?.call(
          fp == null
              ? 'Session refused: peer DTLS fingerprint missing or not sha-256'
              : 'Session ended: peer DTLS fingerprint changed',
        );
        error = 'Peer certificate changed; session ended';
        end();
        return;
      }
      _remoteFp = fp;
      await pc.setRemoteDescription(
        RTCSessionDescription(data['sdp'] as String?, data['type'] as String?),
      );
      if (!live()) return;
      _remoteDescriptionSet = true;
      for (final candidate in _pendingIce) {
        await pc.addCandidate(candidate);
        if (!live()) return;
      }
      _pendingIce.clear();
      if (target) {
        final answer = await pc.createAnswer();
        if (!live()) return;
        await pc.setLocalDescription(answer);
        if (!live()) return;
        _signal('answer', {'sdp': answer.sdp, 'type': answer.type});
        await _applyQuality();
      }
    }
  }

  void _attachChannel(
    RTCDataChannel channel,
    String boundSession,
    int generation,
  ) {
    _channel = channel;
    if (!target) {
      void hello() {
        if (!_generation.isCurrent(generation) || sessionId != boundSession)
          return;
        _sendControl({'t': 'hello'});
        _sendControl({'t': 'monitors'});
      }

      channel.onDataChannelState = (state) {
        if (state == RTCDataChannelState.RTCDataChannelOpen) hello();
      };
      if (channel.state == RTCDataChannelState.RTCDataChannelOpen) hello();
    } else if (_viewOnly) {
      // Tell the controller once the channel is open so its UI can hide input.
      void announce() {
        if (_generation.isCurrent(generation) && sessionId == boundSession)
          _sendControl({'t': 'view_only'});
      }

      channel.onDataChannelState = (state) {
        if (state == RTCDataChannelState.RTCDataChannelOpen) announce();
      };
      if (channel.state == RTCDataChannelState.RTCDataChannelOpen) announce();
    }
    channel.onMessage = (message) async {
      if (!_generation.isCurrent(generation) ||
          sessionId != boundSession ||
          message.isBinary ||
          message.text.length > 4096) return;
      try {
        final event = jsonDecode(message.text);
        if (event is! Map<String, dynamic>) return;
        if (!target) {
          await _controllerMessage(event);
          return;
        }
        if (event['t'] == 'select_display') {
          final d = event['display'];
          if ((Platform.isWindows || Platform.isLinux) && d is int && d >= 0 && d < 64)
            unawaited(_switchCapture(d, boundSession, generation));
          return;
        }
        if (event['t'] == 'hello') {
          if (_authPending && incomingSession == null) _issueChallenge();
          return;
        }
        if (event['t'] == 'enroll') {
          await _onEnroll(event);
          return;
        }
        if (event['t'] == 'auth' || event['t'] == 'auth_finish') {
          await _onAuth(event, boundSession);
          return;
        }
        if (event['t'] == 'monitors') {
          if (_authPending) return;
          _core!.call({
            'op': 'session_check',
            'session_id': boundSession,
            'capability': 'view',
          });
          final current = await _currentDisplay();
          _sendControl({
            't': 'monitors',
            'monitors': _core!.call({'op': 'monitors'})['monitors'],
            if (current != null) 'current': current,
          });
          return;
        }
        if (_viewOnly) return; // input and clipboard are off: drop quietly
        if (event['t'] == 'clipboard_text') {
          final value = event['text'];
          if (value is! String || value.length > 2048) return;
          _core!.call({
            'op': 'session_check',
            'session_id': boundSession,
            'capability': 'clipboard_text',
          });
          if (Platform.isAndroid) {
            await _android.invokeMethod('writeClipboard', {
              'sessionId': boundSession,
              'text': value,
            });
          } else {
            await Clipboard.setData(ClipboardData(text: value));
          }
          return;
        }
        if (Platform.isWindows || Platform.isLinux) {
          if (!_desktopInputSafe ||
              _core!.call({'op': 'input_display'})['desktop_input_safe'] !=
                  true) return;
        }
        // Never forward an operation name, session id, or capability from the peer.
        if (Platform.isAndroid) {
          _core!.call({
            'op': 'validate_input',
            'session_id': boundSession,
            'event': event,
          });
          await _android.invokeMethod('injectInput', {
            'sessionId': boundSession,
            'event': event,
          });
        } else {
          final result = _core!.call({
            'op': 'inject_input',
            'session_id': boundSession,
            'event': event,
          });
          if (event['t'] == 'secure_attention' &&
              result['requires_service'] == true) {
            String? failure;
            if (Platform.isWindows) {
              try {
                _core!.call({'op': 'service_send_sas'});
              } catch (_) {
                failure = 'Ctrl+Alt+Del requires the background service';
              }
            } else {
              failure = 'Ctrl+Alt+Del requires the background service';
            }
            _sendControl({'t': 'notice', 'text': failure ?? 'Ctrl+Alt+Del sent'});
          }
        }
      } catch (e) {
        error = 'Input rejected: $e';
        notifyListeners();
      }
    };
  }

  void _sendControl(Map<String, dynamic> message) {
    final channel = _channel;
    if (channel == null) return;
    channel.send(RTCDataChannelMessage(jsonEncode(message))).catchError((_) {});
  }

  /// Controller side: target-to-controller messages. Everything is validated here.
  Future<void> _controllerMessage(Map<String, dynamic> event) async {
    switch (event['t']) {
      case 'auth_challenge':
        // Sign only for the session we requested ourselves, early in that session.
        final nonce = parseNonce(event['nonce']);
        final binding = _binding, me = deviceId, identity = _identity;
        final id = sessionId, claimed = event['session_id'];
        if (nonce == null ||
            binding == null ||
            me == null ||
            identity == null ||
            id == null ||
            _answers >= 3 ||
            claimed is! String ||
            event['target_id'] is! String ||
            !binding.allowsAuth(claimed, event['target_id'] as String, DateTime.now()))
          return;
        _answers++;
        final fps = await _fingerprints();
        if (fps == null || sessionId != id) return;
        final fields = {
          'purpose': 'auth',
          'session_id': id,
          'target_id': binding.targetId,
          'controller_id': me,
          'nonce': base64Encode(nonce),
          'controller_dtls_fp': fps.controller,
          'target_dtls_fp': fps.target,
        };
        final signed = _core!.call({
          'op': 'unattended_proof_sign',
          'private_key_pkcs8': identity.privateKey,
          ...fields,
        });
        String? ke1;
        final secret = unattendedSecret;
        if (secret != null && secret.isNotEmpty && event['password'] == true) {
          // OPAQUE: only a blinded KE1 is sent; the password stays here until KE2 arrives.
          final start =
              _core!.call({'op': 'unattended_login_start', 'password': secret});
          ke1 = start['ke1'] as String;
          _clientLogin =
              (state: start['state'] as String, password: secret, fields: fields);
        }
        unattendedSecret = null;
        onSecretUsed?.call();
        if (sessionId != id) return;
        _sendControl({
          't': 'auth',
          'public_key': identity.publicKey,
          'signature': signed['signature'],
          if (ke1 != null) 'ke1': ke1,
        });
        break;
      case 'auth_opaque':
        final login = _clientLogin, id = sessionId;
        _clientLogin = null; // single use
        final ke2 = opaqueMessage(event['ke2'], ke2Length);
        if (login == null ||
            ke2 == null ||
            id == null ||
            login.fields['session_id'] != id) return;
        try {
          // Argon2 off the UI isolate; fails on a wrong password, a fake target or another connection.
          final ke3 = (await NativeCore.callOffUi({
            'op': 'unattended_login_finish',
            'password': login.password,
            'state': login.state,
            'ke2': ke2,
            ...login.fields,
          }))['ke3'] as String;
          if (sessionId != id) return;
          _sendControl({'t': 'auth_finish', 'ke3': ke3});
        } catch (_) {
          error = 'The unattended password was not accepted';
          notifyListeners();
        }
        break;
      case 'enroll_request':
        final nonce = parseNonce(event['nonce']);
        final binding = _binding;
        if (nonce == null ||
            binding == null ||
            event['session_id'] != binding.sessionId ||
            event['target_id'] != binding.targetId ||
            sessionId != binding.sessionId) return;
        _enrollChallenge = nonce;
        enrollRequested = true; // shown to the user; signed only after they agree
        break;
      case 'auth_result':
        final preset = event['preset'];
        if (preset is! String || !trustPresets.contains(preset)) return;
        _acceptedPreset = preset; // UI hint only; the target enforces
        status = 'Connection: granted';
        _sendControl({'t': 'monitors'});
        break;
      case 'monitors':
        final list = parseMonitors(event['monitors']);
        if (list == null) return;
        monitors = list;
        if (!list.any((m) => m.id == display)) {
          final current = event['current'];
          // Default: what the target says it captures, else the primary monitor.
          display = list.isEmpty
              ? null
              : list.any((m) => m.id == current)
                  ? current as int
                  : list.firstWhere((m) => m.primary, orElse: () => list.first).id;
        }
        break;
      case 'display':
        final d = event['display'];
        if (d is int && monitors.any((m) => m.id == d)) display = d;
        break;
      case 'view_only':
        _viewOnly = true;
        notice = 'View only: remote device has control disabled';
        break;
      case 'notice':
        final text = event['text'];
        if (text is String && text.length <= 200) notice = text;
        break;
      default:
        return;
    }
    notifyListeners();
  }

  bool _tvRate(List<DateTime> times) {
    final now = DateTime.now();
    times.removeWhere((t) => now.difference(t) >= const Duration(seconds: 1));
    if (times.length >= 10) return false;
    times.add(now);
    return true;
  }

  void _attachTv(RTCDataChannel channel, String boundSession, int generation) {
    _tv = channel;
    bool live() =>
        _generation.isCurrent(generation) &&
        sessionId == boundSession &&
        _tv == channel;
    channel.onMessage = (message) async {
      if (!live() ||
          message.isBinary ||
          utf8.encode(message.text).length > 16384) return;
      try {
        final decoded = jsonDecode(message.text);
        if (decoded is! Map<String, dynamic> || decoded['id'] is! int) return;
        final id = decoded['id'] as int;
        if (!target && decoded['type'] == 'response') {
          final pending = _tvPending.remove(id);
          if (pending == null || pending.isCompleted) return;
          if (decoded['ok'] == true &&
              decoded['result'] is Map<String, dynamic>) {
            pending.complete(decoded['result'] as Map<String, dynamic>);
          } else {
            pending.completeError(StateError('Remote TV request rejected'));
          }
          return;
        }
        if (!target ||
            decoded['type'] != 'request' ||
            decoded['request'] is! Map<String, dynamic>) return;
        if (id <= _tvLastReceivedId ||
            id > 9007199254740991 ||
            !_tvRate(_tvReceived) ||
            _tvInFlight >= 8) return;
        _tvLastReceivedId = id;
        _tvInFlight++;
        final handler = tvHandler;
        Map<String, dynamic>? result;
        try {
          if (handler == null) throw StateError('TV service unavailable');
          result = await handler(
            boundSession,
            decoded['request'] as Map<String, dynamic>,
          );
        } catch (_) {
        } finally {
          _tvInFlight--;
        }
        if (!live()) return;
        var response = jsonEncode({
          'type': 'response',
          'id': id,
          'ok': result != null,
          if (result != null) 'result': result,
        });
        if (utf8.encode(response).length > 16384)
          response = jsonEncode({'type': 'response', 'id': id, 'ok': false});
        await channel.send(RTCDataChannelMessage(response));
      } catch (_) {
        /* Malformed messages never invoke a native operation. */
      }
    };
  }

  Future<Map<String, dynamic>> sendTv(Map<String, dynamic> request) async {
    final channel = _tv;
    final id = sessionId;
    final generation = _generation.current;
    if (target || id == null || channel == null)
      throw StateError('TV channel unavailable');
    if (_tvPending.length >= 8 || !_tvRate(_tvSent))
      throw StateError('TV request limit reached');
    final requestId = ++_tvNextId;
    final encoded = jsonEncode({
      'type': 'request',
      'id': requestId,
      'request': request,
    });
    if (utf8.encode(encoded).length > 16384)
      throw StateError('TV request too large');
    final pending = Completer<Map<String, dynamic>>();
    _tvPending[requestId] = pending;
    try {
      final results = await Future.wait<Object?>([
        channel.send(RTCDataChannelMessage(encoded)).then<Object?>((_) => null),
        pending.future
            .timeout(const Duration(seconds: 5))
            .then<Object?>((value) => value),
      ]);
      if (!_generation.isCurrent(generation) || sessionId != id)
        throw StateError('Session ended');
      return results[1] as Map<String, dynamic>;
    } finally {
      _tvPending.remove(requestId);
    }
  }

  void _attachFiles(
    RTCDataChannel channel,
    String boundSession,
    int generation,
  ) {
    _files = channel;
    if (target)
      _fileReceiver = FileReceiverProtocol(
        boundSession,
        (request) => _core!.call(request),
      );
    bool live() =>
        _generation.isCurrent(generation) &&
        sessionId == boundSession &&
        _files == channel;
    channel.onMessage = (message) async {
      if (!live() || message.isBinary || message.text.length > 24000) return;
      try {
        final m = jsonDecode(message.text);
        if (m is! Map<String, dynamic>)
          throw StateError('Invalid file message');
        final id = m['id'];
        if (id is! String || !RegExp(r'^[A-Za-z0-9_-]{1,100}$').hasMatch(id))
          throw StateError('Invalid transfer ID');
        if (!target && m['t'] == 'ack') {
          if (m['offset'] is int && m['ok'] is bool)
            _fileSender?.acknowledge(id, m['offset'] as int, m['ok'] as bool);
          return;
        }
        if (!target || !_permits('file_transfer'))
          throw StateError('File transfer not authorized');
        if (m['t'] == 'offer') {
          if (fileOffer != null ||
              _fileReceiver?.transferId != null ||
              m['name'] is! String ||
              (m['name'] as String).length > 255 ||
              m['size'] is! int ||
              (m['size'] as int) < 0 ||
              (m['size'] as int) > 1073741824)
            throw StateError('Invalid file offer');
          _core!.call({
            'op': 'session_check',
            'session_id': boundSession,
            'capability': 'file_transfer',
          });
          fileOffer = {'id': id, 'name': m['name'], 'size': m['size']};
          notifyListeners();
        } else if (m['t'] == 'chunk') {
          final offset = _fileReceiver!.chunk(
            id: id,
            at: m['offset'] as int,
            data: m['data'] as String,
            sha256: m['sha256'] as String,
          );
          await channel.send(
            RTCDataChannelMessage(
              jsonEncode({'t': 'ack', 'id': id, 'offset': offset, 'ok': true}),
            ),
          );
        } else if (m['t'] == 'finish') {
          final size = _fileReceiver!.size;
          _fileReceiver!.finish(id: id, sha256: m['sha256'] as String);
          await channel.send(
            RTCDataChannelMessage(
              jsonEncode({
                't': 'ack',
                'id': id,
                'offset': size + 1,
                'ok': true,
              }),
            ),
          );
          fileStatus = 'File received and checksum verified';
          notifyListeners();
        } else {
          throw StateError('Unsupported file message');
        }
      } catch (e) {
        if (!live()) return;
        fileStatus = 'File transfer failed: $e';
        // Revoking the session removes any incomplete native file.
        end();
      }
    };
  }

  Future<void> answerFileOffer({
    required bool allow,
    required String offerId,
    required String offerSession,
    String directory = '',
    String filename = '',
  }) async {
    final offer = fileOffer;
    final channel = _files;
    final id = sessionId;
    final generation = _generation.current;
    if (!target ||
        offer == null ||
        offer['id'] != offerId ||
        id != offerSession ||
        channel == null ||
        id == null) return;
    fileOffer = null;
    try {
      if (allow)
        _fileReceiver!.begin(
          id: offer['id'] as String,
          directory: directory,
          filename: filename,
          length: offer['size'] as int,
        );
      if (!_generation.isCurrent(generation) || sessionId != id) return;
      await channel.send(
        RTCDataChannelMessage(
          jsonEncode({'t': 'ack', 'id': offer['id'], 'offset': 0, 'ok': allow}),
        ),
      );
      fileStatus = allow ? 'Receiving file' : 'File declined';
      notifyListeners();
    } catch (e) {
      fileStatus = 'Could not receive file: $e';
      end();
    }
  }

  Future<void> sendFile(String path) async {
    final channel = _files;
    final id = sessionId;
    final generation = _generation.current;
    if (target ||
        id == null ||
        channel == null ||
        !_permits('file_transfer') ||
        _fileSender != null) return;
    final sender = FileSenderProtocol((request) => _core!.call(request), (
      message,
    ) async {
      if (!_generation.isCurrent(generation) || sessionId != id)
        throw StateError('Session ended');
      await channel.send(RTCDataChannelMessage(jsonEncode(message)));
    });
    _fileSender = sender;
    fileStatus = 'Sending file';
    notifyListeners();
    try {
      await sender.transfer(path);
      if (_generation.isCurrent(generation)) {
        fileStatus = 'File sent and acknowledged';
        notifyListeners();
      }
    } catch (e) {
      if (_generation.isCurrent(generation)) {
        fileStatus = 'File transfer failed: $e';
        end();
      }
    } finally {
      if (identical(_fileSender, sender)) _fileSender = null;
    }
  }

  Future<void> sendClipboard() async {
    if (target || sessionId == null || !_permits('clipboard_text')) return;
    final boundSession = sessionId;
    final generation = _generation.current;
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!_generation.isCurrent(generation) || sessionId != boundSession) return;
    final value = data?.text;
    if (value == null || value.length > 2048) {
      error = 'Clipboard text is empty or exceeds 2048 characters';
      notifyListeners();
      return;
    }
    sendInput({'t': 'clipboard_text', 'text': value});
  }

  void sendInput(Map<String, dynamic> event) {
    final capability =
        event['t'] == 'clipboard_text' ? 'clipboard_text' : 'input';
    if (!target && sessionId != null && !_viewOnly && _permits(capability)) {
      final d = display;
      if (d != null && (event['t'] == 'mouse_move' || event['t'] == 'touch'))
        event = {...event, 'display': d};
      _channel?.send(RTCDataChannelMessage(jsonEncode(event)));
    }
  }

  void toggleMute() {
    muted = !muted;
    _remoteAudio?.enabled = !muted;
    notifyListeners();
  }

  /// Input `display` and the target's captured screen switch together.
  void selectDisplay(int? id) {
    display = id;
    if (id != null) _sendControl({'t': 'select_display', 'display': id});
    notifyListeners();
  }

  /// Target: index of the screen being captured, or null if unknown (then the primary is assumed).
  Future<int?> _currentDisplay() async {
    if (_targetDisplay != null || _captureSource == null) return _targetDisplay;
    try {
      final sources = await desktopCapturer.getSources(
        types: [SourceType.Screen],
      );
      final i = sources.indexWhere((s) => s.id == _captureSource);
      return i < 0 ? null : i;
    } catch (_) {
      return null;
    }
  }

  Future<void> _dropStream(MediaStream? stream) async {
    for (final track in stream?.getTracks() ?? <MediaStreamTrack>[]) {
      await track.stop();
    }
    await stream?.dispose();
  }

  /// Target: capture another screen and swap it into the live senders. The core's monitor id is
  /// the enumeration index; capturer sources are matched by the same index (shortcut: order is
  /// not guaranteed identical, and an index beyond the source list is refused). The new capture
  /// is acquired first, so a failure keeps the old one; the actual display is reported either way.
  Future<void> _switchCapture(int id, String session, int generation) async {
    final pc = _pc;
    bool live() =>
        _generation.isCurrent(generation) && sessionId == session && _pc == pc;
    if (_switching) {
      _pendingDisplay = id; // last request wins
      return;
    }
    final old = _capture;
    if (pc == null ||
        old == null ||
        _authPending ||
        !captureAuthorized(
          () => _core!.call({
            'op': 'session_check',
            'session_id': session,
            'capability': 'view',
          }),
        )) return;
    _switching = true;
    MediaStream? next;
    try {
      final sources = await desktopCapturer.getSources(
        types: [SourceType.Screen],
      );
      if (!live() || id >= sources.length) return;
      next = await navigator.mediaDevices.getDisplayMedia({
        'video': {
          'deviceId': {'exact': sources[id].id},
          'mandatory': {'frameRate': 30.0},
        },
        'audio': _audioAllowed(session),
      });
      if (!live() || _authPending) return;
      final senders = await pc.getSenders();
      for (final track in next.getTracks()) {
        track.enabled =
            !_authPending && (track.kind != 'audio' || _audioAllowed(session));
        RTCRtpSender? sender;
        for (final s in senders) {
          if (s.track?.kind == track.kind) {
            sender = s;
            break;
          }
        }
        if (sender == null) {
          await track.stop();
          continue;
        }
        await sender.replaceTrack(track);
      }
      if (!live()) return;
      _capture = next;
      next = null; // now owned by _capture
      _captureSource = sources[id].id;
      _targetDisplay = id;
      await _dropStream(old);
    } catch (e) {
      if (live()) {
        error = 'Could not switch monitor: $e';
        notifyListeners();
      }
    } finally {
      _switching = false;
      await _dropStream(next);
      final shown = await _currentDisplay();
      if (shown != null && live()) _sendControl({'t': 'display', 'display': shown});
      final again = _pendingDisplay;
      _pendingDisplay = null;
      if (again != null && again != shown && live())
        unawaited(_switchCapture(again, session, generation));
    }
  }

  void sendSecureAttention() {
    notice = null;
    sendInput({'t': 'secure_attention'});
  }

  /// Types text on the remote device.
  void sendText(String text) {
    final valid = validRemoteText(text);
    if (valid == null) {
      error = 'Text is empty, too long, or has control characters';
      notifyListeners();
      return;
    }
    sendInput({'t': 'text', 'text': valid});
  }

  void deny() {
    if (_authPending && incomingSession != null && incomingSession == sessionId) {
      end();
      return;
    }
    if (incomingSession != null)
      _send({'type': 'deny', 'sessionId': incomingSession});
    incomingSession = null;
    incomingController = null;
    notifyListeners();
  }

  void _send(Map<String, dynamic> message) => _socket?.add(jsonEncode(message));
  @override
  Future<void> end() async {
    final wasDirect = _direct;
    if (!wasDirect && sessionId != null) {
      try {
        _send({'type': 'end', 'sessionId': sessionId});
      } catch (_) {}
    }
    _direct = false;
    _directSend = null;
    _revoke();
    if (wasDirect) await onDirectEnded?.call();
    status = connected ? 'Online' : 'Disconnected';
    notifyListeners();
  }

  void _revoke() {
    _generation.invalidate();
    try {
      onSessionEnded?.call();
    } catch (_) {}
    _requestPending = false;
    _authTimer?.cancel();
    _resumeTimer?.cancel();
    _authPending = false;
    _gate = null;
    _failCounted = _viaPassword = _relayOnly = false;
    _window = AuthWindow();
    _enrollGate = null;
    _enrollChallenge = null;
    _enrollPreset = null;
    _serverLogin = null;
    _clientLogin = null;
    _binding = null;
    _requestTarget = null;
    _answers = 0;
    enrollRequested = false;
    _remoteFp = null;
    _controllerKey = null;
    _resumeSession = null;
    _peerDown = false;
    _controllerId = null;
    monitors = [];
    display = null;
    notice = null;
    trustStatus = null;
    _dropSecret();
    _expiry?.cancel();
    _expiry = null;
    _iceRetry?.cancel();
    _iceRetry = null;
    _iceAttempt = 0;
    if (Platform.isAndroid) {
      // Each call is independent; revokeSession (target only) also stops SessionIndicatorService.
      for (final method in [
        'stopCaptureService',
        if (target) 'revokeSession',
      ]) {
        _android.invokeMethod(method).catchError((Object e) {
          onAudit?.call('$method failed: $e');
        });
      }
    }
    _captureServiceOn = false;
    _accepting = false;
    _startingPeer = false;
    _viewOnly = false;
    _videoSender = null;
    for (final pending in _tvPending.values) {
      if (!pending.isCompleted)
        pending.completeError(StateError('Session ended'));
    }
    _tvPending.clear();
    _tvLastReceivedId = 0;
    _tvSent.clear();
    _tvReceived.clear();
    _tv?.close();
    _tv = null;
    _fileSender?.cancel();
    _fileSender = null;
    _files?.close();
    _files = null;
    _fileReceiver = null;
    fileOffer = null;
    _channel?.close();
    _channel = null;
    try {
      _pc?.close();
      for (final track in _capture?.getTracks() ?? <MediaStreamTrack>[]) {
        track.stop();
      }
      _capture?.dispose();
    } catch (e) {
      onAudit?.call('Media teardown failed: $e');
    }
    _pc = null;
    _capture = null;
    _remoteAudio = null;
    muted = false;
    _switching = false;
    _pendingDisplay = null;
    _targetDisplay = null;
    if (rendererReady) renderer.srcObject = null;
    _remoteDescriptionSet = false;
    _peerReady = false;
    _queuedSignals.clear();
    _pendingIce.clear();
    _acceptedPreset = null;
    _directPermissions = {};
    _captureSource = null;
    _desktopInputSafe = false;
    if (target && sessionId != null) {
      try {
        _core?.call({'op': 'session_revoke', 'session_id': sessionId});
      } catch (_) {}
    }
    sessionId = null;
    target = false;
  }

  void _closed({bool retry = false}) {
    _socket = null;
    deviceId = null;
    incomingSession = null;
    incomingController = null;
    // An accepted relay session survives the drop: reconnect, re-auth, then resume.
    final keep = retry &&
        _endpoint != null &&
        !_direct &&
        sessionId != null &&
        _acceptedPreset != null;
    if (keep) {
      _resumeSession = sessionId;
      _resumeTimer?.cancel();
      _resumeTimer = Timer(const Duration(seconds: 60), () {
        if (_resumeSession == null) return;
        error = 'Session could not be resumed';
        end();
      });
    } else {
      _revoke();
    }
    status = keep ? 'Reconnecting…' : 'Disconnected';
    if (retry && _endpoint != null) _scheduleReconnect();
    notifyListeners();
  }

  void _scheduleReconnect() {
    final delay = reconnectDelay(_attempt++);
    if (delay == null) {
      _reconnecting = false;
      _endpoint = null;
      error = 'Gave up reconnecting to the signaling server';
      status = 'Disconnected';
      return;
    }
    _reconnecting = true;
    status = 'Reconnecting…';
    _retry?.cancel();
    _retry = Timer(delay, () => connect(_endpoint!));
  }

  void _scheduleIceRestart() {
    if (_iceRetry != null) return;
    final delay = reconnectDelay(_iceAttempt++);
    if (delay == null) {
      error = 'Connection lost';
      end();
      return;
    }
    status = 'Reconnecting…';
    final generation = _generation.current;
    // _iceRetry stays set until connected or given up, so `reconnecting` never flickers.
    _iceRetry = Timer(delay, () async {
      final pc = _pc;
      if (!_generation.isCurrent(generation) || pc == null) return;
      try {
        await pc.restartIce();
        final offer = await pc.createOffer();
        if (!_generation.isCurrent(generation) || _pc != pc) return;
        await pc.setLocalDescription(offer);
        if (!_generation.isCurrent(generation) || _pc != pc) return;
        _signal('offer', {'sdp': offer.sdp, 'type': offer.type});
      } catch (_) {}
      if (_generation.isCurrent(generation) && _pc == pc && _iceRetry != null) {
        _iceRetry = null;
        _scheduleIceRestart(); // cancelled by 'connected' state
      }
    });
    notifyListeners();
  }

  /// User cancel: stop retrying and end any session.
  void cancelReconnect() {
    if (_reconnecting) {
      _retry?.cancel();
      _endpoint = null;
      _reconnecting = false;
    }
    if (sessionId != null) {
      end();
    } else {
      status = 'Disconnected';
      notifyListeners();
    }
  }

  Future<void> disconnect() async {
    _retry?.cancel();
    _endpoint = null;
    _reconnecting = false;
    end();
    await _socket?.close();
    _closed();
  }

  @override
  void dispose() {
    _retry?.cancel();
    _endpoint = null;
    _reconnecting = false;
    _socket?.close();
    _revoke();
    if (rendererReady) renderer.dispose();
    super.dispose();
  }
}
