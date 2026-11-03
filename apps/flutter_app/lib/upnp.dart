import 'dart:async';
import 'dart:convert';
import 'dart:io';

const _igd = 'urn:schemas-upnp-org:device:InternetGatewayDevice:1';
const _services = [
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];

/// shortcut: regex XML parsing, enough for IGD replies; use a parser if devices misbehave.
String? ssdpLocation(String response) => RegExp(
      r'^location:\s*(\S+)',
      caseSensitive: false,
      multiLine: true,
    ).firstMatch(response)?.group(1);

/// Returns (serviceType, absolute control URL) of the first WAN connection service.
(String, Uri)? parseControl(String xml, Uri base) {
  for (final m in RegExp(
    r'<service>(.*?)</service>',
    dotAll: true,
  ).allMatches(xml)) {
    final s = m.group(1)!;
    final type = RegExp(
      r'<serviceType>\s*(.*?)\s*</serviceType>',
    ).firstMatch(s)?.group(1);
    final url = RegExp(
      r'<controlURL>\s*(.*?)\s*</controlURL>',
    ).firstMatch(s)?.group(1);
    if (type != null && url != null && _services.contains(type)) {
      return (type, base.resolve(url));
    }
  }
  return null;
}

String soapEnvelope(String type, String action, Map<String, String> args) =>
    '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
    '<u:$action xmlns:u="$type">'
    '${args.entries.map((e) => '<${e.key}>${e.value}</${e.key}>').join()}'
    '</u:$action></s:Body></s:Envelope>';

String? parseExternalIp(String xml) => RegExp(
      r'<NewExternalIPAddress>\s*(.*?)\s*</NewExternalIPAddress>',
    ).firstMatch(xml)?.group(1);

class UpnpMapping {
  UpnpMapping(this._type, this._control, this.port, this.externalIp);
  final String _type;
  final Uri _control;
  final int port;
  final String? externalIp;
  String? get external => externalIp == null ? null : '$externalIp:$port';

  static Future<String> _soap(
    Uri control,
    String type,
    String action,
    Map<String, String> args,
  ) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    try {
      final req = await client.postUrl(control);
      req.headers.set('Content-Type', 'text/xml; charset="utf-8"');
      req.headers.set('SOAPAction', '"$type#$action"');
      req.add(utf8.encode(soapEnvelope(type, action, args)));
      final res = await req.close().timeout(const Duration(seconds: 5));
      final body = await utf8.decodeStream(res);
      if (res.statusCode != 200) {
        throw HttpException('UPnP $action failed: ${res.statusCode}');
      }
      return body;
    } finally {
      client.close(force: true);
    }
  }

  static Future<Uri?> _discover() async {
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
    try {
      final done = Completer<Uri?>();
      socket.listen((e) {
        if (e != RawSocketEvent.read || done.isCompleted) return;
        final d = socket.receive();
        final loc = d == null
            ? null
            : ssdpLocation(utf8.decode(d.data, allowMalformed: true));
        final uri = loc == null ? null : Uri.tryParse(loc);
        if (uri != null && uri.scheme == 'http') done.complete(uri);
      });
      socket.send(
        utf8.encode(
          'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: $_igd\r\n\r\n',
        ),
        InternetAddress('239.255.255.250'),
        1900,
      );
      return await done.future.timeout(
        const Duration(seconds: 4),
        onTimeout: () => null,
      );
    } finally {
      socket.close();
    }
  }

  static Future<String?> _localIp(Uri gateway) async {
    final prefix = gateway.host.split('.').take(3).join('.');
    String? fallback;
    for (final i in await NetworkInterface.list(
      type: InternetAddressType.IPv4,
    )) {
      for (final a in i.addresses) {
        if (a.address.startsWith('$prefix.')) return a.address;
        fallback ??= a.address;
      }
    }
    return fallback;
  }

  /// Maps TCP [port] to the same external port. Returns null if no IGD answers.
  static Future<UpnpMapping?> map(int port) async {
    final location = await _discover();
    if (location == null) return null;
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 4);
    String xml;
    try {
      final res = await (await client.getUrl(
        location,
      ))
          .close()
          .timeout(const Duration(seconds: 5));
      xml = await utf8.decodeStream(res);
    } finally {
      client.close(force: true);
    }
    final control = parseControl(xml, location);
    final local = await _localIp(location);
    if (control == null || local == null) return null;
    await _soap(control.$2, control.$1, 'AddPortMapping', {
      'NewRemoteHost': '',
      'NewExternalPort': '$port',
      'NewProtocol': 'TCP',
      'NewInternalPort': '$port',
      'NewInternalClient': local,
      'NewEnabled': '1',
      'NewPortMappingDescription': 'RemoteLink',
      'NewLeaseDuration': '0',
    });
    String? ip;
    try {
      ip = parseExternalIp(
        await _soap(control.$2, control.$1, 'GetExternalIPAddress', {}),
      );
    } catch (_) {}
    return UpnpMapping(control.$1, control.$2, port, ip);
  }

  Future<void> remove() => _soap(_control, _type, 'DeletePortMapping', {
        'NewRemoteHost': '',
        'NewExternalPort': '$port',
        'NewProtocol': 'TCP',
      });
}
