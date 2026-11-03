import 'dart:convert';

import '../lib/tv_bridge.dart';

void check(Object? actual, Object? expected) {
  if (actual != expected) throw StateError('Expected $expected, got $actual');
}

String ssdp(String st) => 'HTTP/1.1 200 OK\r\nST: $st\r\n\r\n';

void main() {
  check(parseDiscovery(ascii.encode(ssdp('roku:ecp'))), 'roku');
  check(
    parseDiscovery(
      ascii.encode(ssdp('urn:samsung.com:device:RemoteControlReceiver:1')),
    ),
    'samsung',
  );
  check(
    parseDiscovery(
      ascii.encode(ssdp('urn:lge-com:service:webos-second-screen:1')),
    ),
    'lg',
  );
  const dial = 'urn:dial-multiscreen-org:device:dial:1';
  check(
    parseDiscovery(ascii.encode('${ssdp(dial)}SERVER: Linux UPnP/1.0 Amazon AFTMM')),
    'firetv',
  );
  check(parseDiscovery(ascii.encode('${ssdp(dial)}SERVER: Vizio')), 'vizio');
  check(parseDiscovery(ascii.encode(ssdp(dial))), null);
  check(parseDiscovery(ascii.encode(ssdp('upnp:rootdevice'))), null);
  check(
    parseDiscovery(ascii.encode('M-SEARCH * HTTP/1.1\r\nST: roku:ecp')),
    null,
  );
  final mdns = [
    0,
    0,
    0x84,
    0,
    0,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    17,
    ...ascii.encode('_androidtvremote2'),
    4,
    ...ascii.encode('_tcp'),
    5,
    ...ascii.encode('local'),
    0,
  ];
  check(parseDiscovery(mdns), 'androidtv');
  mdns[2] = 0; // a query, not an answer
  check(parseDiscovery(mdns), null);
  print('Discovery parse tests passed');
}
