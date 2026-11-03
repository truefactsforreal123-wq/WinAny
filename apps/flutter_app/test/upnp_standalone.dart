import '../lib/upnp.dart';

void main() {
  assert(
    ssdpLocation(
            'HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/d.xml\r\nST: x\r\n\r\n') ==
        'http://192.168.1.1:5000/d.xml',
  );
  assert(ssdpLocation('HTTP/1.1 200 OK\r\n\r\n') == null);
  const xml = '<root><device><serviceList>'
      '<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>'
      '<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>'
      '</serviceList></device></root>';
  final c = parseControl(xml, Uri.parse('http://192.168.1.1:5000/d.xml'))!;
  assert(c.$1.endsWith('WANIPConnection:1'));
  assert(c.$2.toString() == 'http://192.168.1.1:5000/ctl/IPConn');
  assert(parseControl('<root/>', Uri.parse('http://x/')) == null);
  assert(
    parseExternalIp(
          '<s:Body><u:R><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:R></s:Body>',
        ) ==
        '203.0.113.7',
  );
  final env = soapEnvelope('T', 'AddPortMapping', {'NewExternalPort': '4443'});
  assert(env.contains(
      '<u:AddPortMapping xmlns:u="T"><NewExternalPort>4443</NewExternalPort></u:AddPortMapping>'));
  print('upnp ok');
}
