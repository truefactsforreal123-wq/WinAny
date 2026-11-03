const crypto = require('node:crypto');
const [op, ...args] = process.argv.slice(2);
const b = x => Buffer.from(x, 'base64');
if (op === 'generate') {
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ed25519');
  console.log(JSON.stringify({private: privateKey.export({format:'der',type:'pkcs8'}).toString('base64'), public: publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')}));
} else if (op === 'hash') console.log(crypto.createHash('sha256').update(b(args[0])).digest('base64'));
else if (op === 'sign') console.log(crypto.sign(null,b(args[1]),crypto.createPrivateKey({key:b(args[0]),format:'der',type:'pkcs8'})).toString('base64'));
else if (op === 'verify') {
 const prefix = Buffer.from('302a300506032b6570032100','hex');
 console.log(crypto.verify(null,b(args[1]),crypto.createPublicKey({key:Buffer.concat([prefix,b(args[0])]),format:'der',type:'spki'}),b(args[2])));
} else if (op === 'cert') console.log(crypto.createHash('sha256').update(new crypto.X509Certificate(require('node:fs').readFileSync(args[0])).raw).digest('hex'));
