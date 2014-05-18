var crypto = require('crypto')
  , sshKeyToPEM = require('ssh-key-to-pem')
  , asn = require('asn1.js')
  , EVP_BytesToKey = require('EVP_BytesToKey')

// constructor
module.exports = exports = function (input, tag, passphrase) {
  return new PEM(input, tag, passphrase);
};

exports.RSAPrivateKey = asn.define('RSAPrivateKey', function () {
  this.seq().obj(
    this.key('version').int({
      0: 'v1',
      1: 'v2',
      2: 'v3'
    }),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int(),
    this.key('otherPrimeInfos').optional()
  );
});

exports.serialize = function (buffers) {
  var parts = []
    , idx = 0
  buffers.forEach(function (part) {
    var len = Buffer(4);
    if (typeof part === 'string') part = Buffer(part);
    len.writeUInt32BE(part.length, 0);
    parts.push(len);
    idx += len.length;
    parts.push(part);
    idx += part.length;
  });
  return Buffer.concat(parts);
};

exports.unserialize = function (buf) {
  var parts = [];
  var l = buf.length, idx = 0;
  while (idx < l) {
    var dlen = buf.readUInt32BE(idx);
    idx += 4;
    var start = idx;
    var end = start + dlen;
    var part = buf.slice(start, end);
    parts.push(part);
    idx += part.length;
  }
  return parts;
};

exports.writeSSHPubkey = function (opts) {
  opts || (opts = {});
  return (opts.type || 'ssh-rsa')
    + ' '
    + (exports.serialize([
      opts.type || 'ssh-rsa',
      opts.exponent,
      opts.modulus
    ]).toString('base64'))
    + ' '
    + opts.comment
    + '\n';
};

exports.readSSHPubkey = function (str) {
  var input = str.trim().split(' ');
  var buf = Buffer(input[1].trim(), 'base64');
  var parts = exports.unserialize(buf);
  if (parts.length != 3) throw new Error('invalid pubkey field count: ' + parts.length);
  return {
    type: parts[0].toString('ascii'),
    modulus: parts[2],
    exponent: parts[1],
    bits: (parts[2].length - 1) * 8,
    comment: input[2] ? input.slice(2).join(' ') : ''
  };
};

function PEM (input, tag, passphrase) {
  if (Buffer.isBuffer(input)) {
    this.encode(input, tag, passphrase);
  }
  else if (input) {
    input = input.toString('ascii').trim();
    if (input.indexOf('ssh-') === 0) {
      this.pubkey = exports.readSSHPubkey(input);
      this.sshPubkey = input;
      input = sshKeyToPEM(input);
    }
    else if (input.indexOf('-----BEGIN PUBLIC KEY-----') === 0) {
      this.sshPubkey = sshKeyToPEM.pemToRsaSSHKey(input);
      this.pubkey = exports.readSSHPubkey(this.sshPubkey);
    }
    this.decode(input, passphrase);
    if (input.indexOf('-----BEGIN RSA PRIVATE KEY-----') === 0) {
      this.privateKey = exports.RSAPrivateKey.decode(this.buf, 'der');
    }
  }
}

PEM.prototype.toString = function () {
  return this.pem;
};

PEM.prototype.toBuffer = function () {
  return this.buf;
};

PEM.prototype.toSSH = function () {
  if (!this.sshPubkey) throw new Error('not a pubkey!');
  return this.sshPubkey;
};

// decode PEM string -> buffer
PEM.prototype.decode = function (str, passphrase) {
  // store input
  if (str) this.pem = str.toString('ascii').trim();
  var pem = this.pem;
  var match = pem.match(/\-\-\-\-\-\s*BEGIN\s*([^\-]*)\-\-\-\-\-\r?\n/);
  if (!match) throw new Error('no start tag found in PEM');
  this.tag = match[1].trim();
  // parse DEK-Info
  var dekInfo = pem.match(/DEK-Info: ([^,]+),([0-9A-F]+)/i);
  if (dekInfo) {
    if (typeof passphrase !== 'string')
      throw new Error('PEM is encrypted but no passphrase given');
    var algorithm = dekInfo[1].toLowerCase();
    var salt = Buffer(dekInfo[2], 'hex');
    var key = EVP_BytesToKey(dekInfo[1], passphrase, salt);
    var decipher = crypto.createDecipher(algorithm, key, salt);
    pem = pem
      .replace(/Proc-Type: .*\s*/, '')
      .replace(/DEK-Info: .*\s*/, '');
  }

  // strip to base64 data
  this.buf = Buffer(
    pem
      .replace(/.*\-\-\-\-\-BEGIN.*\-\-\-\-\-\s*/, '')
      .replace(/\r?\n\-\-\-\-\-END.*\-\-\-\-\-.*/, '')
      .replace(/\s*/g, '')
    , 'base64');

  // decrypt if needed
  if (dekInfo) {
    var buf1 = decipher.update(this.buf);
    this.buf = Buffer.concat([buf1, decipher.final()]);
  }
  return this.buf;
};

exports.keyBytes = {
  'DES-EDE3-CBC': 24,
  'DES-CBC': 8,
  'AES-128-CBC': 16,
  'AES-192-CBC': 24,
  'AES-256-CBC': 32
};

// encode buffer -> PEM string
PEM.prototype.encode = function (buf, tag, passphrase) {
  if (buf) this.buf = buf;
  if (tag) this.tag = tag;
  var dekInfo = '';
  if (passphrase) {
    var passphrase = passphrase.toString();
    var algorithm = 'aes-256-cbc';
    var salt = crypto.randomBytes(8);
    var dekInfo = ('Proc-Type: 4,ENCRYPTED\nDEK-Info: '
      + (algorithm.toUpperCase())
      + ','
      + (salt.toString('hex').toUpperCase())
      + '\n\n');
    var key = EVP_BytesToKey(algorithm.toUpperCase(), passphrase, salt);
    var cipher = crypto.createCipher(algorithm, key, salt);
    var buf1 = cipher.update(buf);
    buf = Buffer.concat([buf1, cipher.final()]);
  }
  this.pem = (
    '-----BEGIN' + (tag ? ' ' + tag : '') + '-----\n'
    + dekInfo
    + Buffer(buf)
      .toString('base64')
      .match(/.{1,64}/g)
      .join('\n')
    + '\n-----END' + (tag ? ' ' + tag : '') + '-----');
  return this.pem;
};
