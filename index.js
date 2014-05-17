var crypto = require('crypto');

exports.decode = function (pem, passphrase) {
  pem = pem.toString('ascii');
  var dekInfo = pem.match(/DEK-Info: ([^,]+),([0-9A-F]+)/i);
  if (dekInfo) {
    if (typeof passphrase === 'undefined')
      throw new Error('PEM is encrypted but no passphrase given');
    var algorithm = dekInfo[1].toLowerCase();
    var salt = Buffer(dekInfo[2], 'hex');
    var keyLength = (function (algorithm) {
      switch (algorithm) {
        case 'aes-128-cbc': return 128;
        case 'aes-192-cbc': return 192;
        case 'aes-256-cbc': return 256;
        case 'bf-cbc': return 256;
        case 'cast-cbc': return 128;
        case 'des-cbc': return 64;
        case 'desx-cbc': return 184;
        case 'des-ede-cbc': return 128;
        case 'des-ede3-cbc': return 192;
        case 'idea-cbc': return 128;
        case 'rc2-cbc': return 256;
        case 'rc5-cbc': return 128;
        default: return 512;
      }
    })(algorithm);
    var key = crypto.pbkdf2Sync(passphrase, salt, 1, keyLength);
    var decipher = crypto.createDecipher(algorithm, key, salt);
    pem = pem
      .replace(/Proc-Type: .*\s*/, '')
      .replace(/DEK-Info: .*\s*/, '');
  }
  var buf = Buffer(
    pem
      .toString('ascii')
      .replace(/.*\-\-\-\-\-BEGIN.*\-\-\-\-\-\s*/, '')
      .replace(/\r?\n\-\-\-\-\-END.*\-\-\-\-\-.*/, '')
      .replace(/\s*/g, '')
    , 'base64');
  if (dekInfo) {
    var buf1 = decipher.update(buf);
    buf = Buffer.concat([buf1, decipher.final()]);
  }
  return buf;
};

/**
 * Options:
 *
 * - passphrase: encrypt PEM using passphrase
 * - algorithm: cipher algorithm to use (default: aes-256-cbc)
 * - tag: identifying string for boundary, i.e. "PRIVATE KEY"
 */
exports.encode = function (buf, options) {
  options || (options = {});
  var dekInfo = '';
  if (options.passphrase) {
    var passphrase = options.passphrase.toString();
    var algorithm = options.algorithm
      ? options.algorithm.toLowerCase()
      : 'aes-256-cbc';
    var salt = crypto.randomBytes(8);
    var dekInfo = ('Proc-Type: 4,ENCRYPTED\nDEK-Info: '
      + (algorithm.toUpperCase())
      + ','
      + (salt.toString('hex').toUpperCase())
      + '\n\n');
    var keyLength = (function (algorithm) {
      switch (algorithm) {
        case 'aes-128-cbc': return 128;
        case 'aes-192-cbc': return 192;
        case 'aes-256-cbc': return 256;
        case 'bf-cbc': return 256;
        case 'cast-cbc': return 128;
        case 'des-cbc': return 64;
        case 'desx-cbc': return 184;
        case 'des-ede-cbc': return 128;
        case 'des-ede3-cbc': return 192;
        case 'idea-cbc': return 128;
        case 'rc2-cbc': return 256;
        case 'rc5-cbc': return 128;
        default: return 512;
      }
    })(algorithm);
    var key = crypto.pbkdf2Sync(passphrase, salt, 1, keyLength);
    var cipher = crypto.createCipher(algorithm, key, salt);
    var buf1 = cipher.update(buf);
    buf = Buffer.concat([buf1, cipher.final()]);
  }
  return (
    '-----BEGIN' + (options.tag ? ' ' + options.tag : '') + '-----\n'
    + dekInfo
    + Buffer(buf)
      .toString('base64')
      .match(/.{1,64}/g)
      .join('\n')
    + '\n-----END' + (options.tag ? ' ' + options.tag : '') + '-----');
};
