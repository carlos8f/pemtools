exports.decode = function (pem) {
  return Buffer(
    pem
      .toString('ascii')
      .replace(/.*\-\-\-\-\-BEGIN .*\-\-\-\-\-\s*/, '')
      .replace(/\r?\n\-\-\-\-\-END .*\-\-\-\-\-.*/, '')
      .replace(/\s*/g, '')
    , 'base64');
};

exports.encode = function (buf, tag) {
  return (
    '-----BEGIN ' + tag + '-----\n'
    + Buffer(buf)
      .toString('base64')
      .match(/.{1,64}/g)
      .join('\n')
    + '\n-----END ' + tag + '-----');
};
