codec = require('./');
assert = require('assert');
fs = require('fs');
path = require('path');
crypto = require('crypto');
rimraf = require('rimraf');
request = require('request');
 
tmpDir = path.join(require('os').tmpDir(), require('idgen')());
 
fs.mkdirSync(tmpDir);
if (!process.env.DEBUG) {
  process.on('exit', function () {
    rimraf.sync(tmpDir);
  });
}
else console.log('tmpDir', tmpDir);

describe('tests', function () {
  var p = path.join(tmpDir, 'alice.jpg')
    , pem, buf = Buffer('')
 
  it('stream fixture', function (done) {
    request({encoding: null, uri: 'https://raw.githubusercontent.com/carlos8f/node-buffet/master/test/files/folder/Alice-white-rabbit.jpg'})
      .pipe(fs.createWriteStream(p))
      .on('finish', done);
  });
  it('read stream fixture', function (done) {
    fs.createReadStream(p)
      .on('data', function (data) {
        buf = Buffer.concat([buf, data]);
      })
      .pipe(crypto.createHash('sha1'))
      .on('data', function (data) {
        assert.equal(data.toString('hex'), '2bce2ffc40e0d90afe577a76db5db4290c48ddf4');
        done();
      });
  });

  it('convert to pem', function () {
    pem = codec.encode(buf, {tag: 'COOL IMAGE'});
    assert.equal(crypto.createHash('sha1').update(pem).digest('hex'), 'dd8c857178055695f1da6f624f513464e5178af2');
  });

  it('convert to buffer', function () {
    var back = codec.decode(pem);
    assert.deepEqual(back, buf);
    assert.equal(crypto.createHash('sha1').update(back).digest('hex'), '2bce2ffc40e0d90afe577a76db5db4290c48ddf4');
  });

  it('converts to encrypted pem', function () {
    pem = codec.encode(buf, {passphrase: 'totally secret', tag: 'COOL SECRET IMAGE'});
    assert(pem.match(/DEK-Info: /));
  });

  it('decrypts', function () {
    assert.throws(function () {
      codec.decode(pem, 'totally awesome');
    });
    var back = codec.decode(pem, 'totally secret');
    assert.deepEqual(back, buf);
    assert.equal(crypto.createHash('sha1').update(back).digest('hex'), '2bce2ffc40e0d90afe577a76db5db4290c48ddf4');
  });
});
