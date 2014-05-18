pemtools = require('./');
assert = require('assert');
fs = require('fs');
path = require('path');
crypto = require('crypto');
rimraf = require('rimraf');
request = require('request');
prompt = require('cli-prompt');
 
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
    pem = pemtools(buf, 'COOL IMAGE');
    assert.equal(pem.tag, 'COOL IMAGE');
    assert.equal(crypto.createHash('sha1').update(pem.toString()).digest('hex'), 'dd8c857178055695f1da6f624f513464e5178af2');
  });

  it('convert to buffer', function () {
    var back = pemtools(pem.toString());
    assert.deepEqual(back.toBuffer(), buf);
    assert.equal(crypto.createHash('sha1').update(back.toBuffer()).digest('hex'), '2bce2ffc40e0d90afe577a76db5db4290c48ddf4');
  });

  it('converts to encrypted pem', function () {
    pem = pemtools(buf, 'COOL SECRET IMAGE', 'totally secret');
    assert.equal(pem.tag, 'COOL SECRET IMAGE');
    assert(pem.toString().match(/DEK-Info: /));
  });

  it('decrypts', function () {
    assert.throws(function () {
      pemtools(pem, null, 'totally awesome');
    });
    var back = pemtools(pem.toString(), null, 'totally secret');
    assert.equal(back.tag, 'COOL SECRET IMAGE');
    assert.deepEqual(back.toBuffer(), buf);
    assert.equal(crypto.createHash('sha1').update(back.toBuffer()).digest('hex'), '2bce2ffc40e0d90afe577a76db5db4290c48ddf4');
  });
});

describe('ssh key', function () {
  it('public key', function (done) {
    fs.readFile('test.pub', {encoding: 'ascii'}, function (err, pubkey) {
      assert.ifError(err);
      pem = pemtools(pubkey);
      assert.equal(pem.tag, 'PUBLIC KEY');
      assert.equal(pem.pubkey.bits, 2048);
      assert.equal(pem.pubkey.modulus.toString('hex'), '00cf9f910fbd0d19cf793f6e48e6caba1dd472bce658d41d73ecd4703649c133f377e9c5338283b6d2baa51789333f5c8a61574b53993311a581248449c2407156c2d893f7d557a3d71fa2b454c1e482562d4588dc73e40d2a168d3c49af3b7bc2004f99a62fc9e6abd421ed6da8d8aeb44c753698a51cfaf90c6f2d780d2468faae1b88c121367220360a05c76a0e7ff66118a6043ba53d3413b33ee973335419da8cb4408a9a04ec55bae155dfda7fdaa9d6db0fc1e054a688dc4b5fccb671fb388946ea5488d57faf727b64dfc28a530e607a1b6f0949bb7f44379dda5908dad53395d2a2f0f6e744c3b8b827e1a1f2deacce82d2f5873ef1cdc2c1ca162611');
      assert.equal(pem.pubkey.exponent.toString('hex'), '010001');
      var encoded = pemtools.writeSSHPubkey(pem.pubkey);
      assert.deepEqual(encoded, pubkey);
      done();
    });
  });
});
