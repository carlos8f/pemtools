pemtools = require('./');
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

describe('test', function () {
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
      var failed = pemtools(pem, null, 'totally awesome');
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
      assert.equal(pem.pubkey.publicExponent.toString('hex'), '010001');
      var encoded = pemtools.writeSSHPubkey(pem.pubkey);
      assert.deepEqual(encoded, pubkey);
      done();
    });
  });
  it('private key', function (done) {
    fs.readFile('test.pem', {encoding: 'ascii'}, function (err, privateKey) {
      assert.ifError(err);
      pem = pemtools(privateKey, null, 'this is so super cool');
      assert.equal(pem.tag, 'RSA PRIVATE KEY');
      assert.equal(pem.privateKey.version, 'v1');
      assert.equal(pem.privateKey.modulus.toString('hex'), '00cf9f910fbd0d19cf793f6e48e6caba1dd472bce658d41d73ecd4703649c133f377e9c5338283b6d2baa51789333f5c8a61574b53993311a581248449c2407156c2d893f7d557a3d71fa2b454c1e482562d4588dc73e40d2a168d3c49af3b7bc2004f99a62fc9e6abd421ed6da8d8aeb44c753698a51cfaf90c6f2d780d2468faae1b88c121367220360a05c76a0e7ff66118a6043ba53d3413b33ee973335419da8cb4408a9a04ec55bae155dfda7fdaa9d6db0fc1e054a688dc4b5fccb671fb388946ea5488d57faf727b64dfc28a530e607a1b6f0949bb7f44379dda5908dad53395d2a2f0f6e744c3b8b827e1a1f2deacce82d2f5873ef1cdc2c1ca162611');
      assert.equal(pem.privateKey.publicExponent.toString('hex'), '010001');
      assert.equal(pem.privateKey.privateExponent.toString('hex'), '00bb51c396e782025f658d0cfb48fe6e9cab2839b5b93ee6b3c860823cf89e0f39025f2f4421e4a3f5cbdf5734b9bfd8c620bc99817b1ed034fa26f0137be6985b26c02fffd1c39856667c6d266b28b74ef8d95b794a35de8ab27e0a7e9052a27d8dba436de47fcc560ab5f1789675a86992f1cda83a8fc2ff1f70cf1d18fe5896f0885f707183090f189fed62e37aa5c9596badf5d445ee259561062fca17ea4d3a7c9a9fd45c0ad4854fc2e818793d90ea902bd0ba8e04592a01952380965e2be36ee129ed3abab427870206038f724f595fb3e0a544f4f9bc59c8101760929cc07a6e9b5d32ae01ba67f456551974fd8e1f8be71ea2825f589546c0bba28261');
      assert.equal(pem.privateKey.prime1.toString('hex'), '00ff276613a16daa00418fe4f64135741a6f1182a1174f8440441c60bbd24c4c30d980ad23e3f8dac99c528f4e44563070b3bac52892b06d1f895fe591dc688144c4265d28ac589a049287325a9b181c12522a4720225e10426df1a1bae08f24b2b4bd2c62a46bc7afd54627e0496af9db6dbda7a04210ea8b0e1e6c93c639082b');
      assert.equal(pem.privateKey.prime2.toString('hex'), '00d04fd1a8ae3792cf475df148839273827293deb23538a6db579441337b1d75f6a156797f7070e26f68ca107688c5c837ab14f51923354ffec765adffffa3f2d9b536deb430b4c990c9303d84dba8800fb552b791ca83b1bcbdf8af20f179133d58821f7f641e43ce6a49a69a3e7a371383831399200a1e8c37b18e675cf850b3');
      assert.equal(pem.privateKey.exponent1.toString('hex'), '05bc1bf63afd9d018e77ae7cbe70762095f87dc8231efd68f85eeee9a9cb5f3705dc7787c3faf6e7eb248be605712e7b89fe9ba9d2ca3659ac1bc4ac27990db6bef5e1c8253f848eafc06c284f2e168b6edf5663e981d5b9b880e2d2b173662ec2133269312adefd1bbd0cee64980bef9ba2d49eac7d76d8134429ca947cf9ab');
      assert.equal(pem.privateKey.exponent2.toString('hex'), '0f6dba039a53b765eecd406fb47f065b250d5ab32c49f3e1cf0cc5ff8020e079d1dd4bc66a9791cdda9f0cb51ad03b521433cb2b7f761564b3740e7d257c0922a2cf5b93510032e5ac610c4d68cf841ca5bb68a93dac9f5f715a97ee02b48afe422df11348610d789e5ab2223e7a62d5e929ae2beb3994a5a2025e9fbd3d0f0d');
      assert.equal(pem.privateKey.coefficient.toString('hex'), '00e75b06065b8d04a19ddc9e20e7872a0484ebb7634261331e33ec16d70eb26191a6dfb477950f57b387ca0e86d9d7cc5bdab98e142198588aca575cbcc81163beb83148f4050b8aa004acfd886967d73af2c9f3b2be53a8b80285cadb3e3f312cf5823bebb8a5c5b4832a58e1303b8c25092537267a76e548384e213c81beb2e8');
      done();
    });
  });
});
