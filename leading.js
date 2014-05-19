var exec = require('child_process').exec
  , idgen = require('idgen')
  , assert = require('assert')
  , path = require('path')
  , tmpDir = require('os').tmpDir()
  , stats = {}
  , f

;(function doNext () {
  f = path.join(tmpDir, idgen());
  exec('ssh-keygen -f ' + f + " -P ''", function (err, stdout, stderr) {
    assert.ifError(err);
    exec('openssl rsa -in ' + f + ' -text -noout', function (err, stdout, stderr) {
      assert.ifError(err);
      var out = '';
      var lines = stdout.toString().split(/\r?\n/);
      var header;
      for (var idx = 0; idx < lines.length; idx++) {
        var line = lines[idx];
        if (line.match(/^\s+/)) {
          var numMatch = line.match(/^\s+([0-9]{2})/);
          if (numMatch) {
            if (!header) continue;
            var word = numMatch[1];
            if (!stats[header]) stats[header] = {};
            if (!stats[header][word]) stats[header][word] = 0;
            stats[header][word]++;
          }
        }
        else header = line.replace(/\:.*/, '');
      }
      exec("rm -f '" + f + "' '" + f + ".pub'", function (err, stdout, stderr) {
        assert.ifError(err);
        doNext();
      });
    });
  });
})();

process.on('SIGINT', function () {
  console.log(stats);
  exec("rm -f '" + f + "' '" + f + ".pub'", function (err, stdout, stderr) {
    process.exit();
  });
});
