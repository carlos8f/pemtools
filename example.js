var pemtools = require('./');
var fs = require('fs');
var str = fs.readFileSync('test.pem', {encoding: 'ascii'});
var pem = pemtools(str, null, 'this is so super cool');
console.log(pem.privateKey);
