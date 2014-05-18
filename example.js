var pemtools = require('./');
var fs = require('fs');
var str = fs.readFileSync('example.pem', {encoding: 'ascii'});
var pem = pemtools(str, null, '1234');
console.log(pem.privateKey);
