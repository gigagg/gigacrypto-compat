global.chai = require('chai');
global.expect = global.chai.expect;

const c = require('@peculiar/webcrypto');
const enc = require('text-encoding');

global.crypto = new c.Crypto();
global.TextEncoder = enc.TextEncoder;


global.Buffer = global.Buffer || require('buffer').Buffer;
if (typeof btoa === 'undefined') {
  global.btoa = function (str) {
    return new Buffer(str, 'binary').toString('base64');
  };
}

if (typeof atob === 'undefined') {
  global.atob = function (b64Encoded) {
    return new Buffer(b64Encoded, 'base64').toString('binary');
  };
}

if (typeof localStorage === 'undefined') {
  global.localStorageImp = {};
  global.localStorage = {
    setItem: (key, value) => {
      global.localStorageImp[key] = value;
    },
    getItem: (key) => {
      return global.localStorageImp[key];
    }
  }
}
