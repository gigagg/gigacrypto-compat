#!/bin/bash



cat << EOF > BigInteger.js
export const BigInteger = (function () { 'use strict';
if (typeof navigator === 'undefined') {
  var navigator = {};
}
if (typeof window === 'undefined') {
  var window = {};
}
EOF

curl http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js  >> BigInteger.js
echo                                                        >> BigInteger.js
echo '// JSBN2'                                             >> BigInteger.js
echo                                                        >> BigInteger.js
curl http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn2.js >> BigInteger.js
echo                                                        >> BigInteger.js
echo 'return BigInteger; })();'                               >> BigInteger.js

cat << EOF > RSAKey.js
import BigInteger from './BigInteger.js';
export const RSAKey = (function () { 'use strict';
if (typeof navigator === 'undefined') {
  var navigator = {};
}
if (typeof window === 'undefined') {
  var window = {};
}
EOF
curl http://www-cs-students.stanford.edu/~tjw/jsbn/base64.js>> RSAKey.js
curl http://www-cs-students.stanford.edu/~tjw/jsbn/prng4.js >> RSAKey.js
curl http://www-cs-students.stanford.edu/~tjw/jsbn/rng.js   >> RSAKey.js
echo                                                        >> RSAKey.js
curl http://www-cs-students.stanford.edu/~tjw/jsbn/rsa.js   >> RSAKey.js
echo                                                        >> RSAKey.js
echo '// RSA2'                                              >> RSAKey.js
echo                                                        >> RSAKey.js
curl http://www-cs-students.stanford.edu/~tjw/jsbn/rsa2.js  >> RSAKey.js
echo                                                        >> RSAKey.js
cat ./base64rsa.js                                          >> RSAKey.js
echo                                                        >> RSAKey.js
echo '// PEM'                                               >> RSAKey.js
echo                                                        >> RSAKey.js
cat ./pemrsa.js                                             >> RSAKey.js
echo 'return RSAKey; })();'                                   >> RSAKey.js
