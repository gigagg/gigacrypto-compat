## gigacrypto

GigaCrypto is a crypto library to crypt data for the https://giga.gg service.

## Installation

Using npm:

```sh
$ npm i --save gigacrypto
```


## Usage


```typescrypt

// 1) when the user subscribe, generate and export a keychain.
//    Then on the POST /rest/subscribe, you must include the exported keychain.

import { Keychain } from 'gigacrypto';

const keychain = await Keychain.generate('TheUserPasswordHere');
const exportedKeychain = await keychain.export(/* true: will export the masterKey and the password */);

// 2) On user login, import the keychain from the server
//    /rest/login and /rest/me will contain all the needed infos.

import { Keychain } from 'gigacrypto';

const keychain = await Keychain.import(keychainInfos, 'TheUserPasswordHere');
// If there is an error in the process, the user should not be allowed to log in.

// 3) Use the keychain to get the nodeKey and download files :

const nodeKey = keychain.getUnencryptedNodeKey();
// Remember to correctly url encode if it is part of a url.


```
