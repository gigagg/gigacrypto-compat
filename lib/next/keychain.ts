import { LockedKeychain } from '../lockedKeychain';
import { pbkdf2, toBase64, encryptAes, fromBase64, decryptAes } from '../utils';

export class Keychain {
  private readonly rsaLength = 1024;
  private readonly rsaExp = '10001';

  private password: string;

  private rsaKeys: CryptoKeyPair | null = null;
  private salt: Uint8Array | null = null;
  private masterKey: Uint8Array | null = null;
  private nodeKey: Uint8Array | null = null;

  private dekInfo: {
    iv: Uint8Array;
    salt: Uint8Array;
  } | null = null;

  private constructor(password: string) {
    this.password = password;
  }

  public static async generate(password: string) {
    const chain = new Keychain(password);
    await chain.doGenerate();
    return chain;
  }

  public static async import(
    password: string,
    k: LockedKeychain
  ): Promise<Keychain> {
    const chain = new Keychain(password);
    await chain.doImport(k);
    return chain;
  }

  private async doImport(k: LockedKeychain) {
    if (k.password != null) {
      this.password = k.password;
    }

    this.salt = fromBase64(k.salt);

    if (k.masterKey != null) {
      this.masterKey = fromBase64(k.masterKey);
    } else {
      this.masterKey = await calculateMasterKey(this.password, this.salt);
    }

    this.dekInfo = {
      iv: fromBase64(k.rsaKeys.dekInfo.iv),
      salt: fromBase64(k.rsaKeys.dekInfo.salt),
    };

    const privateKey = await this.importPrivateKey(k.rsaKeys.privateKey);
    const publicKey = await this.importPublicKey(k.rsaKeys.publicKey);

    this.rsaKeys = {
      privateKey,
      publicKey,
    };

    this.nodeKey = await this.importNodeKey(k.nodeKey);
  }

  private async doGenerate() {
    // generate a salt (the one stored in the user profile)
    this.salt = crypto.getRandomValues(new Uint8Array(96));

    // generate the master key from the password and salt
    this.masterKey = await calculateMasterKey(this.password, this.salt);

    // generate the RSA keys
    this.rsaKeys = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );

    // generate the nodeKey
    this.nodeKey = crypto.getRandomValues(new Uint8Array(32));

    // generate the dekInfo (for locking the private key)
    this.dekInfo = {
      iv: crypto.getRandomValues(new Uint8Array(16)),
      salt: crypto.getRandomValues(new Uint8Array(8)),
    };
  }

  public async export(weak: boolean = false): Promise<LockedKeychain> {
    if (this.masterKey == null || this.salt == null || this.dekInfo == null) {
      throw new Error('The keychain is not correctly initialized.');
    }

    const masterKey = toBase64(this.masterKey);
    const password = this.password;
    const salt = toBase64(this.salt);
    const privateKey = await this.exportPrivateKey();
    const publicKey = await this.exportPublicKey();
    const nodeKey = await this.exportNodeKey();
    const locked: LockedKeychain = {
      salt,
      rsaKeys: {
        privateKey,
        publicKey,
        dekInfo: {
          type: 'AES-128-CBC:1024',
          iv: toBase64(this.dekInfo.iv),
          salt: toBase64(this.dekInfo.salt),
        },
      },
      nodeKey,
    };

    if (weak) {
      locked.masterKey = masterKey;
      locked.password = password;
    }
    return locked;
  }

  private async exportPrivateKey() {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }
    if (this.masterKey == null) {
      throw new Error('masterKey should not be null.');
    }
    if (this.dekInfo == null) {
      throw new Error('dekInfo should not be null.');
    }

    const priv = await crypto.subtle.exportKey(
      'pkcs8',
      this.rsaKeys.privateKey
    );

    // Create the key for encoding masterKey
    const masterKey = toBase64(this.masterKey);
    const masterKeyEnc = await pbkdf2(masterKey, this.dekInfo.salt, 1024, 128);

    // encode private key
    const data = new Uint8Array(priv);

    const dataEnc = await encryptAes(data, masterKeyEnc, this.dekInfo.iv);
    return toBase64(new Uint8Array(dataEnc.encrypted));
  }

  private async importPrivateKey(pkStr: string) {
    if (this.masterKey == null) {
      throw new Error('masterKey should not be null.');
    }
    if (this.dekInfo == null) {
      throw new Error('dekInfo should not be null.');
    }

    const pk = fromBase64(pkStr);
    const masterKey = await aesPbkdf2Key(
      toBase64(this.masterKey),
      this.dekInfo.salt
    );

    const pkDec = await decryptAes(pk, masterKey, this.dekInfo.iv);

    const dec = new TextDecoder();
    const keyStr = dec.decode(pkDec);

    const reader = new PkcsReader(fromBase64(keyStr));
    const writer = new PkcsWriter();
    const translatedKey = writer.writeRsaPrivateKey(
      reader.readPkcs1RSAPrivate()
    );

    return await crypto.subtle.importKey(
      'pkcs8',
      translatedKey,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  private async importPublicKey(pkStr: string) {
    const pk = fromBase64(pkStr);
    return await crypto.subtle.importKey(
      'spki',
      pk,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  private async exportPublicKey() {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    const pub = await crypto.subtle.exportKey('pkcs8', this.rsaKeys.publicKey);
    return toBase64(new Uint8Array(pub));
  }

  public async importNodeKey(nk: string) {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    let nodeKey = await crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
      },
      this.rsaKeys.privateKey,
      fromBase64(nk)
    );

    if (nodeKey.byteLength > 44) {
      const decoder = new TextDecoder();
      nodeKey = fromBase64(decoder.decode(nodeKey));
    }

    return new Uint8Array(nodeKey);
  }

  public async exportNodeKey() {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }
    if (this.nodeKey == null) {
      throw new Error('nodeKey should not be null.');
    }

    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      this.rsaKeys.privateKey,
      this.nodeKey
    );

    return toBase64(new Uint8Array(encrypted));
  }

  // WARNING: this is not compatible with the actual version of GiGa.GG !
  public async exportLoginPassword() {
    const password = await pbkdf2(
      this.password,
      fromBase64('uh7rPXycB9uxLtRHoLFo1OwOyyHr+UTg'),
      512,
      24
    );
    return toBase64(password);
  }
}

async function calculateMasterKey(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  // For compat issue, the salt here is a base64 encoded string.
  const saltStr = toBase64(salt);
  const encoder = new TextEncoder();
  const realSalt = encoder.encode(saltStr);

  return await pbkdf2(password, realSalt, 1024, 128);
}

async function aesPbkdf2Key(
  password: string,
  salt: Uint8Array
): Promise<Uint8Array> {
  return await pbkdf2(password, salt, 1024, 128);
}

// function cap64char(str: string) {
//   const m = str.match(/.{1,64}/g);
//   if (m == null) {
//     throw new Error('Bad format: cannot cap empty string');
//   }
//   return m.join('\n');
// }

// function getPrivateKeyStr(privateKey: string) {
//   let str = '-----BEGIN RSA PRIVATE KEY-----\n';
//   str += cap64char(privateKey);
//   str += '\n-----END RSA PRIVATE KEY-----';
//   return str;
// }

// function getPublicKeyStr(publicKey: string) {
//   let str = '-----BEGIN PUBLIC KEY-----\n';
//   str += cap64char(publicKey);
//   str += '\n-----END PUBLIC KEY-----';
//   return str;
// }

// tslint:disable: no-bitwise

interface RsaPrivate {
  type: 'rsa-private';
  n: Uint8Array;
  e: Uint8Array;
  d: Uint8Array;
  iqmp: Uint8Array;
  p: Uint8Array;
  q: Uint8Array;
  dmodp: Uint8Array;
  dmodq: Uint8Array;
}

const berInteger = 2;

class PkcsReader {
  private offset = 0;
  constructor(private buf: Uint8Array) {}

  private readLength(offset: number) {
    const oldOffset = offset;
    // tslint:disable-next-line: no-bitwise
    let lenB = this.buf[offset] & 0xff;
    if (lenB === null) {
      throw new Error('LenB should not be null');
    }

    offset++;

    // tslint:disable-next-line: no-bitwise
    if ((lenB & 0x80) === 0x80) {
      // tslint:disable-next-line: no-bitwise
      lenB &= 0x7f;

      if (lenB === 0) {
        throw Error('Indefinite length not supported');
      }

      if (lenB > 4) {
        throw Error('encoding too long');
      }

      if (this.buf.byteLength - offset < lenB) {
        throw new Error('byteLength - offset should be > lenB');
      }

      let len = 0;
      for (let i = 0; i < lenB; i++) {
        // tslint:disable-next-line: no-bitwise
        len = (len << 8) + (this.buf[offset++] & 0xff);
      }
      return [offset, len];
    }
    // Wasn't a variable length
    return [offset, lenB];
  }

  private readMPInt(nm: string) {
    // tslint:disable-next-line: no-bitwise
    const b = this.buf[this.offset] & 0xff;
    if (b !== berInteger) {
      throw new Error(nm + ' is not an Integer: ' + b);
    }
    const [offset, len] = this.readLength(this.offset + 1);
    this.offset = offset;
    const slice = this.buf.slice(this.offset, this.offset + len);
    this.offset += len;

    // for jwk we need to remove the useless 0x00 char.
    // while (
    //   slice.length > 1 &&
    //   slice[0] === 0x00 &&
    //   (slice[1] & 0x80) === 0x80
    // ) {
    //   slice = slice.slice(1);
    // }
    return slice;
  }

  readPkcs1RSAPrivate(): RsaPrivate {
    const [offset, len] = this.readLength(this.offset + 1);
    this.offset = offset;

    const version = this.readMPInt('version');
    // assert.strictEqual(version[0], 0);

    const n = this.readMPInt('modulus');
    const e = this.readMPInt('public exponent');
    const d = this.readMPInt('private exponent');
    const p = this.readMPInt('prime1');
    const q = this.readMPInt('prime2');
    const dmodp = this.readMPInt('exponent1');
    const dmodq = this.readMPInt('exponent2');
    const iqmp = this.readMPInt('iqmp');

    // now, make the key
    return {
      type: 'rsa-private',
      n,
      e,
      d,
      iqmp,
      p,
      q,
      dmodp,
      dmodq,
    };

    // return {
    //   kty: 'RSA',
    //   // kid: 'cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df',
    //   use: 'sig',
    //   n: toBase64(n),
    //   e: toBase64(e),
    //   d: toBase64(d),
    //   p: toBase64(p),
    //   q: toBase64(q),
    //   dp: toBase64(dmodp),
    //   dq: toBase64(dmodq),
    //   qi: toBase64(iqmp),
    // };
  }
}

class PkcsWriter {
  private seq: number[] = [];
  private data: number[] = [];

  private startSequence(tag: number = 16 + 32) {
    // sequence = 16 ;
    // Constructor = 32 ;
    this.data.push(tag);
    this.seq.push(this.data.length);
    // some data will be spliced here.
  }

  private endSequence() {
    const seq = this.seq.pop();
    if (seq == null) {
      throw new Error('No sequence');
    }
    const start = seq;
    const len = this.data.length - start;

    if (len <= 0x7f) {
      this.data.splice(seq, 0, len);
    } else if (len <= 0xff) {
      this.data.splice(seq, 0, 0x81, len);
    } else if (len <= 0xffff) {
      this.data.splice(seq, 0, 0x82, (len >> 8) & 0xff, len & 0xff);
    } else if (len <= 0xffffff) {
      this.data.splice(seq, 0, 0x83, len >> 16, len >> 8, len);
    } else {
      throw Error('Sequence too long');
    }
  }

  private writeOID(s: string) {
    const tag = 6; // OID

    const encodeOctet = (b: number[], octet: number) => {
      if (octet < 128) {
        b.push(octet);
      } else if (octet < 16384) {
        b.push((octet >>> 7) | 0x80);
        b.push(octet & 0x7f);
      } else if (octet < 2097152) {
        b.push((octet >>> 14) | 0x80);

        b.push(((octet >>> 7) | 0x80) & 0xff);
        b.push(octet & 0x7f);
      } else if (octet < 268435456) {
        b.push((octet >>> 21) | 0x80);
        b.push(((octet >>> 14) | 0x80) & 0xff);
        b.push(((octet >>> 7) | 0x80) & 0xff);
        b.push(octet & 0x7f);
      } else {
        b.push(((octet >>> 28) | 0x80) & 0xff);
        b.push(((octet >>> 21) | 0x80) & 0xff);
        b.push(((octet >>> 14) | 0x80) & 0xff);
        b.push(((octet >>> 7) | 0x80) & 0xff);
        b.push(octet & 0x7f);
      }
    };

    const tmp = s.split('.');
    const bytes: number[] = [];
    bytes.push(parseInt(tmp[0], 10) * 40 + parseInt(tmp[1], 10));
    tmp.slice(2).forEach((b) => {
      encodeOctet(bytes, parseInt(b, 10));
    });

    this.data.push(tag);
    this.writeLength(bytes.length);

    this.data = this.data.concat(bytes);
  }

  writeRsaPrivateKey(key: RsaPrivate): Uint8Array {
    this.startSequence();

    // for private key :
    this.data.push(berInteger);
    this.data.push(1); // length
    this.data.push(0); // data

    {
      this.startSequence();
      this.writeOID('1.2.840.113549.1.1.1');

      //
      this.data.push(5); // Null
      this.data.push(0); // null value

      this.endSequence();
    }

    this.startSequence(4); // OctetString
    this.startSequence();

    // version
    this.data.push(berInteger); // integer
    this.data.push(1); // length
    this.data.push(0); // data

    this.writeBuffer(key.n, berInteger);
    this.writeBuffer(key.e, berInteger);
    this.writeBuffer(key.d, berInteger);
    this.writeBuffer(key.p, berInteger);
    this.writeBuffer(key.q, berInteger);
    // if (!key.part.dmodp || !key.part.dmodq)
    // 	utils.addRSAMissing(key);
    this.writeBuffer(key.dmodp, berInteger);
    this.writeBuffer(key.dmodq, berInteger);
    this.writeBuffer(key.iqmp, berInteger);

    this.endSequence();
    this.endSequence();
    this.endSequence();

    const pkcs8data = new Uint8Array(this.data);
    this.data = [];
    this.seq = [];
    return pkcs8data;
  }

  private writeLength(len: number) {
    if (len <= 0x7f) {
      this.data.push(len);
    } else if (len <= 0xff) {
      this.data.push(0x81);
      this.data.push(len);
    } else if (len <= 0xffff) {
      this.data.push(0x82);
      this.data.push(len >> 8);
      this.data.push(len);
    } else if (len <= 0xffffff) {
      this.data.push(0x83);
      this.data.push(len >> 16);
      this.data.push(len >> 8);
      this.data.push(len);
    } else {
      throw Error('Length too long (> 4 bytes)');
    }
  }

  private writeBuffer(buf: Uint8Array, tag: number) {
    this.data.push(tag);
    this.writeLength(buf.length);
    for (const x of buf) {
      this.data.push(x);
    }
  }
}
