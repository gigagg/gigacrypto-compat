import { LockedKeychain } from './lockedKeychain';
import {
  pbkdf2,
  toBase64,
  encryptAes,
  fromBase64,
  decryptAes,
  getRandomValues,
} from './utils';
import { RSAKey } from './jsbn/RSAKey';

export class Keychain5 {
  private readonly rsaLength = 1024;
  private readonly rsaExp = '10001';
  private readonly challengeData = 'dE9yL9kF6nU1zJ0fC4tQ6zY5lO2mN4hE';

  private password: string | null;

  private rsaKeys: RSAKey | null = null;
  private salt: Uint8Array | null = null;
  private masterKey: Uint8Array | null = null;
  private nodeKey: Uint8Array | null = null;

  private dekInfo: {
    iv: Uint8Array;
    salt: Uint8Array;
  } | null = null;

  private constructor(password: string | null) {
    this.password = password;
  }

  public static async generate(password: string) {
    const chain = new Keychain5(password);
    await chain.doGenerate();
    return chain;
  }

  public static async import(
    k: LockedKeychain,
    password?: string,
  ): Promise<Keychain5> {
    const chain = new Keychain5(password || null);
    await chain.doImport(k);
    return chain;
  }

  public static async loadFromLocalStorage(
    itemKey: string,
    password: string
  ): Promise<null | Keychain5> {
    const item = localStorage.getItem(itemKey);
    if (item == null) {
      return null;
    }
    try {
      const value = JSON.parse(item);
      if (
        value == null ||
        value.iv == null ||
        value.encrypted == null ||
        value.salt == null
      ) {
        return null;
      }

      const key = await pbkdf2(password, fromBase64(value.salt));
      const decrypted = await decryptAes(
        fromBase64(value.encrypted),
        key,
        fromBase64(value.iv)
      );

      const rawJson = new TextDecoder().decode(decrypted);
      return await Keychain5.import(JSON.parse(rawJson));
    } catch (error) {
      console.error('Error loading keychain from localStorage', error);
      return null;
    }
  }

  public async storeInLocalStorage(itemKey: string, password: string) {
    // data to store
    const rawJson = JSON.stringify(await this.export(true));

    // aes encrypt
    const salt = getRandomValues(96);
    const data = new TextEncoder().encode(rawJson);
    const key = await pbkdf2(password, salt);
    const result = await encryptAes(data, key);

    // store the value and a way to decrypt it
    const value = {
      iv: toBase64(result.iv),
      encrypted: toBase64(new Uint8Array(result.encrypted)),
      salt: toBase64(salt),
    };
    localStorage.setItem(itemKey, JSON.stringify(value));
  }

  private async doImport(k: LockedKeychain) {
    if (k.password != null) {
      this.password = k.password;
    }

    this.salt = fromBase64(k.salt);

    if (k.masterKey != null) {
      this.masterKey = fromBase64(k.masterKey);
    } else if (this.password == null) {
      throw new Error('Cannot import this keychain without a password');
    } else {
      this.masterKey = await calculateMasterKey(this.password, this.salt);
    }

    this.dekInfo = {
      iv: fromBase64(k.rsaKeys.dekInfo.iv),
      salt: fromBase64(k.rsaKeys.dekInfo.salt),
    };

    this.rsaKeys = new RSAKey();
    await this.importPrivateKey(k.rsaKeys.privateKey);
    await this.importPublicKey(k.rsaKeys.publicKey);

    this.nodeKey = await this.importNodeKey(k.nodeKey);

    if (k.challenge != null) {
      await this.uncipherChallenge(k.challenge);
    }
  }

  private async doGenerate() {
    if (this.password == null) {
      throw new Error('password must not be null');
    }
    // generate a salt (the one stored in the user profile)
    this.salt = getRandomValues(16);

    // generate the master key from the password and salt
    this.masterKey = await calculateMasterKey(this.password, this.salt);

    // generate the RSA keys
    this.rsaKeys = new RSAKey();
    this.rsaKeys.generate(this.rsaLength, this.rsaExp);

    // generate the nodeKey
    this.nodeKey = getRandomValues(32);
    this.nodeKey = new TextEncoder().encode(
      toBase64(this.nodeKey).slice(0, 32)
    );

    // generate the dekInfo (for locking the private key)
    this.dekInfo = {
      iv: getRandomValues(8),
      salt: getRandomValues(8),
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
    const challenge = await this.aesEncryptWithNodeKey(this.challengeData);
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
      challenge,
    };

    if (weak) {
      locked.masterKey = masterKey;
      if (password != null) {
        locked.password = password;
      }
    }
    return locked;
  }

  public async uncipherChallenge(challenge: string) {
    const chal = await this.aesDecryptWithNodeKey(challenge);
    if (new TextDecoder().decode(chal) !== this.challengeData) {
      throw new Error('Challenge failed.');
    }
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

    const priv = this.rsaKeys.privateKeyToPkcs1PemString();

    // Create the key for encoding masterKey
    const masterKey = toBase64(this.masterKey);
    const masterKeyEnc = await pbkdf2(masterKey, this.dekInfo.salt, 1024, 128);

    // encode private key
    const enc = new TextEncoder();
    const data = enc.encode(priv);

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
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    const pk = fromBase64(pkStr);
    const masterKey = await aesPbkdf2Key(
      toBase64(this.masterKey),
      this.dekInfo.salt
    );

    const pkDec = await decryptAes(pk, masterKey, this.dekInfo.iv);

    const dec = new TextDecoder();
    const keyStr = dec.decode(pkDec);
    try {
      this.rsaKeys.readPrivateKeyFromPkcs8PemString(keyStr);
    } catch (e) {
      this.rsaKeys.readPrivateKeyFromPkcs1PemString(keyStr);
    }
  }

  private async importPublicKey(pkStr: string) {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    this.rsaKeys.readPublicKeyFromX509PEMString(pkStr);
  }

  private async exportPublicKey() {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    return this.rsaKeys.publicKeyToX509PemString();
  }

  private async importNodeKey(nk: string) {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }

    const tmp = this.rsaKeys.decrypt64(nk);
    if (tmp == null) {
      throw new Error('NodeKey decryption failed');
    }

    let nodeKey = fromBase64(tmp);
    while (nodeKey.byteLength >= 44) {
      const decoder = new TextDecoder();
      nodeKey = fromBase64(decoder.decode(nodeKey));
    }

    if (nodeKey.byteLength !== 32) {
      throw new Error(
        'Cannot import nodeKey: length 32 != ' + nodeKey.byteLength
      );
    }

    return new Uint8Array(nodeKey);
  }

  private async exportNodeKey() {
    if (this.rsaKeys == null) {
      throw new Error('rsaKeys should not be null.');
    }
    if (this.nodeKey == null) {
      throw new Error('nodeKey should not be null.');
    }

    const dec = new TextDecoder();
    const tmp = this.rsaKeys.encrypt64(toBase64(this.nodeKey));
    if (tmp == null) {
      throw new Error('NodeKey decryption failed');
    }
    return tmp;
  }

  public getUnencryptedNodeKey() {
    if (this.nodeKey == null) {
      throw new Error('nodeKey should not be null.');
    }

    return toBase64(this.nodeKey);
  }

  // WARNING: this is not compatible with the actual version of GiGa.GG !
  public async calculateLoginPassword() {
    if (this.password == null) {
      throw new Error('password should not be null');
    }
    const password = await pbkdf2(
      this.password,
      fromBase64('uh7rPXycB9uxLtRHoLFo1OwOyyHr+UTg'),
      512,
      192
    );
    return toBase64(password);
  }

  // Compatible version of the loginPassword. WARNING: login is case sensitive
  public async calculateLoginPasswordCompat(login: string) {
    if (this.password == null) {
      throw new Error('password should not be null');
    }
    const saltStr = login + '"D<?4\'V%Fh(U,9SjdO4v)|1mJV31]#;W';
    const enc = new TextEncoder();
    const salt = enc.encode(saltStr);

    const password = await pbkdf2(this.password, salt, 1024, 128);
    return toBase64(password);
  }

  /** Change the password of the keychain. Remember to storeInLocalStorage the new keychain (and send the new password to the giga api) */
  public async changePassword(oldPassword: string, newPassword: string) {
    if (this.salt == null) {
      throw new Error('Salt must not be null');
    }
    if (
      this.password != null &&
      this.password !== '' &&
      this.password !== oldPassword
    ) {
      throw new Error('password mismatch');
    }

    this.password = newPassword;
    this.masterKey = await calculateMasterKey(this.password, this.salt);
  }

  /** Encrypt some data using the nodekey as key/iv. Data will be encrypted as is. */
  public async aesEncryptWithNodeKey(data: string) {
    if (this.nodeKey == null) {
      throw new Error('nodekey must not be null');
    }
    const raw = await encryptAes(
      new TextEncoder().encode(data),
      this.nodeKey.slice(0, 16),
      this.nodeKey.slice(16)
    );
    return toBase64(new Uint8Array(raw.encrypted));
  }

  /**
   * Decrypt some data using the nodekey as key/iv.
   * Data is a base64 encode.
   */
  public async aesDecryptWithNodeKey(data: string) {
    if (this.nodeKey == null) {
      throw new Error('nodekey must not be null');
    }
    return await decryptAes(
      fromBase64(data),
      this.nodeKey.slice(0, 16),
      this.nodeKey.slice(16)
    );
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
