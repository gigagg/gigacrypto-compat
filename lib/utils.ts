import { decode64, encode64 } from './base64';
import { sjcl } from './sjcl/sjcl';

function toUint8Array(arr: sjcl.BitArray): Uint8Array {
  return new Uint8Array(sjcl.codec.arrayBuffer.fromBits(arr, false));
}

function toByteArray(buffer: Uint8Array): sjcl.BitArray {
  return sjcl.codec.arrayBuffer.toBits(buffer.buffer);
}

/** generateSalt return a random array of 96 bytes */
export function generateSalt(): Uint8Array {
  return toUint8Array(sjcl.random.randomWords(48, 0));
}

export function getRandomValues(bytes: number): Uint8Array {
  return toUint8Array(sjcl.random.randomWords(bytes / 2, 0));
}

/** pbkdf2 returns a hashed password (PBKDF2-HMAC-SHA256) */
export async function pbkdf2(
  password: string,
  salt: Uint8Array,
  iterations = 1024,
  length = 128
): Promise<Uint8Array> {
  return toUint8Array(
    sjcl.misc.pbkdf2(password, toByteArray(salt), iterations, length)
  );
}

export function toBase64(bytes: Uint8Array): string {
  return encode64(bytes);
}

export function fromBase64(input: string): Uint8Array {
  return decode64(input);
}

/** decryptAes decrypt some data. Use TextEncoder/TextDecoder to convert to string */
export async function decryptAes(
  data: Uint8Array,
  rawKey: Uint8Array,
  iv: Uint8Array
) {
  const aes = new sjcl.cipher.aes(toByteArray(rawKey));
  return toUint8Array(
    sjcl.mode.cbc.decrypt(aes, toByteArray(data), toByteArray(iv))
  );
}

/** encryptAes encrypt some string. Use TextEncoder/TextDecoder to convert to string */
export async function encryptAes(
  data: Uint8Array,
  rawKey: Uint8Array,
  iv: Uint8Array | null = null
) {
  // const encoder = new TextEncoder();
  // const encoded = encoder.encode(data);

  if (iv == null) {
    iv = getRandomValues(8);
  }

  const aes = new sjcl.cipher.aes(toByteArray(rawKey));
  const encrypted = toUint8Array(
    sjcl.mode.cbc.encrypt(aes, toByteArray(data), toByteArray(iv))
  );
  return { encrypted, iv };
}

/** calculateFileKey take the sha1 of a file (hex encoded) and return its fkey */
export async function calculateFileKey(sha1: string) {
  sha1 = sha1.toLowerCase();
  const enc = new TextEncoder();
  const data = await pbkdf2(
    sha1,
    enc.encode(
      '={w|>6L:{Xn;HAKf^w=,fgSX}sfw)`hxopaqk.6Hg\';w23"sd+b07`LSOGqz#-)['
    ),
    32,
    144
  );
  return toBase64(data);
}

/** calculateFileId take the sha1 of a file (hex encoded) and return its fid */
export async function calculateFileId(sha1: string) {
  sha1 = sha1.toLowerCase();
  const enc = new TextEncoder();
  const data = await pbkdf2(
    sha1,
    enc.encode(
      "5%;[yw\"XG2&Om#i*T$v.B2'Ae/VST4t#u$@pxsauO,H){`hUd7Xu@4q4WCc<>'ie"
    ),
    32,
    144
  );
  return toBase64(data);
}
