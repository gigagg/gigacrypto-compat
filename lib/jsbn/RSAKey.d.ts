declare class BigInteger {
  bitLength(): number;
  clone(): BigInteger;
  divide(n: BigInteger): BigInteger;
  intValue(): number;
  mod(a: BigInteger): BigInteger;
  modInverse(m: BigInteger): BigInteger;
  multiply(n: BigInteger): BigInteger;
  pow(e: number): BigInteger;
  shiftLeft(n: number): BigInteger;
  subtract(n: BigInteger): BigInteger;
  toByteArray(): number[];
  toString(b: number): string;

  constructor(a: ArrayLike<number>);
}

export { BigInteger };



declare class RSAKey {
  n: BigInteger;
  e: number;

  setPublic(n: string, e: string): void;

  // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
  encrypt(text: string): string | null;

  // Return the PKCS#1 RSA encryption of "text" as a base64 encoded string
  encrypt64(text: string): string | null;

  // Return the PKCS#1 RSA decryption of "ctext".
  // "ctext" is an even-length hex string and the output is a plain string.
  decrypt(ctext: string): string | null;

  // Return the PKCS#1 RSA decryption of "text".
  // text is base64 encoded and it returns base64 encoded data
  decrypt64(text: string): string | null

  // Set the private key fields N, e, and d from hex strings
  setPrivate(N: string, E: string, D: string): void;

  // Set the private key fields N, e, d and CRT params from hex strings
  setPrivateEx(
    N: string,
    E: string,
    D: string,
    P: string,
    Q: string,
    DP: string,
    DQ: string,
    C: string
  ): void;

  // Generate a new random private key B bits long, using public expt E
  // TODO add the whole list of B and E...
  generate(B: 1024, E: '10001'): void;

  readPrivateKeyFromPkcs1PemString(pem: string): void;
  privateKeyToPkcs1PemString(): string;
  readPrivateKeyFromPkcs8PemString(pem: string): void;
  privateKeyToPkcs8PemString(): string;
  readPublicKeyFromX509PEMString(pem: string): void;
  publicKeyToX509PemString(): string;
}

export { RSAKey };
