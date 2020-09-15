const chars =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

const lookup = new Uint8Array(256);
for (let i = 0; i < chars.length; i++) {
  lookup[chars.charCodeAt(i)] = i;
}

export function encode64(bytes: Uint8Array) {
  const len = bytes.length;
  let base64 = '';

  for (let i = 0; i < len; i += 3) {
    // tslint:disable-next-line: no-bitwise
    base64 += chars[bytes[i] >> 2];
    // tslint:disable-next-line: no-bitwise
    base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    // tslint:disable-next-line: no-bitwise
    base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    // tslint:disable-next-line: no-bitwise
    base64 += chars[bytes[i + 2] & 63];
  }

  if (len % 3 === 2) {
    base64 = base64.substring(0, base64.length - 1) + '=';
  } else if (len % 3 === 1) {
    base64 = base64.substring(0, base64.length - 2) + '==';
  }

  return base64;
}

export function decode64(base64: string): Uint8Array {
  let bufferLength = base64.length * 0.75;
  const len = base64.length;

  if (base64[base64.length - 1] === '=') {
    bufferLength--;
    if (base64[base64.length - 2] === '=') {
      bufferLength--;
    }
  }

  const bytes = new Uint8Array(bufferLength);

  let p = 0;
  for (let i = 0; i < len; i += 4) {
    const encoded1 = lookup[base64.charCodeAt(i)];
    const encoded2 = lookup[base64.charCodeAt(i + 1)];
    const encoded3 = lookup[base64.charCodeAt(i + 2)];
    const encoded4 = lookup[base64.charCodeAt(i + 3)];

    // tslint:disable-next-line: no-bitwise
    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    // tslint:disable-next-line: no-bitwise
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    // tslint:disable-next-line: no-bitwise
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }

  return bytes;
}
