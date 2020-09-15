import { expect } from 'chai';
import { pbkdf2, encryptAes,
  decryptAes, toBase64, calculateFileKey, calculateFileId } from '../lib/utils';

describe('Crypto::Utils', () => {
  it('pbkdf2 should work', async () => {
    const saltStr = 'FLOhgPcpK+IzLOqqzUw2Dbe3o47IsDitc2DBQNiU0i8=';
    const encoder = new TextEncoder();
    const salt = encoder.encode(saltStr);

    const result = await pbkdf2('gigatribe', salt);

    expect(toBase64(result)).equal('jELo/+hD23tTN1/tsGSeHw==');
  });

  it('should encrypt/decrypt aes data', async () => {
    const rawKey = crypto.getRandomValues(new Uint8Array(16));

    const encoder = new TextEncoder();
    const data = encoder.encode('gigatribe');

    const result = await encryptAes(data, rawKey);
    const decrypted = await decryptAes(
      new Uint8Array(result.encrypted),
      rawKey,
      result.iv
    );

    const decoder = new TextDecoder();
    const dec = decoder.decode(decrypted);

    expect(dec).equal('gigatribe');
  });

  it('should calculate fid/fkey', async () => {
    const key = await calculateFileKey('177abc9bcd3bc9785b96e06fcf63d82c58b6f8f6');
    expect(key).equal('V9leIEW8PYNMhlDuMNvkpWei');

    const id = await calculateFileId('177abc9bcd3bc9785b96e06fcf63d82c58b6f8f6');
    expect(id).equal('MUr243SzLSVf11/c7T0SZqyf');
  });
});
