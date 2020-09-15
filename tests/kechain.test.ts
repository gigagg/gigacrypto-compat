import { expect } from 'chai';
import { Keychain5 } from '../lib/keychain';
import { LockedKeychain } from '../lib/lockedKeychain';

describe('Crypto::Keychain5', () => {
  const importableKeychain: LockedKeychain = {
    nodeKey:
      'Am0TSBwizinOPkiECkXY6yWZtZae0xsKU1xSTBjpYTq/1UNVD2ICDicw8JgtYPHqmkdP4bcOCbdPQuGUQ/2mi3oyLsHHcgM2zluCoS8CkzDh7Q9C7yrAspUhGhgHgsAzIxEjbTa4iFeHwez41JGkEC+ucwboE089VlJkhsOxasI=',
    salt: 'FLOhgPcpK+IzLOqqzUw2Dbe3o47IsDitc2DBQNiU0i8=',
    rsaKeys: {
      dekInfo: {
        type: 'AES-128-CBC:1024',
        iv: '24etHeLAcj2Wp4n7xesV7Q==',
        salt: 'g68y7S8Vlwc=',
      },
      privateKey:
        'f/2y9dWg7PolO8kMbn1NSohL9w5djzqzvvJQ6gmvsk1xY3FkU77Q0Xy4Un8SM7grfDiFQtKr2xdTaGivwH0JZRAkdVvuEsYfq8DClyUZLxfVxzAme1Suwpey6Pl/9xpvhKvVt9eyQAlfPg/2llB074ibftPDQpNGpiRBwVvsHRRIC189mWM9UB1wa2bu4ZdHV+/oyxDoojWvXpfvZZjfa+qdrImtkRnQLeGR7aq3eXaZt5Ph0feYmb4viF7g1AE9nsQITSTbgzfnrqLvTwN5oCxlB+keD6bCx/TmK0Dh1G61ouHhZTPu8rcaA66/6MYz/TM+agMoNVrrqNMUZZXlO8fqE69dJsdcENK/2nGYapI+xpQtzRuD24AfvbwsoHfMSDirrN8MR2oWSbzwtkhfv9ULQq0+3H1u3kcwUz/cf/GCyxxcNAi7m1RAkezftLNE8GjJTevRxRT9v+CKh+166vrUClTOhaQH+E5mHB1hEG5jkPwjDkp05LNoEAbftEUkA1dYpDQGfUYJJcksSISeURQUj+mDcnlHGm2ENQa24XYxcSfeR3/eoe/OKmY13rZ3Uy+58XcUf/wkYw4Oz3Dr9/8zqi9wa+vaG7A5swEJXl2l6iP4zOqI7ukIkf2CAKSdLpCLeYH6dKBjHTC3itMEeToWpzdgzc4+JDUWi4inE93tIKUKbVJSmdNz6fSfj03cTKnvYGJWq7HeTH+Qy+0oWd+qZYcWyo4a90SQGc24HRNghs5doS6XjenNuWuVCHjiOQmTrpvqQzcXDaNzOVD++C6u9Fo5Fd4Xk4oOUTw+tgPolv5zV8TSi1avYHOFOCIhriqo8Zwo+UoxdaAp6r4xSU/qnPuUcUhVDYSx/dLyl0sM3y1ePz0lcMhb5wGBSPEfYGJeO7xWFabPXKfN5EuGD9GOSpdAjR4BtfQBkueY7yI/LCui1NJmEYGqLqbY/fWdKVq1N44nrcKqKEl1mi0saOz7dC6+PbcI2etyoICwa8cgCezJ/deaQgVPQV6QAxM31XSp6o584uZlD/c6C+TF9gb/Ma+mHb8hbLa80zb49OZ3VS0F1l9ArBEOuo3dQ7X+rzMXiUm/QdLU/fZeOqsT3w==',
      publicKey:
        'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvupt+SoaJxTnyvzo7d2xtVvhe5N2qxhyW/OVNuh/OeWO2T+BZPJsh6n3+YV4mulsAxmbUvvwpL9EI3xynjw5WpSsXgNAg+s2mAbyGTAOLAlPlymBy1R57XA0DgnIfEh3mQsiWP9uaXp8V8PNkWNC6d+JtRUEImDFy+mFI5XIcQwIDAQAB',
    },
  };

  const importableKeychain2: LockedKeychain = {
    nodeKey:
      'pZT+EwOnr+5DWPI35W4oMv+DlVfTG7R6YNUITUXUlQ95FKDlEVb5DOJ+b4congDW3AThrWzcHVbs1rRKVAVFiUCmA/KoKXrtQPC8c3Qdc8sxFLDOOns7MaVnBe/A0WKwhwNU8o6tjGm/xHS9n2uPPrZVEmGXOZ20MfmzkIdoBjY=',
    rsaKeys: {
      publicKey:
        'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKi4cBYGgjcflTY8QEZovRf5lTHuQx9Vx3+dM80gt04hPbu0fNv5Zx8ixRKGeImLNler6GtaDMtrr/8ekO4vWun0uhH7wkFau68mKHpaib8wLz0gUNTI2BsU41e0IY+q0Yg2k5UedrqkoWVTM+fQGcsiSGM4r7JKdQXDhXZT1X+QIDAQAB',
      privateKey:
        'g8Pc1PmxqLoMlovUpf6EwyqfaiTbd574gkmiW9KcUzi0eCxKM1LgHLNrRCopx928WLjo4WkfllaEcFvyMY1HwWMkgli66Be70UMoZpl0YQBw6mdSxsQ8EnCgkpZbESjGfBZATmenw5ipBYQf39/Qndc2dRfj4lpBxgaIO4RM+GEJmmjS/GQeX0E6e5QCeeaLT5JlM1TL/stSFj1r/xzoa+db8uCJahCw1BFj3ofvfTgpHKm3ZZww8O6iGc2aMxJBKwISy2vAa0URNI5wrD3DRGLOFStZDCnQCs1L3OwA4u5YakfMkzOhkwF1+iKS7tZDqc2rsUZAD2fp0hos/clT4bWuBqh8NWP2tHqXlvxSkvC/e/4w7P5kQbOoGrn/8L1CHbFqbM5Z2ziW9WyOa5XH2+hPJXqlBZNTMyocgv5UulnXao0CK6R3U6XLybc+BqqeuH5ZiIEx/a48mviU1GFCeOicNWl+TzhtjJTFynmLtc18hLkubpbNTOQ8N2nCGLzk5beFLe5/8849W5C/xpLIAQqHQjbVREooxmOCZINfPmkSsW3xzqO3TUYZlfq0wO5p2HRgXiBXvtvXL2+w7yqcREgmuhy7GwFRLyhbEdD8pCoBcnp18V1mkAK8w5L7aPtV8uu567KX0J2py7pyDZS5enlyRUOQ5ZjstK1q9KHMwbsU02jFkyXNLYj/zZtCl1HveyY6CHp7EFXTB8coGeKiNTioP1JNQlAw5ObXhs+bh0UObhN9izDqcynKkFa1SUGXpQYYBGInhv2Xmm3lyQOngN5+9OtfEGHmocYqffnMOd9rmFbe+Bx8KToOepPYoMTGp1q/CSEgxmdMRZxK/7JLwIz+hMd5sfK9V862v+C7fa3JdxxoTEUEop0pRcygq6tEaX3Snx7GdXn08MLiGdYnx+mesme9wFOkFRwYSWoaU2u3hth02A69usfHnjdx0Omx/89sIr49j/fl6zBwmHRblm7hKB8m5PzoWs22TA8gqiGwskqBSuJcmrZlSpWrFMy/UHYkCqeJ44aqptajcQCxRyhMI2x5VwTAaH7Jv1GcqlqGNCiz6BTDl6/tQ1oPjRAstMZ6JRfaR06ZBxOv5T+AdA==',
      dekInfo: {
        type: 'AES-128-CBC:1024',
        iv: 'of3B4b5w3qfgY/anbOPkCw==',
        salt: 'Nin4/dYcSmA=',
      },
    },
    salt: 'bfaWtfjKMtqhb5UBHfceKHbDAVL07d3NMHG2iWxW5SU=',
  };

  it('should generate a keychain', async () => {
    const keychain = await Keychain5.generate('gigatribe');
    expect(keychain).not.equal(null);
  });

  it('should import a keychain', async () => {
    const keychain = await Keychain5.import(importableKeychain, 'gigatribe');
    expect(keychain).not.equal(null);
  });

  it('should import a keychain (2)', async () => {
    const keychain = await Keychain5.import(importableKeychain2, '123456');
    expect(keychain).not.equal(null);
  });

  it('should export a keychain', async () => {
    const keychain = await Keychain5.import(importableKeychain, 'gigatribe');
    let exported = await keychain.export(true);

    expect(exported.rsaKeys.publicKey).equal(
      importableKeychain.rsaKeys.publicKey
    );
    expect(exported.rsaKeys.dekInfo.iv).equal(
      importableKeychain.rsaKeys.dekInfo.iv
    );
    expect(exported.rsaKeys.dekInfo.salt).equal(
      importableKeychain.rsaKeys.dekInfo.salt
    );
    expect(exported.rsaKeys.dekInfo.type).equal(
      importableKeychain.rsaKeys.dekInfo.type
    );
    expect(exported.salt).equal(importableKeychain.salt);
    // weak
    expect(exported.masterKey).equal('jELo/+hD23tTN1/tsGSeHw==');
    expect(exported.password).equal('gigatribe');

    exported = await keychain.export(false);
    expect(exported.rsaKeys.publicKey).equal(
      importableKeychain.rsaKeys.publicKey
    );
    expect(exported.rsaKeys.dekInfo.iv).equal(
      importableKeychain.rsaKeys.dekInfo.iv
    );
    expect(exported.rsaKeys.dekInfo.salt).equal(
      importableKeychain.rsaKeys.dekInfo.salt
    );
    expect(exported.rsaKeys.dekInfo.type).equal(
      importableKeychain.rsaKeys.dekInfo.type
    );
    expect(exported.salt).equal(importableKeychain.salt);
    // strong
    expect(exported.masterKey).equal(undefined);
    expect(exported.password).equal(undefined);
  });

  it('should import a generated keychain', async () => {
    const keychain = await Keychain5.generate('gigatribe');
    const exp1 = await keychain.export(true);
    const imported = await Keychain5.import(exp1, 'gigatribe');
    const exported = await imported.export(true);

    expect(exported.rsaKeys.publicKey).equal(exp1.rsaKeys.publicKey);
    expect(exported.rsaKeys.dekInfo.iv).equal(exp1.rsaKeys.dekInfo.iv);
    expect(exported.rsaKeys.dekInfo.salt).equal(exp1.rsaKeys.dekInfo.salt);
    expect(exported.rsaKeys.dekInfo.type).equal(exp1.rsaKeys.dekInfo.type);
    expect(exported.salt).equal(exp1.salt);
    // weak
    // expect(exported.masterKey).equal(random string here !);
    expect(exported.password).equal('gigatribe');

    expect(exported.salt.length).equal(44);
    expect(exported.nodeKey.length).to.be.above(171);
    expect(exported.nodeKey.length).to.be.below(345);
    expect(exported.masterKey?.length).equal(24);
  });

  it('should fail import when the password is wrong', async () => {
    const keychain = await Keychain5.generate('gigatribe');
    const exp1 = await keychain.export(false);

    try {
      await Keychain5.import(exp1, 'wrong password');
      expect(true).equal(false);
    } catch (error) {}
  });

  it('should generate the login password correctly', async () => {
    const keychain = await Keychain5.generate('azertyuiop');
    const lp = await keychain.calculateLoginPasswordCompat('mobiuser01');
    expect(lp).equal('Ju51bwKeziurk32HMdVx8g==');
  });

  it('should save and load a keychain', async () => {
    const keychain = await Keychain5.generate('azertyuiop');
    const exp1 = await keychain.export();
    await keychain.storeInLocalStorage('item_id', 'SomeGenericPassword');

    const loaded = await Keychain5.loadFromLocalStorage(
      'item_id',
      'SomeGenericPassword'
    );
    // tslint:disable-next-line: no-unused-expression
    expect(loaded).to.not.be.null;
    if (loaded == null) {
      throw new Error('');
    }
    const exported = await loaded.export();

    expect(exported.rsaKeys.publicKey).equal(exp1.rsaKeys.publicKey);
    expect(exported.rsaKeys.dekInfo.iv).equal(exp1.rsaKeys.dekInfo.iv);
    expect(exported.rsaKeys.dekInfo.salt).equal(exp1.rsaKeys.dekInfo.salt);
    expect(exported.rsaKeys.dekInfo.type).equal(exp1.rsaKeys.dekInfo.type);
    expect(exported.salt).equal(exp1.salt);
  });

  it('should be able to get the nodeKey', async () => {
    const keychain = await Keychain5.import(importableKeychain, 'gigatribe');
    expect(keychain).not.equal(null);
    expect(keychain.getUnencryptedNodeKey()).equal(
      '3iBVzCEwx7jNMB1DeaUiYP0lnX0ICCxtXG1vOCnKWrg='
    );
  });

  it('should be able to change the password', async () => {
    const keychain = await Keychain5.import(importableKeychain, 'gigatribe');
    await keychain.changePassword('gigatribe', '123456');
    const exported = await keychain.export();
    expect(exported.rsaKeys.privateKey).not.equal(
      importableKeychain.rsaKeys.privateKey
    );

    await Keychain5.import(exported, '123456');
  });

  it('should be able to calculate end encrypt a filekey', async () => {
    const keychain = await Keychain5.import(importableKeychain, 'gigatribe');
    const fkey = await keychain.aesEncryptWithNodeKey(
      '2zl8/2ADaRE6AGEIFFU/2d+G'
    );
    expect(fkey.length).equal(44);
    expect(fkey).equal('ftFtDfl9uH2RhrWjghS/henUKt7sa4PJHbMRilMBvs4=');
  });
});
