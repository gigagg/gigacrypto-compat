export interface LockedKeychain {
  masterKey?: string;
  password?: string;
  salt: string;
  rsaKeys: {
    privateKey: string;
    publicKey: string;
    dekInfo: DekInfo;
  };
  nodeKey: string;
  challenge?: string;
}

export interface DekInfo {
  type: 'AES-128-CBC:1024';
  iv: string;
  salt: string;
}
