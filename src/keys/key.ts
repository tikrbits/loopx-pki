import {Asym} from '@loopx/crypto/types';
import {HashCtor} from '@loopx/crypto/types';
import {pem} from '@loopx/crypto/encoding/pem';
import {pemcrypt} from '@loopx/crypto/encoding/pemcrypt';
import {algs} from '../algs';
import {assert} from '../utils';

export abstract class AbstractPublicKey {
  protected _asym: Asym<any, any>;
  protected _key: Buffer;

  protected constructor(asym: Asym<any, any>, key: Buffer) {
    this._asym = asym;
    this.key = key;
  }

  get id() {
    return this._asym.id;
  }

  get asym() {
    return this._asym;
  }

  get key() {
    return this._key;
  }

  set key(value) {
    if (!this.asym.publicKeyVerify(value)) {
      throw new Error('Invalid public key.');
    }
    this._key = value;
  }

  abstract toSPKI(compress?: boolean): Buffer;

  toDER(compress?: boolean): Buffer {
    return this.toSPKI(compress);
  }

  toPEM(compress?: boolean) {
    return pem.toPEM(this.toSPKI(compress), 'PUBLIC KEY');
  }

  verifier(hash?: string | HashCtor) {
    assert(this.key, 'key is required');
    if (typeof hash === 'string') {
      hash = algs.getHash(hash);
    }
    return new Verifier(this.asym, this.key!, hash);
  }
}

export abstract class AbstractPrivateKey {
  protected _asym: Asym<any, any>;
  protected _key: Buffer;

  protected constructor(algo: Asym<any, any>, key: Buffer | null) {
    this._asym = algo;
    if (key) this.key = key;
  }

  get id() {
    return this._asym.id;
  }

  get asym() {
    return this._asym;
  }

  get key() {
    return this._key;
  }

  set key(value) {
    if (value !== null && !this.asym.privateKeyVerify(value)) {
      throw new Error('Invalid private key.');
    }
    this._key = value;
  }

  /**
   * @param compress Only for ECDSA
   */
  abstract toPKCS8(compress?: boolean): Buffer;

  abstract generatePublicKey(compress?: boolean): AbstractPublicKey;

  // Import from ASN.1 format
  abstract import(raw: Buffer): this;

  // Export as ASN.1 format
  abstract export(): Buffer;

  /**
   * @param compress Only for ECDSA
   */
  toDER(compress?: boolean): Buffer {
    return this.toPKCS8(compress);
  }

  /**
   * @param passphrase encryption passphrase. empty for none encryption
   * @param compress Only for ECDSA
   */
  toPEM(passphrase?: string | boolean, compress?: boolean) {
    if (typeof passphrase === 'boolean') {
      compress = passphrase;
      passphrase = undefined;
    }

    const block = new pem.PEMBlock();
    block.type = 'PRIVATE KEY';
    block.data = this.toPKCS8(compress);
    if (passphrase) {
      pemcrypt.encrypt(block, 'AES-256-CBC', passphrase);
    }
    return block.toString();
  }

  signer(hash?: string | HashCtor): Signer {
    assert(this.key, 'key is required');
    if (typeof hash === 'string') {
      hash = algs.getHash(hash);
    }
    return new Signer(this.asym, this.key!, hash);
  }
}

export class Signer {
  constructor(protected asym: Asym<any, any>, protected key: Buffer, protected hash?: HashCtor) {}

  sign(msg: Buffer, ...extra: any[]) {
    return this.signMessage(msg, ...extra);
  }

  signMessage(msg: Buffer, ...extra: any[]) {
    return this.asym.adsa(this.hash).signMessage(msg, this.key!, ...extra);
  }

  signDigest(digest: Buffer, ...extra: any[]) {
    return this.asym.adsa(this.hash).signDigest(digest, this.key!, ...extra);
  }
}

export class Verifier {
  constructor(protected asym: Asym<any, any>, protected key: Buffer, protected hash?: HashCtor) {}

  verify(msg: Buffer, sig: Buffer, ...extra: any[]) {
    return this.verifyMessage(msg, sig, ...extra);
  }

  verifyMessage(msg: Buffer, sig: Buffer, ...extra: any[]) {
    return this.asym.adsa(this.hash).verifyMessage(msg, sig, this.key, ...extra);
  }

  verifyDigest(digest: Buffer, sig: Buffer, ...extra: any[]) {
    return this.asym.adsa(this.hash).verifyDigest(digest, sig, this.key, ...extra);
  }
}
