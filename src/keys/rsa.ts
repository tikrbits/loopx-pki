import {oids} from '@loopx/crypto/encoding/oids';
import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {pkcs1} from '@loopx/crypto/encoding/pkcs1';
import {pkcs8} from '@loopx/crypto/encoding/pkcs8';
import {RSA} from '@loopx/crypto/types';
import {algs} from '../algs';
import {AbstractPrivateKey, AbstractPublicKey} from './key';
import {assert} from '../utils';

export class RSAPublicKey extends AbstractPublicKey {
  constructor(key: Buffer) {
    super(algs.getAsym('RSA'), key);
  }

  get asym(): RSA {
    return <RSA>this._asym;
  }

  toSPKI(): Buffer {
    return new x509.SubjectPublicKeyInfo(oids.keyAlgs.RSA, new asn1.Null(), this.key).encode();
  }
}

export class RSAPrivateKey extends AbstractPrivateKey {
  constructor(bits?: number, exponent?: number);
  constructor(key?: Buffer | null);
  constructor(bits?: number | Buffer | null, exponent?: number) {
    const asym = <RSA>algs.getAsym('RSA');
    let key = bits;

    if (key !== null) {
      if (!Buffer.isBuffer(key)) {
        key = asym.privateKeyGenerate(key, exponent);
      }
    }
    super(asym, key);
  }

  get asym(): RSA {
    return <RSA>this._asym;
  }

  generatePublicKey() {
    assert(this.key);
    return new RSAPublicKey(this.asym.publicKeyCreate(this.key!));
  }

  import(raw: Buffer): this {
    this.key = raw;
    return this;
  }

  export(): Buffer {
    assert(this.key);
    const key = this.asym.privateKeyExport(this.key!);
    return new pkcs1.RSAPrivateKey(0, key.n, key.e, key.d, key.p, key.q, key.dp, key.dq, key.qi).encode();
  }

  toPKCS8() {
    return new pkcs8.PrivateKeyInfo(0, oids.keyAlgs.RSA, new asn1.Null(), this.export()).encode();
  }
}
