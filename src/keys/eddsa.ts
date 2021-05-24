import {Asym, EDDSA} from '@loopx/crypto/types';
import {pkcs8} from '@loopx/crypto/encoding/pkcs8';
import {oids} from '@loopx/crypto/encoding/oids';
import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {algs} from '../algs';
import {AbstractPrivateKey, AbstractPublicKey} from './key';
import {assert} from '../utils';

export class EDDSAPublicKey extends AbstractPublicKey {
  constructor(algo: Asym<any, any> | string, key: Buffer) {
    if (typeof algo === 'string') {
      algo = algs.getAsym(algo);
    }
    super(algo, key);
  }

  get asym(): EDDSA {
    return <EDDSA>this._asym;
  }

  toSPKI(compress?: boolean): Buffer {
    // [RFC8410] Page 4, Section 4.
    return new x509.SubjectPublicKeyInfo(oids.curves[this.id], new asn1.Null(), this.key).encode();
  }
}

export class EDDSAPrivateKey extends AbstractPrivateKey {
  constructor(algo: Asym<any, any> | string, key?: Buffer | null) {
    if (typeof algo === 'string') {
      algo = algs.getAsym(algo);
    }
    if (!key && key !== null) {
      key = algo.privateKeyGenerate();
    }
    super(algo, key);
  }

  get asym(): EDDSA {
    return <EDDSA>this._asym;
  }

  generatePublicKey() {
    assert(this.key);
    return new EDDSAPublicKey(this.asym, this.asym.publicKeyCreate(this.key!));
  }

  import(raw: Buffer): this {
    // [RFC8410] Page 7, Section 7.
    const str = asn1.OctString.decode(raw);

    if (!this.asym.privateKeyVerify(str.value)) throw new Error('Invalid private key.');

    this.key = this.asym.privateKeyImport({d: str.value});

    return this;
  }

  export(): Buffer {
    // [RFC8410] Page 7, Section 7.
    return new asn1.OctString(this.key).encode();
  }

  toPKCS8() {
    // [RFC8410] Page 7, Section 7.
    return new pkcs8.PrivateKeyInfo(0, oids.curves[this.id], new asn1.Null(), this.export()).encode();
  }
}
