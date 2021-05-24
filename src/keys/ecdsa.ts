import {sec1} from '@loopx/crypto/encoding/sec1';
import {pkcs8} from '@loopx/crypto/encoding/pkcs8';
import {oids} from '@loopx/crypto/encoding/oids';
import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {Asym, ECDSA} from '@loopx/crypto/types';
import {algs} from '../algs';
import {assert} from '../utils';
import {AbstractPrivateKey, AbstractPublicKey} from './key';

export class ECDSAPublicKey extends AbstractPublicKey {
  constructor(algo: Asym<any, any> | string, key: Buffer) {
    if (typeof algo === 'string') {
      algo = algs.getAsym(algo);
    }
    super(algo, key);
  }

  get asym(): ECDSA {
    return <ECDSA>this._asym;
  }

  toSPKI(compress?: boolean): Buffer {
    // [RFC5480] Page 7, Section 2.2.
    return new x509.SubjectPublicKeyInfo(
      oids.keyAlgs.ECDSA,
      new asn1.OID(oids.curves[this.id]),
      this.asym.publicKeyConvert(this.key, compress),
    ).encode();
  }
}

export class ECDSAPrivateKey extends AbstractPrivateKey {
  constructor(algo: Asym<any, any> | string, key?: Buffer | null) {
    if (typeof algo === 'string') {
      algo = algs.getAsym(algo);
    }
    if (key === undefined) {
      key = algo.privateKeyGenerate();
    }
    super(algo, key);
  }

  get asym(): ECDSA {
    return <ECDSA>this._asym;
  }

  generatePublicKey(compress?: boolean): ECDSAPublicKey {
    assert(this.key);
    return new ECDSAPublicKey(this.asym, this.asym.publicKeyCreate(this.key!, compress));
  }

  import(raw: Buffer): this {
    // [RFC5915] Page 2, Section 3.
    const key: sec1.ECPrivateKey = sec1.ECPrivateKey.decode(raw);
    const curve = key.namedCurveOID.toString();

    assert(key.version.toNumber() === 1);
    assert(curve === oids.curves[this.id] || curve === oids.NONE);

    this.key = this.asym.privateKeyImport({d: key.privateKey.value});

    return this;
  }

  export(compress?: boolean): Buffer {
    assert(this.key);
    // [RFC5915] Page 2, Section 3.
    const pub = this.asym.publicKeyCreate(this.key!, compress);
    return new sec1.ECPrivateKey(1, this.key, this.id, pub).encode();
  }

  toPKCS8(compress?: boolean) {
    assert(this.key);
    // [RFC5915] Page 2, Section 3.
    const pub = this.asym.publicKeyCreate(this.key!, compress);
    const curve = oids.NONE;

    return new pkcs8.PrivateKeyInfo(
      0,
      oids.keyAlgs.ECDSA,
      new asn1.OID(oids.curves[this.id]),
      new sec1.ECPrivateKey(1, this.key, curve, pub).encode(),
    ).encode();
  }
}
