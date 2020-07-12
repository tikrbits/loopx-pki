import {HashCtor} from '@artlab/crypto/types';
import {pkcs10} from '@artlab/crypto/encoding/pkcs10';
import {
  EMPTY,
  PkixAttrProps,
  PkixRDNs,
  PkixSignatureAlgorithm,
} from './commons';
import {createPublicKeyFromSPKI, PkixPrivateKey, PkixPublicKey} from '../keys';
import {CertificationRequest} from '../pkcs10';
import {assert} from '../utils';

export interface PkixCertificationRequestParams {
  subject?: PkixAttrProps[];
  pubkey?: PkixPublicKey;
}

export class PkixCertificationRequest {
  version: number;
  subject: PkixRDNs;
  pubkey: PkixPublicKey;

  signatureAlgorithm: PkixSignatureAlgorithm;
  signature: Buffer;

  static fromPEM(data: Buffer | string) {
    return new PkixCertificationRequest().fromPEM(data);
  }

  static fromPKCS10(req: pkcs10.CertificationRequest) {
    return new PkixCertificationRequest().fromPKCS10(req);
  }

  constructor(params?: PkixCertificationRequestParams) {
    params = params ?? {};

    this.version = 2;
    this.subject = new PkixRDNs(params.subject);
    this.pubkey = params.pubkey!;

    this.signatureAlgorithm = new PkixSignatureAlgorithm();
    this.signature = EMPTY;
  }

  fromPEM(data: Buffer | string) {
    if (Buffer.isBuffer(data)) {
      data = data.toString('utf8');
    }
    return this.fromPKCS10(
      <pkcs10.CertificationRequest>pkcs10.CertificationRequest.fromPEM(data),
    );
  }

  fromPKCS10(req: pkcs10.CertificationRequest) {
    const info = req.certificationRequestInfo;

    this.version = info.version.toNumber();
    this.subject = PkixRDNs.fromASN1(info.subject);
    this.pubkey = createPublicKeyFromSPKI(info.subjectPublicKeyInfo);

    this.signatureAlgorithm = PkixSignatureAlgorithm.fromASN1(
      req.signatureAlgorithm,
    );
    this.signature = req.signature.value;
    return this;
  }

  build(
    key?: PkixPrivateKey,
    hash: string | HashCtor = 'sha256',
    compressPubkey?: boolean,
  ) {
    if (!this.pubkey && key) {
      this.pubkey = key.generatePublicKey();
    }
    assert(this.pubkey, 'public key is required');

    const csr = new CertificationRequest();
    const info = csr.certificationRequestInfo;

    info.version.fromNumber(this.version);
    this.subject.toASN1(info.subject);
    info.subjectPublicKeyInfo.decode(this.pubkey.toSPKI(compressPubkey));

    csr.signatureAlgorithm.decode(this.signatureAlgorithm.toASN1().encode());
    csr.signature.set(this.signature);

    return key ? csr.sign(key, hash) : csr;
  }
}
