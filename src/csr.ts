import {HashCtor} from '@loopx/crypto/types';
import {pkcs10} from '@loopx/crypto/encoding/pkcs10';
import {EMPTY, AttrProps, RDNs, SignatureAlgorithm} from './commons';
import {
  createPublicKeyFromSPKI,
  AbstractPrivateKey,
  AbstractPublicKey,
} from './keys';
import {CertificationRequest} from './pkcs10';
import {assert} from './utils';

export interface ConfigurableCertificationRequestParams {
  subject?: AttrProps[];
  pubkey?: AbstractPublicKey;
}

export class ConfigurableCertificationRequest {
  version: number;
  subject: RDNs;
  pubkey: AbstractPublicKey;

  signatureAlgorithm: SignatureAlgorithm;
  signature: Buffer;

  static fromPEM(data: Buffer | string) {
    return new ConfigurableCertificationRequest().fromPEM(data);
  }

  static fromPKCS10(req: pkcs10.CertificationRequest) {
    return new ConfigurableCertificationRequest().fromPKCS10(req);
  }

  constructor(params?: ConfigurableCertificationRequestParams) {
    params = params ?? {};

    this.version = 2;
    this.subject = new RDNs(params.subject);
    this.pubkey = params.pubkey!;

    this.signatureAlgorithm = new SignatureAlgorithm();
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
    this.subject = RDNs.fromASN1(info.subject);
    this.pubkey = createPublicKeyFromSPKI(info.subjectPublicKeyInfo);

    this.signatureAlgorithm = SignatureAlgorithm.fromASN1(
      req.signatureAlgorithm,
    );
    this.signature = req.signature.value;
    return this;
  }

  build(
    key?: AbstractPrivateKey,
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
