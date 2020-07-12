import {HashCtor} from '@artlab/crypto';
import {x509} from '@artlab/crypto/encoding/x509';

import {Certificate, resolveSignatureAlgorithmOID} from '../x509';
import {createPublicKeyFromSPKI, PkixPrivateKey, PkixPublicKey} from '../keys';
import {dt} from '../utils';

import {PkixCertExtensions, PkixCertExtParams} from '../extensions';
import {
  EMPTY,
  PkixAttrProps,
  PkixRDNs,
  PkixSignatureAlgorithm,
  PkixValidity,
} from './commons';

const DefaultSerialNumber = Buffer.from([0x01]);

export interface PkixCertificateParams {
  serialNumber?: Buffer | string;
  notBefore?: Date;
  notAfter?: Date;
  duration?: string;
  subject?: PkixAttrProps[];
  issuer?: PkixAttrProps[];
  subjectUniqueId?: Buffer;
  issuerUniqueId?: Buffer;
  extensions?: PkixCertExtParams[];
  pubkey?: PkixPublicKey;
}

export class PkixCertificate {
  version: number;
  serialNumber: Buffer;
  validity: PkixValidity;
  subject: PkixRDNs;
  subjectUniqueId?: Buffer;
  issuer: PkixRDNs;
  issuerUniqueId?: Buffer;
  extensions: PkixCertExtensions;
  pubkey: PkixPublicKey;

  signatureAlgorithm: PkixSignatureAlgorithm;
  signature: Buffer;

  static fromPEM(data: Buffer | string) {
    return new PkixCertificate().fromPEM(data);
  }

  static fromX509(cert: x509.Certificate) {
    return new PkixCertificate().fromX509(cert);
  }

  constructor(params?: PkixCertificateParams) {
    params = params ?? {};

    let serialNumber: Buffer = DefaultSerialNumber;
    if (Buffer.isBuffer(params.serialNumber)) {
      serialNumber = params.serialNumber;
    } else if (typeof params.serialNumber === 'string') {
      serialNumber = Buffer.from(params.serialNumber, 'hex');
    }

    const notBefore = params.notBefore ?? new Date();
    const notAfter =
      params.notAfter ?? dt.add(notBefore, params.duration ?? '1y');

    // TBSCertificate
    this.version = 0x02;
    this.serialNumber = serialNumber;

    this.subjectUniqueId = params.subjectUniqueId;
    this.issuerUniqueId = params.issuerUniqueId;

    this.validity = new PkixValidity({notBefore, notAfter});
    this.subject = new PkixRDNs(params.subject);
    this.issuer = new PkixRDNs(params.issuer ?? params.subject);
    this.extensions = new PkixCertExtensions(params.extensions);

    this.pubkey = params.pubkey!;

    // SignatureAlgorithm
    this.signatureAlgorithm = new PkixSignatureAlgorithm();

    // Signature
    this.signature = EMPTY;
  }

  fromPEM(data: Buffer | string) {
    if (Buffer.isBuffer(data)) {
      data = data.toString('utf8');
    }
    return this.fromX509(<x509.Certificate>x509.Certificate.fromPEM(data));
  }

  fromX509(cert: x509.Certificate) {
    // TBSCertificate
    const tbs = cert.tbsCertificate;
    this.version = tbs.version.toNumber();
    this.serialNumber = tbs.serialNumber.value;

    this.pubkey = createPublicKeyFromSPKI(tbs.subjectPublicKeyInfo);
    this.subjectUniqueId = tbs?.subjectUniqueID.value;
    this.issuerUniqueId = tbs?.issuerUniqueID.value;

    this.validity = PkixValidity.fromASN1(tbs.validity);
    this.subject = PkixRDNs.fromASN1(tbs.subject);
    this.issuer = PkixRDNs.fromASN1(tbs.issuer);
    this.extensions = PkixCertExtensions.fromASN1(tbs.extensions);

    // SignatureAlgorithm
    this.signatureAlgorithm = PkixSignatureAlgorithm.fromASN1(
      cert.signatureAlgorithm,
    );

    // Signature
    this.signature = cert.signature.value;
    return this;
  }

  build(
    key?: PkixPrivateKey,
    hash: string | HashCtor = 'sha256',
    compressPubKey?: boolean,
  ) {
    const cert = new Certificate();
    const tbc = cert.tbsCertificate;

    tbc.version.fromNumber(this.version);
    tbc.serialNumber.set(this.serialNumber);
    tbc.subjectUniqueID.set(this.subjectUniqueId);
    tbc.issuerUniqueID.set(this.issuerUniqueId);

    this.validity.toASN1(tbc.validity);
    this.subject.toASN1(tbc.subject);
    this.issuer.toASN1(tbc.issuer);
    this.extensions.toASN1(tbc.extensions, true);

    this.signatureAlgorithm.toASN1(cert.signatureAlgorithm);
    cert.signature.set(this.signature);

    if (this.pubkey) {
      tbc.subjectPublicKeyInfo.decode(this.pubkey.toSPKI(compressPubKey));
      tbc.signature.algorithm.set(
        resolveSignatureAlgorithmOID(this.pubkey, hash),
      );
    }

    return key ? cert.sign(key, hash) : cert;
  }
}
