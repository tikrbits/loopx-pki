import {HashCtor} from '@tib/crypto';
import {x509} from '@tib/crypto/encoding/x509';
import {Certificate, resolveSignatureAlgorithmOID} from './x509';
import {
  createPublicKeyFromSPKI,
  AbstractPrivateKey,
  AbstractPublicKey,
} from './keys';
import {Extensions, ExtensionParams} from './extensions';
import {dt} from './utils';
import {EMPTY, AttrProps, RDNs, SignatureAlgorithm, Validity} from './commons';

const DefaultSerialNumber = Buffer.from([0x01]);

export interface ConfigurableCertificateParams {
  serialNumber?: Buffer | string;
  notBefore?: Date;
  notAfter?: Date;
  duration?: string;
  subject?: AttrProps[];
  issuer?: AttrProps[];
  subjectUniqueId?: Buffer;
  issuerUniqueId?: Buffer;
  extensions?: ExtensionParams[];
  pubkey?: AbstractPublicKey;
}

export class ConfigurableCertificate {
  version: number;
  serialNumber: Buffer;
  validity: Validity;
  subject: RDNs;
  subjectUniqueId?: Buffer;
  issuer: RDNs;
  issuerUniqueId?: Buffer;
  extensions: Extensions;
  pubkey: AbstractPublicKey;

  signatureAlgorithm: SignatureAlgorithm;
  signature: Buffer;

  static fromPEM(data: Buffer | string) {
    return new ConfigurableCertificate().fromPEM(data);
  }

  static fromX509(cert: x509.Certificate) {
    return new ConfigurableCertificate().fromX509(cert);
  }

  constructor(params?: ConfigurableCertificateParams) {
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

    this.validity = new Validity({notBefore, notAfter});
    this.subject = new RDNs(params.subject);
    this.issuer = new RDNs(params.issuer ?? params.subject);
    this.extensions = new Extensions(params.extensions);

    this.pubkey = params.pubkey!;

    // SignatureAlgorithm
    this.signatureAlgorithm = new SignatureAlgorithm();

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

    this.validity = Validity.fromASN1(tbs.validity);
    this.subject = RDNs.fromASN1(tbs.subject);
    this.issuer = RDNs.fromASN1(tbs.issuer);
    this.extensions = Extensions.fromASN1(tbs.extensions);

    // SignatureAlgorithm
    this.signatureAlgorithm = SignatureAlgorithm.fromASN1(
      cert.signatureAlgorithm,
    );

    // Signature
    this.signature = cert.signature.value;
    return this;
  }

  build(
    key?: AbstractPrivateKey,
    hash: string | HashCtor = 'sha256',
    compressPubKey?: boolean,
  ): Certificate {
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
