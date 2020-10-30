import {x509} from '@loopx/crypto/encoding/x509';

export class IssuerMisMatchError extends Error {
  expected: x509.Attribute[];
  actual: x509.Attribute[];

  constructor(expected: x509.Attribute[], actual: x509.Attribute[]) {
    super(
      'The parent certificate did not issue the given child ' +
        "certificate; the child certificate's issuer does not match the " +
        "parent's subject.",
    );
    this.expected = expected;
    this.actual = actual;
  }
}

export class CertVerifyError extends Error {}

export class BadCertificate extends CertVerifyError {}

export class UnsupportedCertificate extends CertVerifyError {}

export class CertificateRevoked extends CertVerifyError {}

interface CertificateExpiredData {
  notBefore: Date;
  notAfter: Date;
  now: Date;
}

export class CertificateExpired extends CertVerifyError {
  data: CertificateExpiredData;

  constructor(message: string, data: CertificateExpiredData) {
    super(message);
    this.data = data;
  }
}

export class CertificateUnknown extends CertVerifyError {}

export class UnknownCA extends CertVerifyError {}
