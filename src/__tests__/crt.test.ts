import '../setup/all';
import {assert} from '@artlab/bsert';
import {
  pem_past_2050,
  pem_sha1,
  pem_sha256,
  pem_sha512,
} from './fixtures/certs.pem';
import {createPrivateKeyFromPEM, createPublicKeyFromPEM} from '../keys';
import {Certificate} from '../models';
import {PkixCertificate} from '../builders';
import {CAStore} from '../castore';

const ExampleAttrs = [
  {
    id: 'CommonName',
    value: 'capkii.com',
  },
  {
    id: 'Country',
    value: 'US',
  },
  {
    id: 'ST',
    value: 'Virginia',
  },
  {
    id: 'Locality',
    value: 'Blacksburg',
  },
  {
    id: 'Organization',
    value: 'Capkii Co.',
  },
  {
    id: 'OU',
    value: 'R&D',
  },
  {
    id: '0.0',
    value: 'Custom Data',
  },
];

function assertFromToPem(pem: string) {
  // cert encode will ignore optional null node for signature null parameter
  // so we need re-from and re-to precess testing
  const cert1 = <Certificate>Certificate.fromPEM(pem);
  const pem1 = cert1.toPEM();
  const cert2 = <Certificate>Certificate.fromPEM(pem1);
  const pem2 = cert2.toPEM();
  assert.equal(pem1, pem2);
}

function assertVerifyPem(pem: string) {
  const cert = <Certificate>Certificate.fromPEM(pem);
  assert.ok(cert.verify(cert));
}

describe('crt', function () {
  it('should convert SHA-1 based certificate to/from PEM', function () {
    assertFromToPem(pem_sha1.certificate);
  });

  it('should convert SHA-256 based certificate to/from PEM', function () {
    assertFromToPem(pem_sha256.certificate);
  });

  it('should convert certificate not before < 2050 < not after to/from PEM', function () {
    assertFromToPem(pem_past_2050.certificate);
  });

  it('should convert SHA-512 based certificate to/from PEM', function () {
    assertFromToPem(pem_sha512.certificate);
  });

  it('should verify SHA-1 based self-signed certificate', function () {
    assertVerifyPem(pem_sha1.certificate);
  });

  it('should verify SHA-256 based self-signed certificate', function () {
    assertVerifyPem(pem_sha256.certificate);
  });

  it('should verify SHA-512 based self-signed certificate', function () {
    assertVerifyPem(pem_sha512.certificate);
  });

  it('should verify not before < 2050 < not after self-signed certificate', function () {
    assertVerifyPem(pem_past_2050.certificate);
  });

  it('should generate and verify a self-signed certificate', function () {
    const keys = {
      privkey: createPrivateKeyFromPEM(pem_sha1.privateKey),
      pubkey: createPublicKeyFromPEM(pem_sha1.publicKey),
    };

    const pc = new PkixCertificate({
      pubkey: keys.pubkey,
      serialNumber: '01',
      subject: ExampleAttrs,
    });

    const cert = pc.build(keys.privkey, 'sha256');
    assert.ok(cert.verify(cert));

    // change the issue subject will cause to throw exception when verify
    pc.subject.findByFilter('CommonName')!.value = 'hello';
    const issuer = pc.build(keys.privkey, 'sha256');
    assert.throws(
      () => issuer.verify(cert),
      'not issue the given child certificate',
    );

    // verify certificate chain
    const cas = new CAStore();
    cas.add(cert);
    cas.verify([cert], (error, depth, chain) => {
      assert.ok(error === undefined);
      return true;
    });
  });

  it('should generate a self-signed certificate after 2050', function () {
    const keys = {
      privkey: createPrivateKeyFromPEM(pem_sha1.privateKey),
      pubkey: createPublicKeyFromPEM(pem_sha1.publicKey),
    };

    const notBefore = new Date('2050-01-02');

    let pc = new PkixCertificate({
      pubkey: keys.pubkey,
      serialNumber: '01',
      subject: ExampleAttrs,
      notBefore,
    });

    pc = PkixCertificate.fromX509(pc.build(keys.privkey));
    assert.deepEqual(pc.validity.notBefore, notBefore);
    assert.deepEqual(pc.validity.notAfter, new Date('2051-01-02'));
  });

  it('should generate raw certificate', function () {
    const keys = {
      privkey: createPrivateKeyFromPEM(pem_sha1.privateKey),
      pubkey: createPublicKeyFromPEM(pem_sha1.publicKey),
    };

    const pc = new PkixCertificate({
      pubkey: keys.pubkey,
      serialNumber: '01',
      subject: ExampleAttrs,
    });

    const cert = pc.build(keys.privkey, 'sha256');
    assert.ok(cert);
    // console.log(cert.toPEM());
    // const raw = cert.encode();
    // console.log(raw);
    // const cert2 = Certificate.decode(raw);
    // assert.ok(cert2);
  });
});
