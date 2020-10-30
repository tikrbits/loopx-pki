import {assert} from '@loopx/bsert';
import {CertificationRequest} from '../pkcs10';
import {ConfigurableCertificationRequest} from '../csr';
import {ECDSAPrivateKey} from '../keys';
import {readFixtureAsString} from './support';

describe('pkcs10', function () {
  it('should sign', function () {
    const key = new ECDSAPrivateKey('p256');
    const csr = new ConfigurableCertificationRequest({
      subject: [
        {
          id: 'commonName',
          value: 'capsec',
        },
      ],
      pubkey: key.generatePublicKey(),
    });
    const req = csr.build();
    assert.ok(req.sign(key).verify());
  });

  it('should verify success', function () {
    const pem = readFixtureAsString('csrs.pem');
    const csr = CertificationRequest.fromPEM(pem);
    assert.ok(csr.verify());
  });

  it('should verify failure', function () {
    const pem = readFixtureAsString('csrs.pem');
    const csr = CertificationRequest.fromPEM(pem);
    csr.certificationRequestInfo.raw = null;
    csr.certificationRequestInfo.subject.names[0].attributes[0].set('Hello');
    assert.ok(!csr.verify());
  });
});
