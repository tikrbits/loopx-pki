import {assert} from '@artlab/bsert';
import {PkixCertificationRequest} from '../builders';
import {PkixECDSAPrivateKey} from '../keys';
import {readFixtureAsString} from './support';

describe('csr', function () {
  it('should create from pem', function () {
    const pem1 = readFixtureAsString('csrs.pem');
    const csr1 = PkixCertificationRequest.fromPEM(pem1);
    const pem2 = csr1.build().toPEM();
    const csr2 = PkixCertificationRequest.fromPEM(pem2);

    assert.deepEqual(csr1, csr2);
  });

  it('should build with private key', function () {
    const key = new PkixECDSAPrivateKey('p256');
    const csr = new PkixCertificationRequest({
      subject: [
        {
          id: 'commonName',
          value: 'capsec',
        },
      ],
    });
    const req = csr.build(key);
    assert.ok(req.verify());
  });

  it('should build without private key', function () {
    const key = new PkixECDSAPrivateKey('p256');
    const csr = new PkixCertificationRequest({
      subject: [
        {
          id: 'commonName',
          value: 'capsec',
        },
      ],
      pubkey: key.generatePublicKey(),
    });
    const req = csr.build();
    assert.throws(() => req.verify());
    assert.ok(req.sign(key).verify());
  });
});
