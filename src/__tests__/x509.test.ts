import '../setup/all';
import {assert} from '@tib/bsert';
import {oids} from '@tib/crypto/encoding/oids';
import {createPrivateKey} from '../keys';
import {ConfigurableCertificate} from '../crt';

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

describe('x509/Certificate', function () {
  describe('#basicConstraints', function () {
    it('should get basicConstraints undefined without basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
      });

      const cert = pc.build(key, 'sha256');
      assert.ok(!cert.basicConstraints);
    });

    it('should get basicConstraints with basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.ok(cert.basicConstraints);
    });
  });

  describe('#isCA', function () {
    it('should return false with CA undefined basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.ok(!cert.isCA);
    });

    it('should return false with CA disabled basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
            ca: false,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.ok(!cert.isCA);
    });

    it('should return true with CA enabled in basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
            ca: true,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.ok(cert.isCA);
    });
  });

  describe('#maxPathLen', function () {
    it('should return undefined with maxLenPath undefined in basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.equal(undefined, cert.maxPathLen);
    });

    it('should return 0 with maxLenPath specified to 0 in basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
            maxPathLen: 0,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.equal(0, cert.maxPathLen);
    });

    it('should return number with maxLenPath specified in basic constraints extension', function () {
      const key = createPrivateKey('p256');
      const pc = new ConfigurableCertificate({
        pubkey: key.generatePublicKey(),
        subject: ExampleAttrs,
        extensions: [
          {
            id: oids.exts.BASIC_CONSTRAINTS,
            maxPathLen: 1,
          },
        ],
      });

      const cert = pc.build(key, 'sha256');
      assert.equal(1, cert.maxPathLen);
    });
  });
});
