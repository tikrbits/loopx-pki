import '../setup/all';
import {assert} from '@artlab/bsert';
import {
  createPrivateKey,
  createPrivateKeyFromPEM,
  createPublicKey,
  createPublicKeyFromPEM,
} from '../keys';
import {algs} from '../algs';
import {readFixtureAsJSON, readFixtureAsString} from './support';

const ecdsa_curves = ['p192', 'p224', 'p256', 'p384', 'p521', 'secp256k1'];

const eddsa_curves = ['ed25519', 'ed448'];

const keys = [
  ['RSA', 'rsa-pkcs8.pem', 'rsa-spki.pem'],
  ['P256', 'p256-pkcs8.pem', 'p256-spki.pem'],
  ['ED25519', 'ed25519-pkcs8.pem', 'ed25519-spki.pem'],
  ['SECP256K1', 'secp256k1-pkcs8.pem', 'secp256k1-spki.pem'],
  // ['DSA', 'dsa-pkcs8.pem', 'dsa-spki.pem'],
];

function parseVector(json: any[]) {
  return json.map(item => {
    if (typeof item !== 'string') return item;
    if (algs.findHash(item)) {
      return algs.findHash(item);
    }
    return Buffer.from(item, 'hex');
  });
}

describe('keys', function () {
  describe('parse and reserialize keys', () => {
    for (const [name, privpemfile, pubpemfile] of keys) {
      it(`should parse and reserialize ${name} key`, () => {
        const privpem = readFixtureAsString(privpemfile);
        const priv = createPrivateKeyFromPEM(privpem);
        assert.ok(priv);
        assert.equal(priv.asym.id, name);
        assert.deepEqual(priv.key, createPrivateKeyFromPEM(priv.toPEM()).key);

        const pubpem = readFixtureAsString(pubpemfile);
        const pub = createPublicKeyFromPEM(pubpem);
        assert.ok(pub);
        assert.equal(pub.asym.id, name);
        assert.deepEqual(pub.key, createPublicKeyFromPEM(pub.toPEM()).key);

        const pub2 = priv.generatePublicKey();
        assert.deepEqual(pub.key, pub2.key);
      });
    }
  });

  describe('sign/verify', function () {
    function itCurve(
      [index, curve, priv, pub, msg, sig, hash]: any[],
      extra: any[],
    ) {
      extra = extra || [];
      it(`should sign and verify (${index}) (${curve})`, () => {
        const realPriv = createPrivateKey(curve, priv);
        const realPub = createPublicKey(curve, pub);
        assert.deepEqual(realPub.key, realPriv.generatePublicKey().key);

        const realSig = realPriv.signer(hash).signDigest(msg, ...extra);
        assert.deepEqual(realSig, sig);

        assert.ok(realPub.verifier(hash).verifyDigest(msg, sig, ...extra));
      });
    }

    describe('rsa', () => {
      const vectors = readFixtureAsJSON(`sign/rsa.json`);

      for (const [i, json] of vectors.entries()) {
        const vector = parseVector(json);

        const [
          privRaw,
          pubRaw,
          hash,
          saltLen,
          msg,
          sig1,
          sig2,
          ct1,
          ct2,
          ct3,
          pkcs8,
          spki,
        ] = vector;

        if (typeof hash === 'function') {
          itCurve([i, 'rsa', privRaw, pubRaw, msg, sig1, hash], []);
        }
      }
    });

    describe('ecdsa', () => {
      const getVectors = (curve: string) => {
        const vectors = readFixtureAsJSON(`sign/${curve}.json`);

        return vectors.map(parseVector);
      };

      for (const curve of ecdsa_curves) {
        describe(curve, () => {
          for (const [i, vector] of getVectors(curve).entries()) {
            const [
              priv,
              pub,
              tweak,
              privAdd,
              privMul,
              privNeg,
              privInv,
              pubAdd,
              pubMul,
              pubNeg,
              pubDbl,
              pubConv,
              pubHybrid,
              sec1,
              xy,
              pkcs8,
              spki,
              msg,
              sig,
              der,
              param,
              other,
              secret,
            ] = vector;

            itCurve([i, curve, priv, pub, msg, sig, null], []);
          }
        });
      }
    });

    describe('eddsa', () => {
      const getVectors = (curve: string) => {
        const vectors = readFixtureAsJSON(`sign/${curve}.json`);
        return vectors.map(parseVector);
      };

      for (const curve of eddsa_curves) {
        describe(curve, () => {
          for (const [i, vector] of getVectors(curve).entries()) {
            const [
              priv,
              scalar,
              prefix,
              reduced,
              pub,
              tweak,
              privAdd,
              privMul,
              privNeg,
              privInv,
              pubAdd,
              pubMul,
              pubNeg,
              pubDbl,
              pubConv,
              privOct,
              pubOct,
              pkcs8,
              spki,
              msg,
              ph,
              sig,
              sigAdd,
              sigMul,
              other,
              edSecret,
              montSecret,
            ] = vector;

            itCurve([i, curve, priv, pub, msg, sig, null], [ph]);
          }
        });
      }
    });
  });

  describe('encryption', () => {
    function itEncryption(curve: string) {
      describe(curve, () => {
        it('should encrypt and decrypt pem', () => {
          const pass = 'hello world';
          const key = createPrivateKey(curve);
          const pem = key.toPEM(pass);
          const key2 = createPrivateKeyFromPEM(pem, pass);
          assert.deepEqual(key, key2);
        });

        it('should decrypt fail with wrong passphrase', () => {
          const key = createPrivateKey(curve);
          const pem = key.toPEM('hello world');
          assert.throws(
            () => createPrivateKeyFromPEM(pem, 'wrong pass'),
            // /bad decrypt/,
          );
        });
      });
    }

    for (const curve of ['rsa', ...ecdsa_curves, ...eddsa_curves]) {
      itEncryption(curve);
    }
  });
});
