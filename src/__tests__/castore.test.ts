import {assert} from '@artlab/bsert';
import {CAStore} from '../castore';
import {resolveFixturePath} from './support';
import {readCertsFromFile} from '../x509';

const cert_chain_dst = resolveFixturePath('cas-leafs/dst-gitr-net-chain.pem');
const cert_leaf_globalsign = resolveFixturePath(
  'cas-leafs/globalsign-gts-google-com.pem',
);
const cert_leaf_frank4dd_expired = resolveFixturePath(
  'cas-leafs/frank4dd-rsa-example-cert.pem',
);
const cert_leaf_github = resolveFixturePath('certs/github.crt');

describe('castore', function () {
  it('should load CAs from directory', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.ok(cas.count > 0);
  });

  it('should verify success for single leaf certificate', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.ok(cas.verify(readCertsFromFile(cert_leaf_globalsign)));
  });

  it('should verify success for chain certificate', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.ok(cas.verify(readCertsFromFile(cert_chain_dst)));
  });

  it('should verify success without validityCheckDate option for expired certificate', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.ok(cas.verify(readCertsFromFile(cert_leaf_frank4dd_expired)));
  });

  it('should verify failure with validityCheckDate option enabled for expired certificate', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.throws(
      () =>
        cas.verify(readCertsFromFile(cert_leaf_frank4dd_expired), {
          validityCheckDate: new Date(),
        }),
      /has expired/,
    );
  });

  it('should verify failure without trust root', async function () {
    const cas = new CAStore();
    await cas.load(resolveFixturePath('cas/*'));
    assert.throws(
      () => cas.verify(readCertsFromFile(cert_leaf_github)),
      /Certificate is not trusted/,
    );
  });
});
