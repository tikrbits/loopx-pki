import {asn1} from '@artlab/crypto/encoding/asn1';
import {x509} from '@artlab/crypto/encoding/x509';
import {pkcs8} from '@artlab/crypto/encoding/pkcs8';
import {pem} from '@artlab/crypto/encoding/pem';
import {pemcrypt} from '@artlab/crypto/encoding/pemcrypt';
import {Asym, ECDSA} from '@artlab/crypto/types';
import {algs, getAsymType} from '../algs';
import {PkixPrivateKey} from './key';
import {PkixRSAPrivateKey, PkixRSAPublicKey} from './rsa';
import {PkixECDSAPrivateKey, PkixECDSAPublicKey} from './ecdsa';
import {PkixEDDSAPrivateKey, PkixEDDSAPublicKey} from './eddsa';

/** Public Key Generations **/
export function createPublicKey(
  algo: string | Asym<any, any>,
  key: Buffer,
  compress?: boolean,
) {
  const asym = typeof algo === 'string' ? algs.getAsym(algo) : algo;
  const type = getAsymType(asym);

  switch (type) {
    case 'rsa':
      return new PkixRSAPublicKey(key);
    case 'ecdsa':
      return new PkixECDSAPublicKey(
        asym,
        (<ECDSA>asym).publicKeyConvert(key, compress),
      );
    case 'eddsa':
      return new PkixEDDSAPublicKey(asym, key);
    default:
      throw new Error(`Unsupported algorithm: ${asym.id}`);
  }
}

export function createPublicKeyFromASN1(
  algo: string | Asym<any, any>,
  key: Buffer,
  compress?: boolean,
) {
  return createPublicKey(algo, key, compress);
}

export function createPublicKeyFromPKCS1(raw: Buffer) {
  return new PkixRSAPublicKey(raw);
}

export function createPublicKeyFromSPKI(
  input: Buffer | x509.SubjectPublicKeyInfo,
  compress?: boolean,
) {
  let spki: x509.SubjectPublicKeyInfo;
  if (Buffer.isBuffer(input)) {
    spki = <x509.SubjectPublicKeyInfo>x509.SubjectPublicKeyInfo.decode(input);
  } else {
    spki = input;
  }

  const {algorithm, parameters} = spki.algorithm;

  const algo = algorithm.toString();
  const isOID = parameters.node.type === asn1.types.OID;
  const curve = isOID ? parameters.node.toString() : '';

  let asym = algs.findAsym(algo);
  if (!asym && curve) {
    asym = algs.findAsym(curve);
  }

  if (!asym) {
    throw new Error(`Unsupported algorithm: (${algo}, ${curve})`);
  }

  return createPublicKeyFromASN1(asym, spki.publicKey.rightAlign());
}

export function createPublicKeyFromPEM(data: string | Buffer) {
  if (Buffer.isBuffer(data)) {
    data = data.toString('utf8');
  }

  const [block] = pem.decode(data);

  if (!block) {
    throw new Error('Invalid pem!');
  }

  if (block.type === 'RSA PUBLIC KEY') {
    return createPublicKeyFromPKCS1(block.data);
  }
  return createPublicKeyFromSPKI(block.data);
}

/** Private Key Generations **/
export function createPrivateKey(
  algo: string | Asym<any, any>,
  key?: Buffer | null,
): PkixPrivateKey {
  const asym = typeof algo === 'string' ? algs.getAsym(algo) : algo;
  const type = getAsymType(asym);

  switch (type) {
    case 'rsa':
      return new PkixRSAPrivateKey(key);
    case 'ecdsa':
      return new PkixECDSAPrivateKey(asym, key);
    case 'eddsa':
      return new PkixEDDSAPrivateKey(asym, key);
    default:
      throw new Error(`Unsupported algorithm: ${asym.id}`);
  }
}

export function createPrivateKeyFromASN1(
  algo: string | Asym<any, any>,
  key?: Buffer | null,
) {
  const priv = createPrivateKey(algo, null);
  if (key) priv.import(key);
  return priv;
}

export function createPrivateKeyFromPKCS1(raw: Buffer) {
  return new PkixRSAPrivateKey(raw);
}

export function createPrivateKeyFromPKCS8(raw: Buffer) {
  const pki: pkcs8.PrivateKeyInfo = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  const algo = algorithm.toString();
  const isOID = parameters.node.type === asn1.types.OID;
  const curve = isOID ? parameters.node.toString() : '';

  let asym = algs.findAsym(algo);
  if (!asym && curve) {
    asym = algs.findAsym(curve);
  }

  if (!asym) {
    throw new Error('Unsupported algorithm: ' + (algo || curve));
  }

  return createPrivateKeyFromASN1(asym, pki.privateKey.value);
}

export function createPrivateKeyFromPEM(
  data: string | Buffer,
  passphrase?: string,
): PkixPrivateKey {
  if (Buffer.isBuffer(data)) {
    data = data.toString('utf8');
  }

  const [block] = pem.decode(data);

  if (!block) {
    throw new Error('Invalid pem!');
  }

  if (passphrase) {
    pemcrypt.decrypt(block, passphrase);
  }

  if (block.type === 'RSA PRIVATE KEY') {
    return createPrivateKeyFromPKCS1(block.data);
  }
  return createPrivateKeyFromPKCS8(block.data);
}
