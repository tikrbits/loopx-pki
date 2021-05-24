import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {pkcs8} from '@loopx/crypto/encoding/pkcs8';
import {pem} from '@loopx/crypto/encoding/pem';
import {pemcrypt} from '@loopx/crypto/encoding/pemcrypt';
import {Asym, ECDSA} from '@loopx/crypto/types';
import {algs, getAsymType} from '../algs';
import {AbstractPrivateKey} from './key';
import {RSAPrivateKey, RSAPublicKey} from './rsa';
import {ECDSAPrivateKey, ECDSAPublicKey} from './ecdsa';
import {EDDSAPrivateKey, EDDSAPublicKey} from './eddsa';

/** Public Key Generations **/
export function createPublicKey(algo: string | Asym<any, any>, key: Buffer, compress?: boolean) {
  const asym = typeof algo === 'string' ? algs.getAsym(algo) : algo;
  const type = getAsymType(asym);

  switch (type) {
    case 'rsa':
      return new RSAPublicKey(key);
    case 'ecdsa':
      return new ECDSAPublicKey(asym, (<ECDSA>asym).publicKeyConvert(key, compress));
    case 'eddsa':
      return new EDDSAPublicKey(asym, key);
    default:
      throw new Error(`Unsupported algorithm: ${asym.id}`);
  }
}

export function createPublicKeyFromASN1(algo: string | Asym<any, any>, key: Buffer, compress?: boolean) {
  return createPublicKey(algo, key, compress);
}

export function createPublicKeyFromPKCS1(raw: Buffer) {
  return new RSAPublicKey(raw);
}

export function createPublicKeyFromSPKI(input: Buffer | x509.SubjectPublicKeyInfo) {
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
export function createPrivateKey(algo: string | Asym<any, any>, key?: Buffer | null): AbstractPrivateKey {
  const asym = typeof algo === 'string' ? algs.getAsym(algo) : algo;
  const type = getAsymType(asym);

  switch (type) {
    case 'rsa':
      return new RSAPrivateKey(key);
    case 'ecdsa':
      return new ECDSAPrivateKey(asym, key);
    case 'eddsa':
      return new EDDSAPrivateKey(asym, key);
    default:
      throw new Error(`Unsupported algorithm: ${asym.id}`);
  }
}

export function createPrivateKeyFromASN1(algo: string | Asym<any, any>, key?: Buffer | null) {
  const priv = createPrivateKey(algo, null);
  if (key) priv.import(key);
  return priv;
}

export function createPrivateKeyFromPKCS1(raw: Buffer) {
  return new RSAPrivateKey(raw);
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

export function createPrivateKeyFromPEM(data: string | Buffer, passphrase?: string): AbstractPrivateKey {
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
