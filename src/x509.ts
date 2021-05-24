import {x509} from '@loopx/crypto/encoding/x509';
import {oids} from '@loopx/crypto/encoding/oids';
import {pem} from '@loopx/crypto/encoding/pem';
import fs from 'fs-extra';
import {HashCtor} from '@loopx/crypto';
import {IssuerMisMatchError} from './errors';
import {algs} from './algs';
import {createPublicKeyFromSPKI, AbstractPrivateKey, AbstractPublicKey} from './keys';
import {BasicConstraintsExtension, Extensions} from './extensions';

export class Certificate extends x509.Certificate {
  protected _extensions: Extensions;

  get extensions() {
    if (this._extensions) {
      return this._extensions;
    }
    return (this._extensions = Extensions.fromASN1(this.tbsCertificate.extensions));
  }

  get basicConstraints() {
    if (!this.extensions || !this.extensions.items) {
      return;
    }
    return <BasicConstraintsExtension>this.extensions.items.find(i => i.id === oids.exts.BASIC_CONSTRAINTS);
  }

  get isCA(): boolean {
    return !!this.basicConstraints?.ca;
  }

  get maxPathLen(): number | undefined {
    return this.basicConstraints?.maxPathLen;
  }

  isIssuer(parent: Certificate) {
    const i = this.tbsCertificate.issuer;
    const s = parent.tbsCertificate.subject;

    return i.encode().equals(s.encode());
  }

  issued(child: Certificate) {
    return child.isIssuer(this);
  }

  get pubkey() {
    const info = this.tbsCertificate.subjectPublicKeyInfo;
    return createPublicKeyFromSPKI(info);
  }

  /**
   *
   * @param key private key
   * @param hash signature algorithm
   */
  sign(key: AbstractPrivateKey, hash: string | HashCtor) {
    hash = typeof hash === 'string' ? algs.getHash(hash) : hash;
    const oid = resolveSignatureAlgorithmOID(key, hash);

    this.tbsCertificate.signature.algorithm.set(oid);

    const raw = this.tbsCertificate.encode();
    this.signature.set(key.signer(hash).signMessage(raw));

    this.signatureAlgorithm.algorithm.set(oid);
    return this;
  }

  verify(child: Certificate) {
    if (!this.issued(child)) {
      throw new IssuerMisMatchError(
        child.tbsCertificate.issuer.names[0] ? child.tbsCertificate.issuer.names[0].attributes : [],
        this.tbsCertificate.issuer.names[0] ? this.tbsCertificate.issuer.names[0].attributes : [],
      );
    }

    const sigoid = child.signatureAlgorithm.algorithm.toString();
    const hash = algs.findHashBySig(sigoid);
    if (!hash) {
      throw new Error(`Could not compute certificate digest. Unknown signature OID name: ${oids.fname(sigoid)}`);
    }

    const raw = child.tbsCertificate.raw ?? child.tbsCertificate.encode();

    return this.pubkey.verifier(hash).verifyMessage(raw, child.signature.value);
  }
}

export function resolveSignatureAlgorithmOID(key: AbstractPublicKey | AbstractPrivateKey, hash: string | HashCtor) {
  hash = typeof hash === 'string' ? algs.getHash(hash) : hash;
  return oids.foid(key.asym.algo + hash.id.toUpperCase()) || oids.foid(key.asym.algo);
}

export function readCerts(data: string): Certificate[] {
  const answer: Certificate[] = [];
  for (const block of pem.decode(data)) {
    if (block.type !== 'CERTIFICATE') {
      continue;
    }
    answer.push(<Certificate>Certificate.decode(block.data));
  }
  return answer;
}

export function readCertsFromFile(file: string): Certificate[] {
  return readCerts(fs.readFileSync(file).toString('utf8'));
}
