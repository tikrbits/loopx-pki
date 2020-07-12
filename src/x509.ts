import {x509} from '@artlab/crypto/encoding/x509';
import {oids} from '@artlab/crypto/encoding/oids';
import {pem} from '@artlab/crypto/encoding/pem';
import fs from 'fs-extra';
import {HashCtor} from '@artlab/crypto';
import {IssuerMisMatchError} from './errors';
import {algs} from './algs';
import {createPublicKeyFromSPKI, PkixPrivateKey, PkixPublicKey} from './keys';
import {PkixCertExtBasicConstraints, PkixCertExtensions} from './extensions';

export class Certificate extends x509.Certificate {
  protected _extensions: PkixCertExtensions;

  get extensions() {
    if (this._extensions) {
      return this._extensions;
    }
    return (this._extensions = PkixCertExtensions.fromASN1(
      this.tbsCertificate.extensions,
    ));
  }

  get basicConstraints() {
    if (!this.extensions || !this.extensions.items) {
      return;
    }
    return <PkixCertExtBasicConstraints>(
      this.extensions.items.find(i => i.id === oids.exts.BASIC_CONSTRAINTS)
    );
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
  sign(key: PkixPrivateKey, hash: string | HashCtor) {
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
        child.tbsCertificate.issuer.names[0]
          ? child.tbsCertificate.issuer.names[0].attributes
          : [],
        this.tbsCertificate.issuer.names[0]
          ? this.tbsCertificate.issuer.names[0].attributes
          : [],
      );
    }

    const sigoid = child.signatureAlgorithm.algorithm.toString();
    const hash = algs.findHashBySig(sigoid);
    if (!hash) {
      throw new Error(
        `Could not compute certificate digest. Unknown signature OID name: ${oids.fname(
          sigoid,
        )}`,
      );
    }

    const raw = child.tbsCertificate.raw ?? child.tbsCertificate.encode();

    return this.pubkey.verifier(hash).verifyMessage(raw, child.signature.value);
  }
}

export function resolveSignatureAlgorithmOID(
  key: PkixPublicKey | PkixPrivateKey,
  hash: string | HashCtor,
) {
  hash = typeof hash === 'string' ? algs.getHash(hash) : hash;
  return (
    oids.foid(key.asym.algo + hash.id.toUpperCase()) || oids.foid(key.asym.algo)
  );
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
