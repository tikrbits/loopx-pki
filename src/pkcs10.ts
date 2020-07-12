import {pkcs10} from '@artlab/crypto/encoding/pkcs10';
import {HashCtor} from '@artlab/crypto/types';
import {oids} from '@artlab/crypto/encoding/oids';
import {algs} from './algs';
import {createPublicKeyFromSPKI, AbstractPrivateKey} from './keys';
import {resolveSignatureAlgorithmOID} from './x509';

export class CertificationRequest extends pkcs10.CertificationRequest {
  get pubkey() {
    const info = this.certificationRequestInfo.subjectPublicKeyInfo;
    return createPublicKeyFromSPKI(info);
  }

  static fromPEM<T = CertificationRequest>(str: string): T {
    return <T>(<unknown>new CertificationRequest().fromPEM(str));
  }

  sign(key: AbstractPrivateKey, hash: string | HashCtor = 'sha256') {
    hash = typeof hash === 'string' ? algs.getHash(hash) : hash;
    const oid = resolveSignatureAlgorithmOID(key, hash);
    const raw = this.certificationRequestInfo.encode();
    this.signature.set(key.signer(hash).signMessage(raw));
    this.signatureAlgorithm.algorithm.set(oid);
    return this;
  }

  verify() {
    const sigOid = this.signatureAlgorithm.algorithm.toString();
    const hash = algs.findHashBySig(sigOid);
    if (!hash) {
      throw new Error(
        `Could not compute certificate digest. Unknown signature OID name: ${oids.fname(
          sigOid,
        )}`,
      );
    }
    const info = this.certificationRequestInfo;

    const raw = info.raw ?? info.encode();

    return this.pubkey.verifier(hash).verifyMessage(raw, this.signature.value);
  }
}
