import {CAStore} from './castore';
import {Certificate} from './x509';
import {Validity} from './commons';
import {BadCertificate, CertificateExpired, CertVerifyError, UnknownCA, UnsupportedCertificate} from './errors';
import {Extensions} from './extensions';

export type VerifyCallback = (error: CertVerifyError | undefined, depth: number, certs: Certificate[]) => boolean;

export interface VerifyOptions {
  verify?: VerifyCallback;
  validityCheckDate?: Date;
}

function verifyValidity(cert: Certificate, options: VerifyOptions) {
  const date = options.validityCheckDate;
  if (date) {
    const validity = Validity.fromASN1(cert.tbsCertificate.validity);
    if (date < validity.notBefore || date > validity.notAfter) {
      return new CertificateExpired('Certificate is not valid yet or has expired.', {
        notBefore: validity.notBefore,
        notAfter: validity.notAfter,
        now: date,
      });
    }
  }
}

function verifyWithParent(
  cas: CAStore,
  cert: Certificate,
  parent: Certificate,
): [Certificate, boolean, undefined | Error] {
  let selfsigned = false;
  let error: Error | undefined;
  parent = parent || cas.getIssuer(cert);
  if (!parent) {
    // check for self-signed cert
    if (cert.isIssuer(cert)) {
      selfsigned = true;
      parent = cert;
    }
  }

  if (parent) {
    // FIXME: current CA store implementation might have multiple
    //  certificates where the issuer can't be determined from the
    //  certificate (happens rarely with, eg: old certificates) so normalize
    //  by always putting parents into an array
    //
    // TODO: there's may be an extreme degenerate case currently uncovered
    //  where an old intermediate certificate seems to have a matching parent
    //  but none of the parents actually verify ... but the intermediate
    //  is in the CA and it should pass this check; needs investigation
    const parents = Array.isArray(parent) ? parent.slice() : [parent];

    // try to verify with each possible parent (typically only one)
    let verified = false;
    while (!verified && parents.length > 0) {
      parent = parents.shift();
      try {
        verified = parent.verify(cert);
      } catch (e) {
        // failure to verify, don't care why, try next one
      }
    }

    if (!verified) {
      error = new BadCertificate('Certificate signature is invalid.');
    }
  }

  if (!error && (!parent || selfsigned) && !cas.has(cert)) {
    // no parent issuer and certificate itself is not trusted
    error = new UnknownCA('Certificate is not trusted.');
  }

  return [parent, selfsigned, error];
}

function verifyExtensions(cert: Certificate) {
  // supported extensions
  const supports = ['KEY_USAGE', 'BASIC_CONSTRAINTS'];
  const extensions = Extensions.fromASN1(cert.tbsCertificate.extensions);
  for (const ext of extensions.items) {
    if (ext.critical && !supports.includes(ext.name)) {
      return new UnsupportedCertificate('Certificate has an unsupported critical extension.');
    }
  }
}

export function verify(store: CAStore, chain: Certificate[], options?: VerifyOptions | VerifyCallback) {
  // if a verify callback is passed as the third parameter, package it within
  // the options object. This is to support a legacy function signature that
  // expected the verify callback as the third parameter.
  if (typeof options === 'function') {
    options = {verify: options};
  }

  options = options ?? {};

  // copy cert chain references to another array to protect against changes
  // in verify callback
  chain = chain.slice();
  const certs = chain.slice();

  // if no validityCheckDate is specified, default to the current date. Make
  // sure to maintain the value null because it indicates that the validity
  // period should not be checked.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const validityCheckDate = options.validityCheckDate ?? new Date();

  // verify each cert in the chain using its parent, where the parent
  // is either the next in the chain or from the CA store
  let first = true;
  let depth = 0;
  let error: Error | undefined;

  while (chain.length > 0) {
    const cert = <Certificate>chain.shift();
    let parent: Certificate | undefined;
    let selfsigned = false;

    // 1. check valid time
    error = verifyValidity(cert, options);

    // 2. verify with parent from chain or CA store
    if (!error) {
      [parent, selfsigned, error] = verifyWithParent(store, cert, chain[0]);
    }

    // 3. TODO: check revoked

    // 4. check for matching issuer/subject
    if (!error && parent && !cert.isIssuer(parent)) {
      // parent is not issuer
      error = new BadCertificate('Certificate issuer is invalid.');
    }

    // 5. TODO: check names with permitted names tree

    // 6. TODO: check names against excluded names tree

    // 7. check for unsupported critical extensions
    if (!error) {
      error = verifyExtensions(cert);
    }

    // 8. TODO check for CA if cert is not first or is the only certificate
    //      remaining in chain with no parent or is self-signed
    if (!error && (!first || (chain.length === 0 && (!parent || selfsigned)))) {
      // reference: forge/lib/x509
    }

    if (options.verify) {
      try {
        if (options.verify(error, depth, certs)) {
          error = undefined;
        }
      } catch (e) {
        if (!(e instanceof CertVerifyError)) {
          throw new BadCertificate(e.message);
        }
        throw e;
      }
    }

    if (error) {
      throw error;
    }

    // no longer first cert in chain
    first = false;
    ++depth;
  }

  return true;
}
