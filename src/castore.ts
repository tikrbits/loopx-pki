/**
 * castore.ts - CA Store
 *
 * Parts of this software are based on digitalbazaar/forge
 *   Copyright (c) 2010, Digital Bazaar, Inc. (BSD-3-Clause OR GPL-2.0)
 *   https://github.com/digitalbazaar/forge
 *
 * Resources:
 *   https://github.com/digitalbazaar/forge/blob/master/lib/x509.js
 */

import fg from 'fast-glob';
import {SHA1} from '@loopx/crypto/sha1';
import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {Certificate, readCerts, readCertsFromFile} from './x509';
import {verify, VerifyCallback, VerifyOptions} from './verifer';

function raw(node: asn1.Node) {
  return node.raw ?? node.encode();
}

function ensureSubjectHash(subject: x509.RDNSequence): string {
  const s = subject as any;
  if (!s._hash) {
    s._hash = SHA1.digest(subject.raw ?? subject.encode()).toString('hex');
  }
  return s._hash;
}

export class CAStore {
  protected certs: {[key: string]: Certificate[]};

  static create(certs?: Certificate[]) {
    return new CAStore(certs);
  }

  constructor(certs?: Certificate[]) {
    this.certs = {};
    if (certs) {
      for (const cert of certs) this.add(cert);
    }
  }

  get count() {
    return Object.values(this.certs).reduce(
      (num, certs) => num + certs.length,
      0,
    );
  }

  protected getBySubject(subject: x509.RDNSequence) {
    return this.certs[ensureSubjectHash(subject)];
  }

  /**
   * Gets the certificate that issued the passed certificate or its
   * 'parent'.
   *
   * @param cert the certificate to get the parent for.
   *
   * @return the parent certificate or null if none was found.
   */
  getIssuer(cert: Certificate) {
    return this.getBySubject(cert.tbsCertificate.issuer);
  }

  /**
   * Checks to see if the given certificate is in the store.
   *
   * @param cert the certificate to check (either a Certificate or a
   *          PEM-formatted certificate).
   *
   * @return true if the certificate is in the store, false if not.
   */
  has(cert: Certificate | string) {
    if (typeof cert === 'string') {
      cert = <Certificate>Certificate.fromPEM(cert);
    }
    const matches = this.getBySubject(cert.tbsCertificate.subject);
    if (matches && matches.length > 0) {
      const target = raw(cert);
      return !!matches.find(c => target.equals(raw(c)));
    }
    return false;
  }

  /**
   * Adds a trusted certificate to the store.
   *
   * @param certs the certificates to add as a trusted certificate (either a
   *          Certificate object or a PEM-formatted certificate).
   */
  add(certs: Certificate | Certificate[] | string) {
    if (typeof certs === 'string') {
      certs = readCerts(certs);
    }

    if (!Array.isArray(certs)) {
      certs = [certs];
    }

    for (const cert of certs) {
      const hash = ensureSubjectHash(cert.tbsCertificate.subject);

      if (!this.has(cert)) {
        if (hash in this.certs) {
          this.certs[hash].push(cert);
        } else {
          this.certs[hash] = [cert];
        }
      }
    }

    return this;
  }

  async load(patterns: string | string[]): Promise<this> {
    const entries = await fg(patterns);

    for (const entry of entries) {
      this.add(readCertsFromFile(entry));
    }

    return this;
  }

  /**
   * Lists all of the certificates kept in the store.
   *
   * @return an array of all of the Certificate objects in the store.
   */
  list() {
    return Object.values(this.certs).reduce((answer: Certificate[], certs) => {
      answer.push(...certs);
      return answer;
    }, []);
  }

  /**
   * Removes a certificate from the store.
   *
   * @param cert the certificate to remove (either a Certificate or a
   *          PEM-formatted certificate).
   *
   * @return the certificate that was removed or null if the certificate
   *           wasn't in store.
   */
  remove(cert: Certificate | string) {
    if (typeof cert === 'string') {
      cert = <Certificate>Certificate.fromPEM(cert);
    }

    if (!this.has(cert)) {
      return;
    }

    const matches = this.getBySubject(cert.tbsCertificate.subject);
    if (!matches || !matches.length) {
      return;
    }

    const hash = ensureSubjectHash(cert.tbsCertificate.subject);

    let answer: Certificate | undefined;
    const target = raw(cert);
    for (let i = 0; i < matches.length; i++) {
      if (target.equals(raw(matches[i]))) {
        answer = matches[i];
        matches.splice(i, 1);
        break;
      }
    }
    if (matches.length === 0) {
      delete this.certs[hash];
    }

    return answer;
  }

  /**
   * Verifies a certificate chain against the given Certificate Authority store
   * with an optional custom verify callback.
   *
   * @param {Certificate | Certificate[] | string} chain the certificate chain
   *                  entity or file to verify, with the root or highest authority
   *                  at the end (an array of certificates).
   * @param options a callback to be called for every certificate in the chain or
   *                  an object with:
   *                  verify a callback to be called for every certificate in the
   *                    chain
   *                  validityCheckDate the date against which the certificate
   *                    validity period should be checked. Pass null to not check
   *                    the validity period. By default, the current date is used.
   *
   * The verify callback has the following signature:
   *
   * verified - Set to true if certificate was verified, otherwise the
   *   pki.certificateError for why the certificate failed.
   * depth - The current index in the chain, where 0 is the end point's cert.
   * certs - The certificate chain, *NOTE* an empty chain indicates an anonymous
   *   end point.
   *
   * The function returns true on success and on failure either the appropriate
   * CertificateError or an object with 'error' set to the appropriate
   * CertificateError and 'message' set to a custom error message.
   *
   * @return true if successful, error thrown if not.
   */
  verify(
    chain: Certificate | Certificate[] | string,
    options?: VerifyOptions | VerifyCallback,
  ): boolean {
    if (typeof chain === 'string') {
      chain = readCertsFromFile(chain);
    }
    if (!Array.isArray(chain)) {
      chain = [chain];
    }
    return verify(this, chain, options);
  }
}
