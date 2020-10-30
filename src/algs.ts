import {HashCtor, Asym} from '@loopx/crypto/types';
import {oids} from '@loopx/crypto/encoding/oids';
import {assert} from './utils';

const {foid, fname, findHashBySig} = oids;

export interface OIDs {
  [oid: string]: Asym<any, any>;
}

class Algs {
  protected _asyms: {[name: string]: Asym<any, any>} = {};
  protected _hashes: {[name: string]: HashCtor} = {};

  get asyms() {
    return this._asyms;
  }

  get hashes() {
    return this._hashes;
  }

  addAsym(items: OIDs): void;
  addAsym(oid: string, asym: Asym<any, any>): void;
  addAsym(oid: string | OIDs, asym?: Asym<any, any>): void {
    if (typeof oid === 'string' && asym) {
      oid = {[oid]: asym};
    }

    for (const entry of Object.entries(oid)) {
      const id = foid(entry[0]);
      const name = fname(entry[0]);
      assert(id, `Invalid object identifier: ${id}`);
      assert(!this._asyms[id], `Asym ${name} exists`);
      this._asyms[id] = entry[1];
    }
  }

  findAsym(oid: string) {
    return this._asyms[foid(oid)];
  }

  getAsym(oid: string) {
    const asym = this.findAsym(oid);
    if (!asym) {
      throw new Error(`No asym found: ${fname(oid) || oid}`);
    }
    return asym;
  }

  addHash(hashes: HashCtor[]) {
    for (const hash of hashes) {
      this._hashes[hash.id.toUpperCase()] = hash;
    }
  }

  findHash(id: string) {
    return this._hashes[id] || this._hashes[id.toUpperCase()];
  }

  findHashBySig(sigIdOrName: string) {
    const sid = foid(sigIdOrName);
    if (!sid) {
      return;
    }
    const hid = findHashBySig(sid);
    if (!hid) {
      return;
    }
    return this.findHash(fname(hid));
  }

  getHash(oid: string) {
    const hash = this.findHash(oid);
    if (!hash) {
      throw new Error(`No hash found by oid: ${fname(oid) || oid}`);
    }
    return hash;
  }

  getHashBySig(sigIdOrName: string) {
    const hash = this.findHashBySig(sigIdOrName);
    if (!hash) {
      throw new Error(
        `No hash found for signature algorithm: : ${
          fname(sigIdOrName) || sigIdOrName
        }`,
      );
    }
  }
}

export const algs = new Algs();

export type AsymType = 'unknown' | 'rsa' | 'ecdsa' | 'eddsa';

const ECDSA_CURVES = ['p192', 'p224', 'p256', 'p384', 'p521', 'secp256k1'];
const EDDSA_CURVES = ['ed448', 'ed25519'];

export function getAsymType(asym: string | Asym<any, any>): AsymType {
  asym = typeof asym === 'string' ? algs.findAsym(asym) : asym;
  if (!asym) {
    return 'unknown';
  }
  const id = asym.id.toLowerCase();
  if (id === 'rsa') {
    return 'rsa';
  } else if (ECDSA_CURVES.includes(id)) {
    return 'ecdsa';
  } else if (EDDSA_CURVES.includes(id)) {
    return 'eddsa';
  }
  return 'unknown';
}
