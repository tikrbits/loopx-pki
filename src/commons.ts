import {oids} from '@tib/crypto/encoding/oids';
import {asn1} from '@tib/crypto/encoding/asn1';
import {x509} from '@tib/crypto/encoding/x509';

export const EMPTY = Buffer.allocUnsafe(0);

export const AttrNameShortToFull: Record<string, string> = {
  CN: 'COMMONNAME',
  C: 'COUNTRY',
  L: 'LOCALITY',
  ST: 'PROVINCE',
  O: 'ORGANIZATION',
  OU: 'ORGANIZATIONALUNIT',
  E: 'EMAIL',
};

export const AttrNameFullToShort: Record<string, string> = Object.keys(
  AttrNameShortToFull,
).reduce((o, k) => ({[k]: AttrNameShortToFull[k], ...o}), {});

export class Validity {
  notBefore: Date;
  notAfter: Date;

  constructor({notBefore, notAfter}: {notBefore: Date; notAfter: Date}) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }

  static fromASN1(validity: x509.Validity) {
    const notBefore = new Date(validity.notBefore.node.value * 1000);
    const notAfter = new Date(validity.notAfter.node.value * 1000);
    return new Validity({notBefore, notAfter});
  }

  toASN1(validity?: x509.Validity) {
    validity = validity ?? new x509.Validity();
    validity.notBefore.node.set(Math.floor(this.notBefore.getTime() / 1000));
    validity.notAfter.node.set(Math.floor(this.notAfter.getTime() / 1000));
    return validity;
  }
}

export interface AttrProps {
  id: string;
  value: any;
  type?: string;
}

export class Attr {
  id: string;

  value: any;
  type?: string;

  constructor(options: AttrProps);
  constructor(id: string, value: any, type?: string);
  constructor(id: string | AttrProps, value?: any, type?: string) {
    if (typeof id !== 'string') {
      type = id.type;
      value = id.value;
      id = id.id;
    }
    const idOrName = id.toUpperCase();
    this.id = oids.foid(AttrNameShortToFull[idOrName] || idOrName);
    this.value = value;
    this.type = type;
  }

  static fromASN1(attribute: x509.Attribute) {
    return new Attr(
      attribute.id.toString(),
      attribute.value.node.value,
      attribute.value.node.constructor.name,
    );
  }

  valueAsASN1() {
    const Type = this.type ? (asn1 as any)[this.type] : asn1.PrintString;
    return new Type(this.value);
  }

  toASN1() {
    return new x509.Attribute(oids.foid(this.id), this.valueAsASN1());
  }

  get name() {
    return oids.attrsByVal[this.id];
  }

  get shortName() {
    return AttrNameFullToShort[this.name];
  }
}

export class RDNs extends Array<Attr> {
  constructor(attrs?: AttrProps[]) {
    super();
    attrs = attrs ?? [];
    this.push(...attrs.map(attr => new Attr(attr)));
  }

  static fromASN1(rdns: x509.RDNSequence) {
    return new RDNs().fromASN1(rdns);
  }

  fromASN1(rdns: x509.RDNSequence) {
    this.clean();
    for (const rdn of rdns.names) {
      for (const attribute of rdn.attributes) {
        this.add(attribute);
      }
    }

    return this;
  }

  toASN1(rdns?: x509.RDNSequence) {
    rdns = rdns ?? new x509.RDNSequence();
    // TODO support comapact mode?
    // for (const attr of this) {
    //   if (!rdns.names[0]) {
    //     rdns.names[0] = new x509.RDN(attr.id, attr.valueAsASN1());
    //   } else {
    //     rdns.names[0].attributes.push(attr.toASN1());
    //   }
    // }
    for (const attr of this) {
      rdns.names.push(new x509.RDN(attr.id, attr.valueAsASN1()));
    }
    return rdns;
  }

  _find(filter: string): [number, Attr?] {
    filter = filter.toUpperCase();
    for (let i = 0; i < this.length; i++) {
      const item = this[i];
      if (
        item.id === filter ||
        item.name === filter ||
        item.shortName === filter
      ) {
        return [i, item];
      }
    }
    return [-1];
  }

  /**
   *
   * @param filter id, name or shortName
   */
  findByFilter(filter: string) {
    const [, found] = this._find(filter);
    return found;
  }

  add(attribute: x509.Attribute): Attr;
  add(id: string, value: any): Attr;
  add(id: string | x509.Attribute, value?: any) {
    const attr =
      typeof id === 'string' ? new Attr(id, value) : Attr.fromASN1(id);
    this.push(attr);
    return attr;
  }

  remove(filter: string) {
    const [index, found] = this._find(filter);
    if (found) {
      this.splice(index, 1);
    }
  }

  clean() {
    this.length = 0;
  }

  set(attrs: {[id: string]: any}) {
    this.clean();
    for (const name of Object.keys(attrs)) {
      this.add(name, attrs[name]);
    }
  }
}

export class SignatureAlgorithm {
  algorithm: string;

  constructor(algorithm?: string) {
    this.algorithm = algorithm ?? oids.NONE;
  }

  static fromASN1(ai: x509.AlgorithmIdentifier) {
    return new SignatureAlgorithm(ai.algorithm.toString());
  }

  toASN1(ai?: x509.AlgorithmIdentifier) {
    ai = ai ?? new x509.AlgorithmIdentifier();
    ai.algorithm.set(oids.foid(this.algorithm));
    return ai;
  }
}
