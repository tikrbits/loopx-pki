import {BufferReader, StaticWriter} from '@loopx/bufio';
import {oids} from '@loopx/crypto/encoding/oids';
import {asn1} from '@loopx/crypto/encoding/asn1';
import {x509} from '@loopx/crypto/encoding/x509';
import {assert} from './utils';

export interface ExtensionOptions {
  critical?: boolean;
  value?: Buffer;

  [prop: string]: any;
}

export interface ExtensionParams extends ExtensionOptions {
  id: string;
}

export class Extension {
  static id = oids.NONE;

  critical: boolean;

  constructor(params: ExtensionParams) {
    this.check(params);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {id, critical, value, ...others} = params;
    this.critical = !!critical;
    if (value) {
      this.value = value;
    } else {
      Object.assign(this, others);
    }
  }

  protected check(params: ExtensionParams) {
    assert(
      oids.foid(params.id) === this.id,
      `'params.id'(${params.id}) is not match with current extension's id ${
        (<typeof Extension>this.constructor).id
      }`,
    );
  }

  get id() {
    return (<typeof Extension>this.constructor).id;
  }

  get name() {
    return oids.fname(this.id);
  }

  get value() {
    throw new Error('Unimplemented');
  }

  set value(value: Buffer) {
    throw new Error('Unimplemented');
  }
}

export class GenericExtension extends Extension {
  protected _id: string;
  protected _value: Buffer;

  constructor(params: ExtensionParams) {
    super(params);
    this._id = oids.foid(params.id);
  }

  protected check(params: ExtensionParams) {
    assert(
      Buffer.isBuffer(params.value) && params.value.length > 0,
      'params.value is required and should not be empty',
    );
  }

  get id() {
    return this._id;
  }

  get value(): Buffer {
    return this._value;
  }

  set value(value: Buffer) {
    this._value = value;
  }
}

export interface KeyUsageExtensionOptions extends ExtensionOptions {
  digitalSignature?: boolean;
  nonRepudiation?: boolean;
  keyEncipherment?: boolean;
  dataEncipherment?: boolean;
  keyAgreement?: boolean;
  keyCertSign?: boolean;
  cRLSign?: boolean;
  encipherOnly?: boolean;
  decipherOnly?: boolean;
}

export class KeyUsageExtension
  extends Extension
  implements KeyUsageExtensionOptions {
  static id: string = oids.exts.KEY_USAGE;

  digitalSignature: boolean;
  nonRepudiation: boolean;
  keyEncipherment: boolean;
  dataEncipherment: boolean;
  keyAgreement: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
  encipherOnly: boolean;
  decipherOnly: boolean;

  get value(): Buffer {
    const bs = new asn1.BitString();
    bs.set(7);
    if (this.digitalSignature) {
      bs.setBit(0, 1);
    }
    if (this.nonRepudiation) {
      bs.setBit(1, 1);
    }
    if (this.keyEncipherment) {
      bs.setBit(2, 1);
    }
    if (this.dataEncipherment) {
      bs.setBit(3, 1);
    }
    if (this.keyAgreement) {
      bs.setBit(4, 1);
    }
    if (this.keyCertSign) {
      bs.setBit(5, 1);
    }
    if (this.cRLSign) {
      bs.setBit(6, 1);
    }
    if (this.encipherOnly) {
      bs.setBit(7, 1);
    }
    if (this.decipherOnly) {
      bs.setBit(0, 1);
    }
    return bs.encode();
  }

  set value(value: Buffer) {
    const node: asn1.BitString = asn1.BitString.decode(value);
    this.digitalSignature = !!node.getBit(0);
    this.nonRepudiation = !!node.getBit(1);
    this.keyEncipherment = !!node.getBit(2);
    this.dataEncipherment = !!node.getBit(3);
    this.keyAgreement = !!node.getBit(4);
    this.keyCertSign = !!node.getBit(5);
    this.cRLSign = !!node.getBit(6);
    this.encipherOnly = !!node.getBit(7);
    this.decipherOnly = !!node.getBit(0);
  }
}

export class BasicConstraints extends asn1.Sequence {
  _ca?: asn1.Bool;
  _maxPathLen?: asn1.Integer;

  constructor() {
    super();
  }

  get ca(): boolean | undefined {
    return this._ca?.value;
  }

  set ca(value: boolean | undefined) {
    if (value == null) {
      this._ca = undefined;
      return;
    }
    if (!this._ca) {
      this._ca = new asn1.Bool();
    }
    this._ca.set(value);
  }

  get maxPathLen(): number | undefined {
    return this._maxPathLen?.toNumber();
  }

  set maxPathLen(value: number | undefined) {
    if (value == null) {
      this._maxPathLen = undefined;
      return;
    }
    if (!this._maxPathLen) {
      this._maxPathLen = new asn1.Integer();
    }
    this._maxPathLen.set(value);
  }

  get isRaw() {
    return true;
  }

  getBodySize() {
    let size = 0;
    if (this._ca) {
      size += this._ca.getSize();
    }

    if (this._maxPathLen) {
      size += this._maxPathLen.getSize();
    }

    return size;
  }

  writeBody(bw: StaticWriter) {
    if (this._ca) {
      this._ca.write(bw);
    }
    if (this._maxPathLen) {
      this._maxPathLen.write(bw);
    }
    return bw;
  }

  readBody(br: BufferReader) {
    if (br.left()) {
      this._ca = this._ca ?? new asn1.Bool();
      this._ca.read(br);
    }

    if (br.left()) {
      this._maxPathLen = this._maxPathLen ?? new asn1.Integer();
      this._maxPathLen.read(br);
    }

    return this;
  }

  clean() {
    return this._ca?.clean() !== false && this._maxPathLen?.clean() !== false;
  }
}

export interface BasicConstraintsExtensionOptions extends ExtensionOptions {
  ca?: boolean;
  maxPathLen?: number;
}

export class BasicConstraintsExtension
  extends Extension
  implements BasicConstraintsExtensionOptions {
  static id: string = oids.exts.BASIC_CONSTRAINTS;

  ca?: boolean;
  maxPathLen?: number;

  get value(): Buffer {
    const bc = new BasicConstraints();
    bc.ca = !!this.ca;
    bc.maxPathLen = this.maxPathLen;
    return bc.encode();
  }

  set value(value: Buffer) {
    const bc = <BasicConstraints>BasicConstraints.decode(value);
    this.ca = !!bc.ca;
    this.maxPathLen = bc.maxPathLen;
  }
}

type PkixCertExtClass = typeof Extension;

const PkixCertExtensionClasses: PkixCertExtClass[] = [
  KeyUsageExtension,
  BasicConstraintsExtension,
];

export function createExtension(ext: ExtensionParams): Extension;
export function createExtension(
  id: string,
  options: Buffer | asn1.OctString | Partial<ExtensionOptions>,
): Extension;
export function createExtension(
  id: string | ExtensionParams,
  options?: Buffer | asn1.OctString | Partial<ExtensionOptions>,
): Extension {
  let ext: ExtensionParams;
  if (typeof id === 'string') {
    // flat params
    assert(options, '`options` is required when id is string');
    if (Buffer.isBuffer(options)) {
      ext = {id, value: options};
    } else {
      ext = {id, ...options};
    }
  } else {
    ext = id;
  }

  const Ext =
    PkixCertExtensionClasses.find(
      cls => cls.id === ext.id || cls.id === oids.foid(ext.id),
    ) ?? GenericExtension;
  return new Ext(ext);
}

// function isOctString(x: any): x is asn1.OctString {
//   return x.type === asn1.types.OCTSTRING;
// }

export class Extensions {
  protected _items: Extension[];

  constructor(exts?: ExtensionParams[]) {
    this._items = [];
    if (exts) {
      this.add(exts);
    }
  }

  static fromASN1(extensions: x509.Extensions) {
    const answer = new Extensions();
    for (const e of extensions.extensions) {
      answer.add({
        id: e.extnID.toString(),
        value: e.extnValue.value,
        critical: e.critical.value,
      });
    }
    return answer;
  }

  toASN1(extensions?: x509.Extensions, clean?: boolean) {
    extensions = extensions ?? new x509.Extensions();
    if (clean) {
      extensions.clean();
    }
    for (const ext of this._items) {
      const e = new x509.Extension();
      e.extnID.set(ext.id);
      e.critical.set(ext.critical);
      e.extnValue.set(ext.value);
      extensions.extensions.push(e);
    }
    return extensions;
  }

  get items(): Extension[] {
    return this._items;
  }

  add(
    exts: Extension | Extension[] | ExtensionParams | ExtensionParams[],
  ): void;
  add(id: string, options: Buffer | Partial<ExtensionOptions>): void;
  add(
    id: string | Extension | Extension[] | ExtensionParams | ExtensionParams[],
    options?: Buffer | Partial<ExtensionOptions>,
  ): void {
    let exts: (Extension | ExtensionParams)[];
    if (typeof id === 'string') {
      // flat params
      assert(options, '`options` is required when id is string');
      if (Buffer.isBuffer(options)) {
        exts = [{id, value: options}];
      } else {
        exts = [{id, ...options}];
      }
    } else if (!Array.isArray(id)) {
      // PkixCertExt or PkixCertExtParams
      exts = [id];
    } else {
      // PkixCertExt[] or PkixCertExtParams[]
      exts = id;
    }

    for (const ext of exts) {
      if (ext instanceof Extension) {
        this._items.push(ext);
      } else {
        this._items.push(createExtension(ext));
      }
    }
  }
}
