import {p192} from '@artlab/crypto/p192';
import {p224} from '@artlab/crypto/p224';
import {p256} from '@artlab/crypto/p256';
import {p384} from '@artlab/crypto/p384';
import {p521} from '@artlab/crypto/p521';
import {secp256k1} from '@artlab/crypto/secp256k1';
import {ed448} from '@artlab/crypto/ed448';
import {ed25519} from '@artlab/crypto/ed25519';
import {rsa} from '@artlab/crypto/rsa';

import {MD5} from '@artlab/crypto/md5';
import {SHA1} from '@artlab/crypto/sha1';
import {SHA224} from '@artlab/crypto/sha224';
import {SHA256} from '@artlab/crypto/sha256';
import {SHA384} from '@artlab/crypto/sha384';
import {SHA512} from '@artlab/crypto/sha512';

import {oids} from '@artlab/crypto/encoding/oids';
import {algs} from '../algs';

const {curves, keyAlgs} = oids;

algs.addAsym({
  [curves.P192]: p192,
  [curves.P224]: p224,
  [curves.P256]: p256,
  [curves.P384]: p384,
  [curves.P521]: p521,
  [curves.SECP256K1]: secp256k1,
  [curves.ED448]: ed448,
  [curves.ED25519]: ed25519,
  [keyAlgs.RSA]: rsa,
});

algs.addHash([MD5, SHA1, SHA224, SHA256, SHA384, SHA512]);
