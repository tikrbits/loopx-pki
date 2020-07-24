import {p192} from '@tib/crypto/p192';
import {p224} from '@tib/crypto/p224';
import {p256} from '@tib/crypto/p256';
import {p384} from '@tib/crypto/p384';
import {p521} from '@tib/crypto/p521';
import {secp256k1} from '@tib/crypto/secp256k1';
import {ed448} from '@tib/crypto/ed448';
import {ed25519} from '@tib/crypto/ed25519';
import {rsa} from '@tib/crypto/rsa';

import {MD5} from '@tib/crypto/md5';
import {SHA1} from '@tib/crypto/sha1';
import {SHA224} from '@tib/crypto/sha224';
import {SHA256} from '@tib/crypto/sha256';
import {SHA384} from '@tib/crypto/sha384';
import {SHA512} from '@tib/crypto/sha512';

import {oids} from '@tib/crypto/encoding/oids';
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
