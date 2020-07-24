import {p256} from '@tib/crypto/p256';
import {SHA256} from '@tib/crypto/sha256';
import {oids} from '@tib/crypto/encoding/oids';
import {algs} from '../algs';

const {curves} = oids;

algs.addAsym({
  [curves.P256]: p256,
});

algs.addHash([SHA256]);
