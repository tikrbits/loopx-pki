import {p256} from '@artlab/crypto/p256';
import {SHA256} from '@artlab/crypto/sha256';
import {oids} from '@artlab/crypto/encoding/oids';
import {algs} from '../algs';

const {curves} = oids;

algs.addAsym({
  [curves.P256]: p256,
});

algs.addHash([SHA256]);
