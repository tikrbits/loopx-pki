import {p256} from '@loopx/crypto/p256';
import {SHA256} from '@loopx/crypto/sha256';
import {oids} from '@loopx/crypto/encoding/oids';
import {algs} from '../algs';

const {curves} = oids;

algs.addAsym({
  [curves.P256]: p256,
});

algs.addHash([SHA256]);
