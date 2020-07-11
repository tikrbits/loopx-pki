import fs from 'fs-extra';
import {pem} from '@artlab/crypto/encoding/pem';
import {Certificate} from './models';

export function assert(
  condition: any,
  msg: string = 'no additional info provided',
): asserts condition {
  if (!condition) {
    throw new Error('Assertion Error: ' + msg);
  }
}

export function noop(..._args: unknown[]): void {}

export function readCerts(data: string): Certificate[] {
  const answer: Certificate[] = [];
  for (const block of pem.decode(data)) {
    if (block.type !== 'CERTIFICATE') {
      continue;
    }
    answer.push(<Certificate>Certificate.decode(block.data));
  }
  return answer;
}

export function readCertsFromFile(file: string): Certificate[] {
  return readCerts(fs.readFileSync(file).toString('utf8'));
}
