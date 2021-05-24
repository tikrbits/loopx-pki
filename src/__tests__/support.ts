import util = require('util');
import fs = require('fs');
import path = require('path');

export function inspect(target: any) {
  console.log(util.inspect(target, false, 10, true));
}

export function resolveFixturePath(...pathSegments: string[]) {
  return path.resolve(__dirname, 'fixtures', ...pathSegments);
}

export function readFixtureAsString(...pathSegments: string[]) {
  return fs.readFileSync(path.resolve(__dirname, 'fixtures', ...pathSegments)).toString();
}

export function readFixtureAsJSON(...pathSegments: string[]) {
  return JSON.parse(readFixtureAsString(...pathSegments));
}
