// Time the Node addon's verify(header, solution) the way a pool calls it.
// Usage: node tests/node_bench.js <equihashverify.node> <proofs.tsv> <iterations> [label]
// Valid proofs are decoded once up front, so only the verify() call is timed.
// Prints one JSON line with CPU and wall time per share for this process.
'use strict';
const fs = require('fs');
const path = require('path');
const [addonPath, proofsPath, iterationsArg, label] = process.argv.slice(2);
if (!addonPath || !proofsPath || !(Number(iterationsArg) > 0))
  throw new Error('usage: node node_bench.js <addon.node> <proofs.tsv> <iterations> [label]');
const addon = require(path.resolve(addonPath));
const iterations = Number(iterationsArg);

const proofs = fs.readFileSync(proofsPath, 'utf8').split('\n')
  .map(line => line.trim().split(/\s+/))
  .filter(fields => fields.length >= 4 && fields[1] === 'valid')
  .map(([, , header, solution]) => ({header: Buffer.from(header, 'hex'), solution: Buffer.from(solution, 'hex')}));
if (!proofs.length) throw new Error('no valid proofs in ' + proofsPath);

for (let i = 0; i < 64; i++) {
  const proof = proofs[i % proofs.length];
  if (addon.verify(proof.header, proof.solution) !== true) throw new Error('warmup proof rejected');
}

let failures = 0;
const cpuStart = process.cpuUsage();
const wallStart = process.hrtime();
for (let i = 0; i < iterations; i++) {
  const proof = proofs[i % proofs.length];
  if (addon.verify(proof.header, proof.solution) !== true) failures++;
}
const wall = process.hrtime(wallStart);
const cpu = process.cpuUsage(cpuStart);
console.log(JSON.stringify({
  label: label || path.resolve(addonPath),
  node: process.version,
  iterations,
  failures,
  cpu_us_per_share: (cpu.user + cpu.system) / iterations,
  wall_us_per_share: (wall[0] * 1e6 + wall[1] / 1e3) / iterations,
}));
process.exit(failures ? 1 : 0);
