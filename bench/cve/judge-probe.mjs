// Neutral judge probe. Deliberately shares no code with redoscope.
//
// Receives one regex and one attack family, and times `RegExp.prototype.test`
// on the family at escalating sizes. Each result is flushed with writeSync
// before the next — possibly non-terminating — match begins, so the parent
// can kill this process and still read every completed sample.

import fs from "node:fs";

const request = JSON.parse(process.argv[2]);
const flags = request.flags.replace(/[gy]/g, "");

let regex;
try {
  regex = new RegExp(request.source, flags);
} catch (error) {
  fs.writeSync(1, `${JSON.stringify({ error: String(error) })}\n`);
  process.exit(0);
}

const build = (n) => request.pumps.map((p) => p.prefix + p.pump.repeat(n)).join("") + request.suffix;
const sizeOf = (n) => request.pumps.reduce((a, p) => a + p.prefix.length + p.pump.length * n, 0) + request.suffix.length;

for (let i = 0; i < 20; i++) regex.test(build(1));

for (let n = 1; sizeOf(n) <= request.maxChars; n = Math.max(n + 1, Math.ceil(n * 1.25))) {
  const input = build(n);
  const started = process.hrtime.bigint();
  regex.test(input);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  fs.writeSync(1, `${JSON.stringify({ n, length: input.length, ms })}\n`);
  if (ms >= request.stopMs) break;
}
