/**
 * Child-process timing probe. Never import this — it is spawned.
 *
 * Runs a regex against progressively longer attack strings and reports each
 * result on its own line. It has to be a separate process because the whole
 * point is to run regexes that may not terminate in any reasonable time: the
 * parent kills it on a timeout, and a killed process is the only reliable way
 * to abandon a synchronous regex in V8.
 *
 * Results are written with `fs.writeSync` rather than `console.log` so every
 * line is on disk before the next, possibly non-returning, match begins.
 */

import fs from "node:fs";

interface ProbeRequest {
  source: string;
  flags: string;
  prefix: string;
  pump: string;
  suffix: string;
  repetitions: number[];
  /** Stop escalating once a single match exceeds this. */
  stopMs: number;
}

function main(): void {
  const request: ProbeRequest = JSON.parse(process.argv[2]);

  // `g` and `y` make `.test` stateful via lastIndex, which would silently
  // corrupt every measurement after the first.
  const flags = request.flags.replace(/[gy]/g, "");

  let regex: RegExp;
  try {
    regex = new RegExp(request.source, flags);
  } catch (error) {
    fs.writeSync(1, `${JSON.stringify({ error: String(error) })}\n`);
    return;
  }

  // Let the JIT settle so the first real sample is not measuring compilation.
  const warmup = request.prefix + request.pump + request.suffix;
  for (let i = 0; i < 50; i++) regex.test(warmup);

  for (const repetitions of request.repetitions) {
    const input = request.prefix + request.pump.repeat(repetitions) + request.suffix;
    const started = process.hrtime.bigint();
    const matched = regex.test(input);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;

    fs.writeSync(1, `${JSON.stringify({ repetitions, length: input.length, ms, matched })}\n`);
    if (ms > request.stopMs) return;
  }
}

main();
