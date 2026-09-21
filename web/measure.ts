/**
 * The browser counterpart of `src/dynamic.ts`.
 *
 * Same ladders, same fitting, same verdicts — only the kill switch differs. A
 * synchronous regex in V8 cannot be interrupted, so each ladder runs in its
 * own Worker and the page calls `terminate()` when the budget runs out. That
 * is the browser's `SIGKILL`.
 */

import {
  classify,
  EXPONENTIAL_LADDER,
  POLYNOMIAL_LADDER,
  SEVERITY,
  SIGNIFICANT_MS,
  STOP_MS,
  type DynamicResult,
  type TimingSample,
} from "../src/growth.ts";
import { renderAttack, type Attack } from "../src/witness.ts";

// Self-contained: serialised into a Blob, so it may not reference anything
// outside its own body.
function probe(): void {
  self.onmessage = (event: MessageEvent) => {
    const r = event.data;
    let regex: RegExp;
    try {
      regex = new RegExp(r.source, r.flags.replace(/[gy]/g, ""));
    } catch (error) {
      postMessage({ error: String(error) });
      return;
    }
    const warmup = r.prefix + r.pump + r.suffix;
    for (let i = 0; i < 50; i++) regex.test(warmup);
    for (const repetitions of r.repetitions) {
      const input = r.prefix + r.pump.repeat(repetitions) + r.suffix;
      const started = performance.now();
      const matched = regex.test(input);
      const ms = performance.now() - started;
      postMessage({ repetitions, length: input.length, ms, matched });
      if (ms > r.stopMs) break;
    }
    postMessage({ done: true });
  };
}

let probeUrl: string | null = null;
function probeWorker(): Worker {
  probeUrl ??= URL.createObjectURL(new Blob([`(${probe.toString()})()`], { type: "text/javascript" }));
  return new Worker(probeUrl);
}

export type SampleListener = (sample: TimingSample, attack: Attack) => void;

export function runLadderExposed(
  source: string,
  flags: string,
  attack: Attack,
  repetitions: number[],
  timeoutMs: number,
  onSample: SampleListener,
  signal?: AbortSignal,
): Promise<{ samples: TimingSample[]; timedOut: boolean; engineError: string | null }> {
  return new Promise((resolve) => {
    const worker = probeWorker();
    const samples: TimingSample[] = [];
    let settled = false;
    const finish = (timedOut: boolean, engineError: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abandon);
      worker.terminate();
      if (timedOut) {
        const stuckAt = repetitions[samples.length];
        const killed: TimingSample = {
          repetitions: stuckAt,
          length: renderAttack(attack, stuckAt).length,
          ms: timeoutMs,
          matched: false,
          timedOut: true,
        };
        samples.push(killed);
        onSample(killed, attack);
      }
      resolve({ samples, timedOut, engineError });
    };
    // Unlike a child process, a worker cannot be read after death, so a kill
    // is only a kill when a rung was still pending.
    const abandon = () => finish(false, "cancelled");
    signal?.addEventListener("abort", abandon);
    const timer = setTimeout(() => finish(samples.length < repetitions.length, null), timeoutMs);
    worker.onmessage = (event: MessageEvent) => {
      const data = event.data;
      if (data.error) return finish(false, data.error);
      if (data.done) return finish(false, null);
      const sample: TimingSample = { ...data, timedOut: false };
      samples.push(sample);
      onSample(sample, attack);
    };
    worker.postMessage({ source, flags, ...attack, repetitions, stopMs: STOP_MS });
  });
}

/** Mirrors `verify` in `src/dynamic.ts`, asynchronously. */
export async function verifyInBrowser(
  source: string,
  flags: string,
  attacks: Attack[],
  onSample: SampleListener,
  signal?: AbortSignal,
  timeoutMs = 2000,
): Promise<DynamicResult> {
  let best: DynamicResult = {
    growth: "unknown",
    base: null,
    exponent: null,
    fitQuality: null,
    attack: null,
    samples: [],
    worst: null,
    timedOut: false,
    engineError: null,
  };

  for (const attack of attacks) {
    if (attack.pump.length === 0) continue;
    if (signal?.aborted) break;
    let { samples, timedOut, engineError } = await runLadderExposed(source, flags, attack, EXPONENTIAL_LADDER, timeoutMs, onSample, signal);

    const sawNothing = !timedOut && samples.every((s) => s.ms < SIGNIFICANT_MS);
    if (sawNothing && engineError === null && !signal?.aborted) {
      const big = await runLadderExposed(source, flags, attack, POLYNOMIAL_LADDER, timeoutMs, onSample, signal);
      if (big.samples.length > 0) ({ samples, timedOut, engineError } = big);
    }

    const candidate: DynamicResult = {
      ...classify(samples),
      attack,
      samples,
      worst: samples.at(-1) ?? null,
      timedOut,
      engineError,
    };
    if (SEVERITY[candidate.growth] > SEVERITY[best.growth]) best = candidate;
    if (best.growth === "exponential") break;
  }
  return best;
}

/**
 * Browser twin of `measureRewrite`: does the rewrite stay linear under these
 * attacks? Renders each attack at 25k and 100k characters, times it in a
 * terminable worker, and rejects anything slow or clearly super-linear.
 */
export async function measureRewriteInBrowser(source: string, flags: string, attacks: Attack[]): Promise<boolean> {
  const SIZES = [25_000, 100_000];
  const BUDGET_MS = 400;
  for (const attack of attacks) {
    if (attack.pump.length === 0) continue;
    const repetitions = SIZES.map((size) => Math.max(1, Math.floor(size / attack.pump.length)));
    const samples: TimingSample[] = [];
    let killed = false;
    await runLadderExposed(source, flags, attack, repetitions, 2000, (s) => samples.push(s)).then((r) => (killed = r.timedOut));
    if (killed) return false;
    const done = samples.filter((s) => !s.timedOut);
    if (done.length < repetitions.length) return false;
    const worst = done[done.length - 1];
    if (worst.ms > BUDGET_MS) return false;
    if (done[0].ms > 1 && worst.ms / done[0].ms > 6) return false;
  }
  return true;
}
