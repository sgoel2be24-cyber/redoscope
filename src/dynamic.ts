/**
 * Measures what a witness actually costs, instead of asserting what it should.
 *
 * Static analysis says a pattern is ambiguous. That is a claim about the
 * automaton, not about any engine: V8 can defeat some ambiguity outright with
 * literal prefilters, and an ambiguous pattern with no way to fail is not
 * exploitable at all. So the attack is run for real, on an escalating ladder
 * of input sizes, and the growth rate is fitted from the numbers that come
 * back. "1.98^n, 512ms at n=26" is a fact; "possibly vulnerable" is not.
 *
 * This file owns the Node process harness. The fitting lives in `growth.ts`
 * so other runtimes reach identical verdicts.
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { Attack } from "./witness.ts";
import { renderAttack } from "./witness.ts";
import {
  classify,
  EXPONENTIAL_LADDER,
  POLYNOMIAL_LADDER,
  SEVERITY,
  SIGNIFICANT_MS,
  STOP_MS,
  type DynamicResult,
  type TimingSample,
} from "./growth.ts";

export { projectMs, repetitionsToExceed } from "./growth.ts";
export type { DynamicResult, Growth, TimingSample } from "./growth.ts";

// Running from source, the probe is TypeScript; from the published package
// it is compiled JavaScript, because Node will not strip types under node_modules.
const FROM_SOURCE = import.meta.url.endsWith(".ts");
const PROBE_PATH = fileURLToPath(new URL(FROM_SOURCE ? "./probe.ts" : "./probe.js", import.meta.url));

export interface DynamicOptions {
  /** Wall-clock budget per attack candidate. */
  timeoutMs?: number;
  /** Skip the large-input ladder. Useful when only exponential matters. */
  skipPolynomialLadder?: boolean;
}

function runLadder(
  source: string,
  flags: string,
  attack: Attack,
  repetitions: number[],
  timeoutMs: number,
): { samples: TimingSample[]; timedOut: boolean; engineError: string | null } {
  const request = JSON.stringify({
    source,
    flags,
    prefix: attack.prefix,
    pump: attack.pump,
    suffix: attack.suffix,
    repetitions,
    stopMs: STOP_MS,
  });

  const args: string[] = ["--no-warnings"];
  // Type stripping is only on by default from Node 23.
  if (FROM_SOURCE && Number(process.versions.node.split(".")[0]) < 23) args.push("--experimental-strip-types");
  args.push(PROBE_PATH, request);

  const result = spawnSync(process.execPath, args, {
    timeout: timeoutMs,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
    killSignal: "SIGKILL",
  });

  const samples: TimingSample[] = [];
  let engineError: string | null = null;

  for (const line of (result.stdout ?? "").split("\n")) {
    if (!line.trim()) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed.error === "string") {
      engineError = parsed.error;
      continue;
    }
    samples.push({
      repetitions: parsed.repetitions as number,
      length: parsed.length as number,
      ms: parsed.ms as number,
      matched: parsed.matched as boolean,
      timedOut: false,
    });
  }

  // Fewer results than rungs means the process was killed mid-match. That
  // unfinished rung is the most informative sample there is, so it is
  // recorded rather than discarded.
  const killed = samples.length < repetitions.length && engineError === null;
  if (killed) {
    const stuckAt = repetitions[samples.length];
    samples.push({
      repetitions: stuckAt,
      length: renderAttack(attack, stuckAt).length,
      ms: timeoutMs,
      matched: false,
      timedOut: true,
    });
  }

  return { samples, timedOut: killed, engineError };
}

/**
 * Try each candidate attack and keep the one that does the most damage.
 *
 * Candidates differ only in their failing suffix, and which suffix works is
 * genuinely hard to predict — so this measures instead of guessing.
 */
export function verify(
  source: string,
  flags: string,
  attacks: Attack[],
  options: DynamicOptions = {},
): DynamicResult {
  const timeoutMs = options.timeoutMs ?? 2000;

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

    let { samples, timedOut, engineError } = runLadder(
      source,
      flags,
      attack,
      EXPONENTIAL_LADDER,
      timeoutMs,
    );

    // Nothing showed up on short inputs. A quadratic curve is invisible at
    // n = 40 but obvious at n = 32000, so escalate before concluding safety.
    const sawNothing = !timedOut && samples.every((s) => s.ms < SIGNIFICANT_MS);
    if (sawNothing && !options.skipPolynomialLadder && engineError === null) {
      const big = runLadder(source, flags, attack, POLYNOMIAL_LADDER, timeoutMs);
      if (big.samples.length > 0) {
        samples = big.samples;
        timedOut = big.timedOut;
        engineError = big.engineError;
      }
    }

    const verdict = classify(samples);
    const candidate: DynamicResult = {
      ...verdict,
      attack,
      samples,
      worst: samples.length > 0 ? samples[samples.length - 1] : null,
      timedOut,
      engineError,
    };

    if (SEVERITY[candidate.growth] > SEVERITY[best.growth]) best = candidate;
    if (best.growth === "exponential") break; // cannot do better
  }

  return best;
}

/**
 * Does `rewrite` stay linear under a set of attacks?
 *
 * Used to check a suggested fix. Unlike `verify`, this does not trust any
 * static verdict: it renders each attack at a large size and times the rewrite
 * directly, in a killable process. A fix that redoscope's model cannot see
 * through — an atomic group behind a lookahead — is still caught here, because
 * a still-quadratic rewrite blows past the budget on a 100k-character input.
 *
 * Returns true only when every attack finishes comfortably and the largest
 * input is no worse than mildly super-linear.
 */
export function measureRewrite(source: string, flags: string, attacks: Attack[]): boolean {
  const SIZES = [25_000, 100_000];
  const BUDGET_MS = 400;
  for (const attack of attacks) {
    if (attack.pump.length === 0) continue;
    const repetitions = SIZES.map((size) => Math.max(1, Math.floor(size / attack.pump.length)));
    const { samples, timedOut } = runLadder(source, flags, attack, repetitions, 2000);
    if (timedOut) return false;
    const done = samples.filter((s) => !s.timedOut);
    if (done.length < repetitions.length) return false; // a rung did not return
    const worst = done[done.length - 1];
    if (worst.ms > BUDGET_MS) return false;
    // Quadratic between 25k and 100k (16× the work) shows as a large ratio.
    const first = done[0];
    if (first.ms > 1 && worst.ms / first.ms > 6) return false;
  }
  return true;
}
