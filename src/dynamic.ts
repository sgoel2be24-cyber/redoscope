/**
 * Measures what a witness actually costs, instead of asserting what it should.
 *
 * Static analysis says a pattern is ambiguous. That is a claim about the
 * automaton, not about any engine: V8 can defeat some ambiguity outright with
 * literal prefilters, and an ambiguous pattern with no way to fail is not
 * exploitable at all. So the attack is run for real, on an escalating ladder
 * of input sizes, and the growth rate is fitted from the numbers that come
 * back. "1.98^n, 512ms at n=26" is a fact; "possibly vulnerable" is not.
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { Attack } from "./witness.ts";
import { renderAttack } from "./witness.ts";

const PROBE_PATH = fileURLToPath(new URL("./probe.ts", import.meta.url));

/** Below this, the reading is scheduler noise rather than signal. */
const SIGNIFICANT_MS = 0.5;
/** How hard a single match has to be before escalation stops. */
const STOP_MS = 150;

/**
 * Small repetition counts, stepping by one.
 *
 * The window between "too fast to time" and "too slow to finish" is narrow
 * when the base is large — at 4× per repetition it is barely five rungs wide —
 * so the ladder is fine-grained rather than spaced. Rungs are cheap: the probe
 * stops climbing as soon as one match exceeds `STOP_MS`.
 */
const EXPONENTIAL_LADDER = Array.from({ length: 45 }, (_, i) => i + 4);
/** Large repetition counts, geometric, to expose an exponent. */
const POLYNOMIAL_LADDER = [250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000];

export type Growth = "constant" | "linear" | "polynomial" | "exponential" | "unknown";

export interface TimingSample {
  repetitions: number;
  length: number;
  ms: number;
  matched: boolean;
  timedOut: boolean;
}

export interface DynamicResult {
  growth: Growth;
  /** Measured base for exponential growth, per repetition. */
  base: number | null;
  /** Measured exponent for polynomial growth, against input length. */
  exponent: number | null;
  /** R² of the winning fit, 0..1. */
  fitQuality: number | null;
  /** The attack that hurt most, or null when none could be built. */
  attack: Attack | null;
  samples: TimingSample[];
  /** The largest input that was actually measured. */
  worst: TimingSample | null;
  /** True when the engine had to be killed — the strongest possible signal. */
  timedOut: boolean;
  engineError: string | null;
}

export interface DynamicOptions {
  /** Wall-clock budget per attack candidate. */
  timeoutMs?: number;
  /** Skip the large-input ladder. Useful when only exponential matters. */
  skipPolynomialLadder?: boolean;
}

interface Regression {
  slope: number;
  intercept: number;
  r2: number;
}

/** Ordinary least squares, plus the coefficient of determination. */
function regress(xs: number[], ys: number[]): Regression | null {
  const n = xs.length;
  if (n < 3) return null;

  const meanX = xs.reduce((a, b) => a + b, 0) / n;
  const meanY = ys.reduce((a, b) => a + b, 0) / n;

  let sxy = 0;
  let sxx = 0;
  for (let i = 0; i < n; i++) {
    sxy += (xs[i] - meanX) * (ys[i] - meanY);
    sxx += (xs[i] - meanX) ** 2;
  }
  if (sxx === 0) return null;

  const slope = sxy / sxx;
  const intercept = meanY - slope * meanX;

  let ssRes = 0;
  let ssTot = 0;
  for (let i = 0; i < n; i++) {
    ssRes += (ys[i] - (intercept + slope * xs[i])) ** 2;
    ssTot += (ys[i] - meanY) ** 2;
  }
  const r2 = ssTot === 0 ? 1 : 1 - ssRes / ssTot;
  return { slope, intercept, r2 };
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
  if (Number(process.versions.node.split(".")[0]) < 23) args.push("--experimental-strip-types");
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

function classify(samples: TimingSample[]): {
  growth: Growth;
  base: number | null;
  exponent: number | null;
  fitQuality: number | null;
} {
  const timedOut = samples.some((s) => s.timedOut);
  const usable = samples.filter((s) => !s.timedOut && s.ms >= SIGNIFICANT_MS);

  // A kill on a short input is conclusive on its own: no polynomial of a
  // reasonable degree takes seconds on a few dozen characters.
  const killedEarly = timedOut && samples[samples.length - 1].repetitions <= 64;

  const exponentialFit = regress(
    usable.map((s) => s.repetitions),
    usable.map((s) => Math.log(s.ms)),
  );
  const polynomialFit = regress(
    usable.map((s) => Math.log(s.length)),
    usable.map((s) => Math.log(s.ms)),
  );

  const base = exponentialFit ? Math.exp(exponentialFit.slope) : null;
  const exponent = polynomialFit ? polynomialFit.slope : null;

  if (killedEarly) {
    return { growth: "exponential", base, exponent: null, fitQuality: exponentialFit?.r2 ?? null };
  }
  if (base !== null && base >= 1.2 && (exponentialFit?.r2 ?? 0) >= 0.85) {
    return { growth: "exponential", base, exponent: null, fitQuality: exponentialFit!.r2 };
  }
  if (timedOut) {
    return { growth: "polynomial", base: null, exponent, fitQuality: polynomialFit?.r2 ?? null };
  }
  if (exponent !== null && exponent >= 1.6 && (polynomialFit?.r2 ?? 0) >= 0.85) {
    return { growth: "polynomial", base: null, exponent, fitQuality: polynomialFit!.r2 };
  }
  if (usable.length === 0) {
    return { growth: "constant", base: null, exponent: null, fitQuality: null };
  }
  if (exponent !== null && exponent >= 0.6) {
    return { growth: "linear", base: null, exponent, fitQuality: polynomialFit?.r2 ?? null };
  }
  return { growth: "constant", base: null, exponent, fitQuality: polynomialFit?.r2 ?? null };
}

const SEVERITY: Record<Growth, number> = {
  exponential: 4,
  polynomial: 3,
  linear: 2,
  constant: 1,
  unknown: 0,
};

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
 * Extrapolate the fitted curve to a repetition count that was never run.
 *
 * Useful for reports — "8 seconds at n = 40" lands harder than a slope — but
 * it is an extrapolation, and callers should present it as one.
 */
export function projectMs(result: DynamicResult, repetitions: number): number | null {
  const reference = result.samples.find((s) => !s.timedOut && s.ms >= SIGNIFICANT_MS);
  if (!reference) return null;

  if (result.growth === "exponential" && result.base !== null) {
    return reference.ms * result.base ** (repetitions - reference.repetitions);
  }
  if (result.growth === "polynomial" && result.exponent !== null && reference.repetitions > 0) {
    return reference.ms * (repetitions / reference.repetitions) ** result.exponent;
  }
  return null;
}

/**
 * The smallest attack that would cost at least `ms`.
 *
 * Inverting the curve reads far better than evaluating it: "1 second of CPU
 * from 29 characters of input" is a threat model, whereas "74647 seconds at
 * n=21" is a number nobody can act on.
 */
export function repetitionsToExceed(
  result: DynamicResult,
  ms: number,
  pumpLength: number,
): { repetitions: number; characters: number } | null {
  const reference = result.samples.find((s) => !s.timedOut && s.ms >= SIGNIFICANT_MS);
  if (!reference) return null;

  let repetitions: number;
  if (result.growth === "exponential" && result.base !== null && result.base > 1) {
    repetitions =
      reference.repetitions + Math.log(ms / reference.ms) / Math.log(result.base);
  } else if (result.growth === "polynomial" && result.exponent !== null && result.exponent > 0) {
    repetitions = reference.repetitions * (ms / reference.ms) ** (1 / result.exponent);
  } else {
    return null;
  }

  if (!Number.isFinite(repetitions) || repetitions <= 0) return null;
  const rounded = Math.ceil(repetitions);
  // Beyond this the extrapolation is well past anything measured, and an
  // attacker who needs a gigabyte of input does not have a useful attack.
  if (rounded * pumpLength > 100_000_000) return null;

  const base = result.samples[0];
  const overhead = base ? base.length - base.repetitions * pumpLength : 0;
  return { repetitions: rounded, characters: rounded * pumpLength + Math.max(0, overhead) };
}
