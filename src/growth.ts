/**
 * Turning timings into a growth verdict. Pure arithmetic, no I/O.
 *
 * Kept apart from the process-spawning harness in `dynamic.ts` so that any
 * runtime able to time a regex — Node, a browser worker — reaches the same
 * verdict from the same samples.
 */

import type { Attack } from "./witness.ts";

/** Below this, the reading is scheduler noise rather than signal. */
export const SIGNIFICANT_MS = 0.5;
/** How hard a single match has to be before escalation stops. */
export const STOP_MS = 150;

/**
 * Small repetition counts, stepping by one.
 *
 * The window between "too fast to time" and "too slow to finish" is narrow
 * when the base is large — at 4× per repetition it is barely five rungs wide —
 * so the ladder is fine-grained rather than spaced. Rungs are cheap: the probe
 * stops climbing as soon as one match exceeds `STOP_MS`.
 */
export const EXPONENTIAL_LADDER = Array.from({ length: 45 }, (_, i) => i + 4);
/** Large repetition counts, geometric, to expose an exponent. */
export const POLYNOMIAL_LADDER = [250, 500, 1000, 2000, 4000, 8000, 16000, 32000, 64000];

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

export function classify(samples: TimingSample[]): {
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

export const SEVERITY: Record<Growth, number> = {
  exponential: 4,
  polynomial: 3,
  linear: 2,
  constant: 1,
  unknown: 0,
};

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

