/**
 * redoscope — public API.
 *
 * The design commitment is that a verdict and its evidence travel together.
 * `inspect` never reports a pattern as dangerous without also handing back
 * the string that makes it dangerous and, unless you ask it not to, the
 * measurement proving that string works.
 */

import type { SourceSpan } from "./analysis.ts";
import { describeAttack, renderAttack } from "./witness.ts";
import { verify, projectMs } from "./dynamic.ts";
import { prepare, withMeasurement, type Report } from "./core.ts";

export { parse } from "./parser.ts";
export { compile, simulate } from "./nfa.ts";
export { analyze } from "./analysis.ts";
export { buildAttacks, renderAttack, describeAttack } from "./witness.ts";
export { verify, projectMs } from "./dynamic.ts";
export { CharSet } from "./charset.ts";
export type { Verdict, AnalysisResult } from "./analysis.ts";
export type { DynamicResult, Growth, TimingSample } from "./dynamic.ts";
export type { Attack } from "./witness.ts";
export type { NFA, Approximations } from "./nfa.ts";

export type { Confidence, Report, Prepared } from "./core.ts";
export { prepare, withMeasurement, fitsWithin } from "./core.ts";

export type { Suggestion, Candidate } from "./suggest.ts";
export { suggestFixes, candidateFixes } from "./suggest.ts";

export interface InspectOptions {
  /** Run the timing harness. On by default; it is what makes a report evidence. */
  measure?: boolean;
  /** Wall-clock budget per attack candidate, in milliseconds. */
  timeoutMs?: number;
  maxStates?: number;
  /**
   * Largest input your code accepts. When set, a pattern is exploitable only
   * if its attack costs a second of CPU within this many characters.
   */
  maxInput?: number;
}

/** Analyse one pattern end to end. */
export function inspect(source: string, flags = "", options: InspectOptions = {}): Report {
  const { report, attacks } = prepare(source, flags, options.maxStates);
  if (attacks.length === 0 || options.measure === false) return report;
  return withMeasurement(report, verify(source, flags, attacks, { timeoutMs: options.timeoutMs }), options.maxInput);
}

/** One-line summary of a report, for terminals and commit messages. */
export function summarize(report: Report): string {
  if (report.error) return `/${report.source}/${report.flags}: ${report.error}`;

  const name = `/${report.source}/${report.flags}`;
  if (report.verdict === "safe") return `${name}: linear`;

  const shape =
    report.verdict === "exponential" ? "exponential" : `polynomial O(n^${report.degree})`;

  if (!report.dynamic) return `${name}: ${shape} (not measured)`;
  if (report.dynamic.growth === "constant" || report.dynamic.growth === "linear") {
    return `${name}: ${shape} in theory, but measured ${report.dynamic.growth} — not exploitable`;
  }

  // The fitted base is growth per *pump repetition*, which equals growth per
  // character only when the pump is one character long. Saying "3.82^n" for a
  // two-character pump would read as a much scarier regex than it is.
  const pumpLength = report.attack?.pump.length ?? 1;
  const measured =
    report.dynamic.base !== null
      ? pumpLength === 1
        ? `${report.dynamic.base.toFixed(2)}^n`
        : `${report.dynamic.base.toFixed(2)}^n per ${pumpLength}-char pump`
      : report.dynamic.exponent !== null
        ? `O(n^${report.dynamic.exponent.toFixed(1)})`
        : report.dynamic.growth;
  const worst = report.dynamic.worst;
  const cost = worst
    ? `, ${worst.timedOut ? `>${worst.ms.toFixed(0)}` : worst.ms.toFixed(0)}ms at ${worst.length} chars`
    : "";
  return `${name}: ${shape}, measured ${measured}${cost}`;
}

export { projectMs as projectMilliseconds };
export type { SourceSpan };
export { describeAttack as formatAttack, renderAttack as buildAttackString };
