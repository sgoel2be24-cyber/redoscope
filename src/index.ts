/**
 * redoscope — public API.
 *
 * The design commitment is that a verdict and its evidence travel together.
 * `inspect` never reports a pattern as dangerous without also handing back
 * the string that makes it dangerous and, unless you ask it not to, the
 * measurement proving that string works.
 */

import { parse } from "./parser.ts";
import { compile, PatternTooLargeError, type Approximations } from "./nfa.ts";
import { analyze, type AnalysisResult, type SourceSpan, type Verdict } from "./analysis.ts";
import { buildAttacks, describeAttack, renderAttack, type Attack } from "./witness.ts";
import { verify, projectMs, type DynamicResult, type Growth } from "./dynamic.ts";
import { RegexParseError, walk, type Node } from "./ast.ts";

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

/** How much the static verdict can be trusted, given the modelling shortcuts taken. */
export type Confidence = "measured" | "high" | "reduced";

export interface Report {
  source: string;
  flags: string;
  /** What the automaton says. */
  verdict: Verdict;
  /** 1 for linear, k for Θ(n^k), `Infinity` for exponential. */
  degree: number;
  confidence: Confidence;
  /** The sub-expression responsible, as an offset range into `source`. */
  hotspot: SourceSpan | null;
  /** The generated attack, present whenever the verdict is not "safe". */
  attack: Attack | null;
  /** Measurement, when it was run. */
  dynamic: DynamicResult | null;
  /**
   * Whether the pattern can actually be made slow, as opposed to merely being
   * ambiguous. An ambiguous pattern with no reachable failure is not a bug.
   */
  exploitable: boolean | null;
  approximations: Approximations;
  /** Set when the pattern could not be analysed at all. */
  error: string | null;
}

export interface InspectOptions {
  /** Run the timing harness. On by default; it is what makes a report evidence. */
  measure?: boolean;
  /** Wall-clock budget per attack candidate, in milliseconds. */
  timeoutMs?: number;
  maxStates?: number;
}

/**
 * Grow a hotspot outwards to the whole quantifier that contains it.
 *
 * The analysis points at the individual character edges in the pump, but the
 * inner `a+` of `(a+)+` is perfectly safe on its own — it is the nesting that
 * costs. Reporting the widest enclosing repeat blames the construct a reader
 * actually has to change.
 */
function widenHotspot(root: Node, span: SourceSpan): SourceSpan {
  // Union rather than "smallest enclosing": a polynomial pump straddles two
  // sibling loops, as in `\s*\s*`, and neither one alone contains the span.
  let start = span.start;
  let end = span.end;
  walk(root, (node) => {
    if (node.type !== "Repeat") return;
    if (node.end <= span.start || node.start >= span.end) return; // no overlap
    start = Math.min(start, node.start);
    end = Math.max(end, node.end);
  });
  return { start, end };
}

function confidenceOf(approximations: Approximations, measured: boolean): Confidence {
  if (measured) return "measured";
  // Backreferences and lookaround are modelled as ε, which adds paths the
  // engine may not have. Anchors are modelled the same way but only ever
  // restrict where a match may start, so they do not inflate ambiguity.
  if (approximations.backreference || approximations.lookaround) return "reduced";
  return "high";
}

/** Analyse one pattern end to end. */
export function inspect(source: string, flags = "", options: InspectOptions = {}): Report {
  const measure = options.measure ?? true;

  const failed = (error: string): Report => ({
    source,
    flags,
    verdict: "safe",
    degree: 1,
    confidence: "reduced",
    hotspot: null,
    attack: null,
    dynamic: null,
    exploitable: null,
    approximations: {
      lookaround: false,
      backreference: false,
      wordBoundary: false,
      anchor: false,
      widenedRepeat: false,
    },
    error,
  });

  let analysis: AnalysisResult;
  let nfa;
  let root: Node;
  try {
    const pattern = parse(source, flags);
    root = pattern.root;
    nfa = compile(pattern, { maxStates: options.maxStates });
    analysis = analyze(nfa);
  } catch (error) {
    if (error instanceof RegexParseError || error instanceof PatternTooLargeError) {
      return failed(error.message);
    }
    throw error;
  }

  if (analysis.verdict === "safe" || analysis.witness === null) {
    return {
      source,
      flags,
      verdict: "safe",
      degree: 1,
      confidence: confidenceOf(nfa.approximations, false),
      hotspot: null,
      attack: null,
      dynamic: null,
      exploitable: analysis.truncated ? null : false,
      approximations: nfa.approximations,
      error: null,
    };
  }

  const attacks = buildAttacks(nfa, analysis.witness);
  const dynamic = measure ? verify(source, flags, attacks, { timeoutMs: options.timeoutMs }) : null;

  return {
    source,
    flags,
    verdict: analysis.verdict,
    degree: analysis.degree,
    confidence: confidenceOf(nfa.approximations, dynamic !== null),
    hotspot: analysis.hotspot ? widenHotspot(root, analysis.hotspot) : null,
    attack: dynamic?.attack ?? attacks[0],
    dynamic,
    exploitable: dynamic ? dynamic.growth === "exponential" || dynamic.growth === "polynomial" : null,
    approximations: nfa.approximations,
    error: null,
  };
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
