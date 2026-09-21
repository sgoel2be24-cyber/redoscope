/**
 * The runtime-independent half of `inspect`.
 *
 * Everything up to the point where an attack has to be run lives here, with
 * no Node imports, so a browser gets the same verdict, hotspot and witness as
 * the CLI. The caller supplies the measurement: a child process in Node, a
 * terminable worker in a browser.
 */

import { parse } from "./parser.ts";
import { compile, PatternTooLargeError, type Approximations } from "./nfa.ts";
import { analyze, type AnalysisResult, type SourceSpan, type Verdict } from "./analysis.ts";
import { buildAttacks, type Attack } from "./witness.ts";
import { repetitionsToExceed, type DynamicResult } from "./growth.ts";
import { RegexParseError, walk, type Node } from "./ast.ts";

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

/**
 * Static analysis result. `attacks` is non-empty exactly when the report is
 * still waiting on a measurement to decide `exploitable`.
 */
export interface Prepared {
  report: Report;
  attacks: Attack[];
}

export function prepare(source: string, flags = "", maxStates?: number): Prepared {
  const failed = (error: string): Prepared => ({
    report: {
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
    },
    attacks: [],
  });

  let analysis: AnalysisResult;
  let nfa;
  let root: Node;
  try {
    const pattern = parse(source, flags);
    root = pattern.root;
    nfa = compile(pattern, { maxStates });
    analysis = analyze(nfa);
  } catch (error) {
    if (error instanceof RegexParseError || error instanceof PatternTooLargeError) {
      return failed(error.message);
    }
    throw error;
  }

  if (analysis.verdict === "safe" || analysis.witness === null) {
    return {
      report: {
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
      },
      attacks: [],
    };
  }

  // The primary witness first, then the fallbacks, without repeats.
  const seen = new Set<string>();
  const attacks = [analysis.witness, ...analysis.alternatives]
    .flatMap((witness) => buildAttacks(nfa, witness))
    .filter((attack) => {
      const key = JSON.stringify(attack);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    // Each attack costs a measurement; an inconclusive pattern should not
    // hold a scan hostage.
    .slice(0, 10);
  return {
    report: {
      source,
      flags,
      verdict: analysis.verdict,
      degree: analysis.degree,
      confidence: confidenceOf(nfa.approximations, false),
      hotspot: analysis.hotspot ? widenHotspot(root, analysis.hotspot) : null,
      attack: attacks[0],
      dynamic: null,
      exploitable: null,
      approximations: nfa.approximations,
      error: null,
    },
    attacks,
  };
}

/** What an attack has to cost before it counts. */
export const COST_BUDGET_MS = 1000;

/**
 * Can the measured attack cost a full CPU second without exceeding
 * `maxInput` characters? Uses the kill when there was one, otherwise the
 * fitted curve.
 */
export function fitsWithin(dynamic: DynamicResult, maxInput: number): boolean {
  const attack = dynamic.attack;
  if (!attack) return false;
  if (dynamic.timedOut && dynamic.worst && dynamic.worst.length <= maxInput) return true;
  const needed = repetitionsToExceed(dynamic, COST_BUDGET_MS, attack.pump.length);
  return needed !== null && needed.characters <= maxInput;
}

/**
 * Fold a measurement into a prepared report.
 *
 * With `maxInput`, super-linear growth is not enough: the attack also has to
 * reach a second of CPU within that many characters. Most services cap their
 * inputs, and a quadratic that needs 10 MB to hurt is not a finding for them.
 */
export function withMeasurement(report: Report, dynamic: DynamicResult, maxInput?: number): Report {
  const superLinear = dynamic.growth === "exponential" || dynamic.growth === "polynomial";
  return {
    ...report,
    confidence: "measured",
    attack: dynamic.attack ?? report.attack,
    dynamic,
    exploitable: superLinear && (maxInput === undefined || fitsWithin(dynamic, maxInput)),
  };
}
