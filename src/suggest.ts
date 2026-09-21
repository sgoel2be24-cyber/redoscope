/**
 * Suggest a rewrite that removes the backtracking, and prove it (Node entry).
 *
 * Finding a bug and proving it is most of the job; the rest is telling the
 * developer what to type instead. redoscope does that without pretending to a
 * certainty it does not have. Every suggestion clears two bars:
 *
 *   1. **It is not slow.** The rewrite is stress-tested by running the attack
 *      against it at 100k characters — measurement, not re-analysis, because
 *      an atomic rewrite hides its quantifier behind a lookahead that the
 *      static model reads as empty and would wrongly clear.
 *   2. **It still means the same thing** — for the accept/reject decision a
 *      validator makes. The original and the rewrite run against a corpus of
 *      generated strings (accepting walks, near-misses, the attack itself, and
 *      random noise) and must agree on every one. This is a check, not a
 *      proof, so the count is always reported; any disagreement discards it.
 *
 * A rewrite that changes what is matched (the bounded fallback) says so and
 * never claims equivalence.
 */

import { parse } from "./parser.ts";
import { compile, type NFA } from "./nfa.ts";
import { prepare, type Report } from "./core.ts";
import { measureRewrite } from "./dynamic.ts";
import { candidateFixes, checkEquivalence, summaryFor, type Suggestion } from "./suggest-core.ts";

export type { Suggestion, Candidate, Equivalence } from "./suggest-core.ts";
export { candidateFixes, checkEquivalence, summaryFor } from "./suggest-core.ts";

/** Verify one candidate rewrite is both fast and faithful. */
function assess(source: string, flags: string, nfa: NFA, rewrite: string, kind: Suggestion["kind"]): Suggestion | null {
  if (rewrite === source) return null;
  try {
    void new RegExp(rewrite, flags.replace(/[gy]/g, ""));
  } catch {
    return null;
  }
  const stress = [...prepare(source, flags).attacks, ...prepare(rewrite, flags).attacks];
  if (!measureRewrite(rewrite, flags, stress)) return null;

  const equiv = checkEquivalence(source, rewrite, flags, nfa);
  if (kind !== "bounded" && !equiv.equivalent) return null;

  return {
    rewrite,
    flags,
    kind,
    summary: summaryFor(kind),
    equivalent: equiv.equivalent,
    samplesChecked: equiv.checked,
    divergesOn: equiv.divergesOn,
  };
}

/**
 * Suggest rewrites for a flagged pattern, best first.
 *
 * `report` is an already-computed analysis of `source`; only exploitable
 * patterns with a hotspot get suggestions. Language-preserving rewrites come
 * before the bounded mitigation.
 */
export function suggestFixes(source: string, flags: string, report: Report): Suggestion[] {
  let nfa: NFA;
  try {
    nfa = compile(parse(source, flags));
  } catch {
    return [];
  }
  const suggestions: Suggestion[] = [];
  for (const c of candidateFixes(source, flags, report)) {
    const s = assess(source, flags, nfa, c.rewrite, c.kind);
    if (s) suggestions.push(c.bound === undefined ? s : { ...s, bound: c.bound });
  }
  return suggestions;
}
