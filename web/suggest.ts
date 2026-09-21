/**
 * Browser entry to the fix suggester.
 *
 * Reuses the pure candidate generation and equivalence check from
 * `suggest-core.ts`, and does the "is it actually fast now" verification in a
 * worker via `measureRewriteInBrowser`, so the page reaches the same verdict
 * as the CLI without a Node subprocess.
 */

import { parse } from "../src/parser.ts";
import { compile } from "../src/nfa.ts";
import { prepare, type Report } from "../src/core.ts";
import { candidateFixes, checkEquivalence, summaryFor, type Suggestion } from "../src/suggest-core.ts";
import { measureRewriteInBrowser } from "./measure.ts";

export async function suggestFixesInBrowser(source: string, flags: string, report: Report): Promise<Suggestion[]> {
  let nfa;
  try {
    nfa = compile(parse(source, flags));
  } catch {
    return [];
  }
  const out: Suggestion[] = [];
  for (const c of candidateFixes(source, flags, report)) {
    let ok = false;
    try {
      void new RegExp(c.rewrite, flags.replace(/[gy]/g, ""));
      ok = true;
    } catch {
      ok = false;
    }
    if (!ok) continue;
    const stress = [...prepare(source, flags).attacks, ...prepare(c.rewrite, flags).attacks];
    if (!(await measureRewriteInBrowser(c.rewrite, flags, stress))) continue;
    const equiv = checkEquivalence(source, c.rewrite, flags, nfa);
    if (c.kind !== "bounded" && !equiv.equivalent) continue;
    out.push({
      rewrite: c.rewrite,
      flags,
      kind: c.kind,
      summary: summaryFor(c.kind),
      equivalent: equiv.equivalent,
      samplesChecked: equiv.checked,
      divergesOn: equiv.divergesOn,
      bound: c.bound,
    });
  }
  return out;
}
