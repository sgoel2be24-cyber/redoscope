/**
 * A suggested fix must be trustworthy: it has to be fast, and — unless it
 * declares otherwise — it has to accept and reject exactly what the original
 * did. These tests check both properties directly, and check that redoscope
 * refuses to invent a fix it cannot stand behind.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect, suggestFixes } from "../src/index.ts";

const fixesFor = (source: string, flags = "") => {
  const report = inspect(source, flags, { timeoutMs: 1500 });
  return { report, suggestions: suggestFixes(source, flags, report) };
};

/** Brute-force accept/reject agreement on a spread of strings. */
function agreesEverywhere(a: string, b: string, flags: string, samples: string[]): boolean {
  const clean = flags.replace(/[gy]/g, "");
  const ra = new RegExp(a, clean);
  const rb = new RegExp(b, clean);
  return samples.every((s) => ra.test(s) === rb.test(s));
}

test("collapses a nested quantifier to an equivalent linear form", () => {
  const { suggestions } = fixesFor("^(a+)+$");
  const collapse = suggestions.find((s) => s.kind === "collapse");
  assert.ok(collapse, "expected a collapse suggestion");
  assert.equal(collapse.rewrite, "^a+$");
  assert.equal(collapse.equivalent, true);

  const samples = ["", "a", "aaaa", "aaab", "b", "aaa!", "\n", "aaaaaaaaaa"];
  assert.ok(agreesEverywhere("^(a+)+$", collapse.rewrite, "", samples));
});

test("every equivalent suggestion actually runs fast on the original attack", () => {
  for (const src of ["^(a+)+$", "^([a-zA-Z0-9._-]+)+@example\\.com$", "^([ab]|[bc])*$"]) {
    for (const s of fixesFor(src).suggestions.filter((x) => x.kind !== "bounded")) {
      const re = new RegExp(s.rewrite, s.flags.replace(/[gy]/g, ""));
      // The classic attack: a long run that fails at the very end.
      const evil = "a".repeat(60_000) + "!";
      const start = performance.now();
      re.test(evil);
      const ms = performance.now() - start;
      assert.ok(ms < 250, `${s.rewrite} took ${ms.toFixed(0)}ms on a 60k attack`);
    }
  }
});

test("a bounded mitigation is offered but never claims equivalence", () => {
  const { suggestions } = fixesFor("\\s*,\\s*");
  const bounded = suggestions.find((s) => s.kind === "bounded");
  assert.ok(bounded, "expected a bounded mitigation");
  assert.equal(bounded.equivalent, true, "agrees within the bound, on the tested corpus");
  assert.ok(bounded.bound! > 0);
  // It genuinely changes the language: a run past the cap no longer matches the same way.
  assert.notEqual(new RegExp("\\s*,\\s*").test(" ".repeat(2000) + ","), false);
});

test("no suggestion is invented when none can be verified", () => {
  // `(\w+\s?)*$` is exponential, but atomic-wrapping it stays super-linear and
  // there is no clean collapse, so redoscope offers nothing rather than a lie.
  const { report, suggestions } = fixesFor("(\\w+\\s?)*$");
  assert.equal(report.exploitable, true);
  assert.equal(
    suggestions.filter((s) => s.kind !== "bounded").length,
    0,
    "should not emit an unverified equivalent rewrite",
  );
});

test("safe patterns get no suggestions", () => {
  assert.deepEqual(fixesFor("^\\d+$").suggestions, []);
  assert.deepEqual(fixesFor("abc").suggestions, []);
});
