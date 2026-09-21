/**
 * Regexes from real npm advisories that earlier versions missed.
 *
 * Each one must be *proven* by redoscope's own generated attack — flagged and
 * measured super-linear — not merely called ambiguous. They cover the witness
 * failures the CVE benchmark exposed: the engine's retry loop, a suffix the
 * pattern does consume, a two-character suffix, a pump on the far side of a
 * word boundary, and an offset-0 match that has to be stepped over.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "../src/index.ts";

const cases: { advisory: string; source: string; flags?: string; teaches: string }[] = [
  { advisory: "GHSA-593f-38f6-jp5m (koa)", source: "\\s*,\\s*", teaches: "unanchored: n retries × n work" },
  { advisory: "GHSA-cph5-m8f7-6c5x (axios)", source: "\\s*$", teaches: "an anchor that fails is not acceptance" },
  { advisory: "GHSA-832h-xg76-4gv6 (brace-expansion)", source: "^(.*,)+(.+)?$", teaches: "suffix outside `.`: a newline" },
  { advisory: "GHSA-44pw-h2cw-w3vq (hawk)", source: "^(?:(?:\\r\\n)?\\s)*((?:[^:]+)|(?:\\[[^\\]]+\\]))(?::(\\d+))?(?:(?:\\r\\n)?\\s)*$", teaches: "failing suffix the pattern consumes: ':'" },
  { advisory: "GHSA-73rr-hh4g-fpgx (diff)", source: "^(?:Index:|diff(?: -r \\w+)+)\\s+(.+?)\\s*$", teaches: "two-character suffix" },
  {
    advisory: "GHSA-44c6-4v22-4mhx (semver-regex)",
    source: "(?<=^v?|\\sv?)(?:(?:0|[1-9]\\d*)\\.){2}(?:0|[1-9]\\d*)(?:-(?:0|[1-9]\\d*|[\\da-z-]*[a-z-][\\da-z-]*)(?:\\.(?:0|[1-9]\\d*|[\\da-z-]*[a-z-][\\da-z-]*))*)?(?:\\+[\\da-z-]+(?:\\.[\\da-z-]+)*)?\\b",
    flags: "gi",
    teaches: "pump of non-word characters defeats \\b",
  },
  { advisory: "GHSA-x4c5-c7rf-jjgv (@octokit/endpoint)", source: "^\\W+|\\W+$", teaches: "step over the offset-0 match with a lead character" },
];

for (const c of cases) {
  test(`proves ${c.advisory}: ${c.teaches}`, () => {
    const report = inspect(c.source, c.flags ?? "", { timeoutMs: 2000 });
    assert.equal(report.error, null);
    assert.notEqual(report.verdict, "safe", `static verdict for ${c.source}`);
    assert.equal(
      report.exploitable,
      true,
      `measured ${report.dynamic?.growth} with attack ${JSON.stringify(report.attack)}`,
    );
  });
}
