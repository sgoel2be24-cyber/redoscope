import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect, prepare, withMeasurement, fitsWithin } from "../src/index.ts";
import { classify, type TimingSample } from "../src/growth.ts";
import { renderSarif } from "../src/sarif.ts";
import type { FoundRegex } from "../src/scan.ts";

const sample = (repetitions: number, length: number, ms: number, timedOut = false): TimingSample => ({
  repetitions,
  length,
  ms,
  matched: false,
  timedOut,
});

test("prepare is exactly inspect without measurement", () => {
  for (const source of ["^(a+)+$", "(a+)+", "^(\\s|\\w)+$", "\\s*#?\\s*$", "a(", "(?<=x)y+"]) {
    assert.deepEqual(prepare(source).report, inspect(source, "", { measure: false }), source);
  }
});

test("a prepared report waits on measurement only when there is something to attack", () => {
  assert.equal(prepare("^\\d+(\\.\\d+)?$").attacks.length, 0);
  assert.equal(prepare("a(").attacks.length, 0);
  assert.ok(prepare("^(a+)+$").attacks.length > 0);
});

test("withMeasurement decides exploitability from growth, not from the static verdict", () => {
  const { report, attacks } = prepare("^(a+)+$");
  const base = { base: null, exponent: null, fitQuality: null, attack: attacks[0], samples: [], worst: null, timedOut: false, engineError: null };
  assert.equal(withMeasurement(report, { ...base, growth: "constant" }).exploitable, false);
  assert.equal(withMeasurement(report, { ...base, growth: "exponential" }).exploitable, true);
  assert.equal(withMeasurement(report, { ...base, growth: "exponential" }).confidence, "measured");
});

test("an input cap turns a slow-growing quadratic into a non-finding", () => {
  const { report, attacks } = prepare("\\s*$");
  const attack = attacks[0];
  // 1 ms at 1,000 characters, quadratic: 1 s needs about 31,600 characters.
  const samples = [1000, 2000, 4000, 8000].map((n) => sample(n, n, (n / 1000) ** 2));
  const dynamic = { ...classify(samples), attack, samples, worst: samples.at(-1)!, timedOut: false, engineError: null };

  assert.equal(withMeasurement(report, dynamic).exploitable, true);
  assert.equal(withMeasurement(report, dynamic, 50_000).exploitable, true);
  assert.equal(withMeasurement(report, dynamic, 10_000).exploitable, false);
  assert.equal(fitsWithin(dynamic, 31_000), false);
  assert.equal(fitsWithin(dynamic, 32_000), true);
});

test("classify recovers a doubling curve as exponential with base ≈ 2", () => {
  const samples = [10, 11, 12, 13, 14, 15].map((n) => sample(n, n, 0.01 * 2 ** n));
  const result = classify(samples);
  assert.equal(result.growth, "exponential");
  assert.ok(Math.abs(result.base! - 2) < 0.01);
});

test("classify recovers a quadratic curve as polynomial with exponent ≈ 2", () => {
  const samples = [1000, 2000, 4000, 8000, 16000].map((n) => sample(n, n, 1e-6 * n * n));
  const result = classify(samples);
  assert.equal(result.growth, "polynomial");
  assert.ok(Math.abs(result.exponent! - 2) < 0.01);
});

test("a kill on a short input is exponential on its own", () => {
  assert.equal(classify([sample(10, 20, 3), sample(11, 22, 2000, true)]).growth, "exponential");
});

test("SARIF output carries the rule, location and evidence", () => {
  const report = inspect("^(a+)+$", "", { measure: false });
  const location: FoundRegex = { source: "^(a+)+$", flags: "", file: "src/x.js", line: 3, column: 11, raw: "/^(a+)+$/", kind: "literal" };
  const sarif = JSON.parse(renderSarif([{ location, report }], "0.0.0"));

  assert.equal(sarif.version, "2.1.0");
  const [result] = sarif.runs[0].results;
  assert.equal(result.ruleId, "redoscope/exponential");
  assert.equal(result.level, "error");
  assert.equal(sarif.runs[0].tool.driver.rules[result.ruleIndex].id, result.ruleId);
  assert.deepEqual(result.locations[0].physicalLocation.region, { startLine: 3, startColumn: 11, endColumn: 20 });
  assert.match(result.message.text, /Attack: "aa" \+ "aa" × 25 \+ "!"/);
  assert.match(result.message.text, /Not measured/);
});
