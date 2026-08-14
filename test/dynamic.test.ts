import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect, summarize, projectMilliseconds } from "../src/index.ts";
import { renderAttack } from "../src/witness.ts";

/**
 * These tests are slow on purpose: they spawn real engines and time real
 * matches. They are also the only tests that can falsify the project's central
 * claim, which is that a static verdict plus a generated witness predicts what
 * the engine actually does.
 *
 * Run them serially. `node --test` runs files in parallel by default, and a
 * timing probe competing with five other test files for CPU measures the
 * scheduler as much as the regex — which made this file fail roughly one run
 * in three. `npm test` sets `--test-concurrency=1` for exactly this reason.
 * Assertions below are also deliberately loose about absolute numbers: the
 * shape of the curve is the claim, not the constant in front of it.
 */

test("generated witnesses really do blow up the engine", { timeout: 120_000 }, () => {
  // Every one of these is exponential *and* has a reachable failure, so the
  // static verdict and the measurement have to agree.
  const patterns = [
    "^(a+)+$",
    "^(a*)*$",
    "^([a-zA-Z]+)*$",
    "^(x+x+)+y$",
    "^(\\w+\\s?)*$",
    "^(a|a)*$",
    "^(([a-z])+.)+[A-Z]([a-z])+$",
  ];

  for (const source of patterns) {
    const report = inspect(source, "", { timeoutMs: 3000 });
    assert.equal(report.verdict, "exponential", `static: ${summarize(report)}`);
    assert.ok(report.attack, `no witness for /${source}/`);
    assert.equal(
      report.dynamic?.growth,
      "exponential",
      `measurement disagreed: ${summarize(report)}`,
    );
    assert.equal(report.exploitable, true);
  }
});

test("a witness that claims 2^n grows at roughly 2^n", { timeout: 60_000 }, () => {
  const report = inspect("^(a*)*$", "", { timeoutMs: 3000 });
  assert.equal(report.dynamic?.growth, "exponential");
  const base = report.dynamic!.base!;
  // Wide bounds on purpose: the exact base moves with machine, JIT state and
  // load. What must hold is that growth is multiplicative per repetition and
  // the fit is tight — a doubling curve cannot pass for a linear one.
  assert.ok(base > 1.4 && base < 3.5, `expected a base near 2, measured ${base}`);
  assert.ok(report.dynamic!.fitQuality! > 0.85, `poor fit: R²=${report.dynamic!.fitQuality}`);
});

test("ambiguity without a reachable failure is not exploitable", { timeout: 60_000 }, () => {
  // `(a+)+` is exponentially ambiguous, but unanchored and always matching, so
  // the engine never has to explore the ambiguity. Reporting this as a
  // vulnerability is the most common false positive in this space.
  const report = inspect("(a+)+", "", { timeoutMs: 2000 });
  assert.equal(report.verdict, "exponential");
  assert.equal(report.exploitable, false);
  assert.ok(
    report.dynamic?.growth === "constant" || report.dynamic?.growth === "linear",
    `measured ${report.dynamic?.growth}`,
  );
  assert.match(summarize(report), /not exploitable/);
});

test("polynomial patterns are measured on inputs big enough to show it", { timeout: 120_000 }, () => {
  const report = inspect("^\\s*\\s*$", "", { timeoutMs: 3000 });
  assert.equal(report.verdict, "polynomial");
  assert.equal(report.degree, 2);
  assert.ok(
    report.dynamic?.growth === "polynomial",
    `measured ${report.dynamic?.growth}: ${summarize(report)}`,
  );
  // The largest sample must be long enough that a quadratic is visible at all.
  assert.ok(report.dynamic!.worst!.length > 1000, "polynomial ladder did not escalate");
});

test("safe patterns skip measurement entirely", () => {
  const started = performance.now();
  const report = inspect("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");
  const elapsed = performance.now() - started;

  assert.equal(report.verdict, "safe");
  assert.equal(report.dynamic, null);
  assert.equal(report.exploitable, false);
  assert.ok(elapsed < 250, `safe patterns should not spawn a probe (${elapsed.toFixed(0)}ms)`);
});

test("the reported attack string is the one that was measured", { timeout: 60_000 }, () => {
  const report = inspect("^(a+)+$", "", { timeoutMs: 3000 });
  const attack = report.attack!;
  const worst = report.dynamic!.worst!;

  const rebuilt = renderAttack(attack, worst.repetitions);
  assert.equal(rebuilt.length, worst.length, "reported attack does not reproduce the timed input");

  // And it must genuinely be slow when replayed here, not just in the probe.
  const started = performance.now();
  new RegExp(report.source).test(rebuilt);
  assert.ok(
    performance.now() - started > 20,
    "replaying the published attack string was fast — the report would be misleading",
  );
});

test("parse failures are reported, not thrown", () => {
  const report = inspect("(unclosed");
  assert.ok(report.error, "expected an error message");
  assert.equal(report.dynamic, null);
  assert.match(summarize(report), /unclosed/);
});

test("projection extrapolates the fitted curve", { timeout: 60_000 }, () => {
  const report = inspect("^(a*)*$", "", { timeoutMs: 3000 });
  const small = projectMilliseconds(report.dynamic!, 20)!;
  const large = projectMilliseconds(report.dynamic!, 30)!;
  assert.ok(large > small * 100, `expected steep growth, got ${small} -> ${large}`);
});

test("measurement can be turned off", () => {
  const report = inspect("^(a+)+$", "", { measure: false });
  assert.equal(report.verdict, "exponential");
  assert.equal(report.dynamic, null);
  assert.equal(report.exploitable, null);
  assert.ok(report.attack, "a witness should still be generated without measurement");
  assert.match(summarize(report), /not measured/);
});
