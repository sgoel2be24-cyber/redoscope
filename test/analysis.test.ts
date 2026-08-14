import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../src/parser.ts";
import { compile } from "../src/nfa.ts";
import { analyze, type Verdict } from "../src/analysis.ts";

const run = (src: string, flags = "") => analyze(compile(parse(src, flags)));

function check(src: string, expected: Verdict, flags = ""): ReturnType<typeof run> {
  const result = run(src, flags);
  assert.equal(result.verdict, expected, `/${src}/${flags} -> ${result.verdict}, want ${expected}`);
  return result;
}

test("finds exponential ambiguity in the classic offenders", () => {
  const exponential = [
    "(a+)+",
    "(a*)*",
    "(a|a)*",
    "(a+)*",
    "([a-zA-Z]+)*",
    "(x+x+)+y",
    "^(a+)+$",
    "(\\w+\\s?)*$",
    "^(([a-z])+.)+[A-Z]([a-z])+$",
    "(.*)*x",
    // `\s*` can match empty inside the `+`, so a run of spaces can be carved
    // up by the outer loop in exponentially many ways.
    "^(\\s*|\\w)+$",
  ];
  for (const src of exponential) check(src, "exponential");
});

test("finds polynomial ambiguity and reports the right degree", () => {
  const quadratic = run("a*a*b");
  assert.equal(quadratic.verdict, "polynomial");
  assert.equal(quadratic.degree, 2);

  const alsoQuadratic = run("^\\s*\\s*$");
  assert.equal(alsoQuadratic.verdict, "polynomial");
  assert.equal(alsoQuadratic.degree, 2);

  const cubic = run("a*a*a*b");
  assert.equal(cubic.verdict, "polynomial");
  assert.equal(cubic.degree, 3);
});

test("does not cry wolf on ordinary patterns", () => {
  const safe = [
    "abc",
    "a*b*",
    "[a-z]+",
    "(ab)*",
    "(a|b)*",
    "^\\d+$",
    "a{2,4}b",
    "^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$",
    "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$",
    "(?:ab|cd)+",
    "^-?\\d+(\\.\\d+)?$",
    "\\/\\*[\\s\\S]*?\\*\\/",
    "^#[0-9a-fA-F]{6}$",
    "(a|b|c)+d",
    // Disjoint alternatives cannot be ambiguous, however alarming they look.
    "^(\\s|\\w)+$",
    // Overlapping prefixes are not enough either: after 'a' the two branches
    // need different next characters, so the pair of paths dies immediately.
    "(a|ab)+c",
  ];
  for (const src of safe) check(src, "safe");
});

test("the i flag can create ambiguity that is absent without it", () => {
  // 'a' and 'A' are disjoint until case folding merges them.
  check("(a|A)*", "safe");
  check("(a|A)*", "exponential", "i");
});

test("distinct alternatives stay safe, overlapping ones do not", () => {
  check("(ab|cd)*", "safe");
  check("(ab|ab)*", "exponential");
  check("([ab]|[bc])*", "exponential");
  check("([ab]|[cd])*", "safe");
});

test("witnesses drive the automaton where they claim to", () => {
  for (const src of ["(a+)+", "([a-zA-Z]+)*", "a*a*b", "(x+x+)+y"]) {
    const nfa = compile(parse(src));
    const result = analyze(nfa);
    assert.ok(result.witness, `/${src}/ produced no witness`);

    const { prefix, pump } = result.witness!;
    assert.ok(pump.length > 0, `/${src}/ produced an empty pump`);

    // Walk prefix + pump^3 through the automaton; it must stay live throughout,
    // since the pump is by construction a cycle.
    const input = [...prefix, ...pump, ...pump, ...pump];
    let live = new Set<number>([nfa.initial]);
    for (const cp of input) {
      const next = new Set<number>();
      for (const q of live) {
        for (const t of nfa.transitions[q]) if (t.set.has(cp)) next.add(t.to);
      }
      assert.ok(next.size > 0, `/${src}/ witness died on ${String.fromCodePoint(cp)}`);
      live = next;
    }
  }
});

test("hotspots point at the quantifier responsible", () => {
  const src = "^abc(d+)+$";
  const result = run(src);
  assert.equal(result.verdict, "exponential");
  assert.ok(result.hotspot);
  const text = src.slice(result.hotspot!.start, result.hotspot!.end);
  assert.ok(text.includes("d"), `hotspot was ${JSON.stringify(text)}`);
  assert.ok(!text.includes("abc"), `hotspot too wide: ${JSON.stringify(text)}`);
});

test("exponential beats polynomial when both are present", () => {
  const result = run("a*a*(b+)+c");
  assert.equal(result.verdict, "exponential");
  assert.equal(result.degree, Infinity);
});

test("reports truncation instead of a false all-clear", () => {
  const result = analyze(compile(parse("(a+)+(b+)+(c+)+(d+)+")), { maxProductStates: 5 });
  assert.ok(result.truncated || result.verdict === "exponential");
});

test("bounded repeats are not treated as unbounded loops", () => {
  check("(a{2,3}){2,3}", "safe");
  // A bounded outer repeat cannot compound: `(a+){2,3}` is three concatenated
  // `a+`, which is polynomial, not exponential.
  const bounded = run("(a+){2,3}");
  assert.equal(bounded.verdict, "polynomial");
  assert.equal(bounded.degree, 3);
});

test("analysis is fast on realistic patterns", () => {
  const patterns = [
    "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d?\\d)$",
    "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
  ];
  const started = performance.now();
  for (const src of patterns) run(src);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 3000, `analysis took ${elapsed.toFixed(0)}ms`);
});
