import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../src/parser.ts";
import { compile, simulate, transitionCount, PatternTooLargeError } from "../src/nfa.ts";

const build = (src: string, flags = "") => compile(parse(src, flags));

/** Every string up to `maxLen` over `alphabet`, shortest first. */
function* allStrings(alphabet: string, maxLen: number): Generator<string> {
  let frontier = [""];
  yield "";
  for (let len = 1; len <= maxLen; len++) {
    const next: string[] = [];
    for (const prefix of frontier) {
      for (const ch of alphabet) {
        const s = prefix + ch;
        next.push(s);
        yield s;
      }
    }
    frontier = next;
  }
}

test("compiled automaton accepts exactly what the engine accepts", () => {
  // Anchors, lookaround and backreferences are modelled as ε on purpose, so
  // patterns using them are excluded here and covered by their own tests.
  const patterns = [
    "a",
    "ab",
    "a|b",
    "a*",
    "a+",
    "a?",
    "(ab)*",
    "a{2,3}",
    "a{0,3}",
    "a{2,}",
    "[a-c]+",
    "[^a]",
    "(a|ab)c",
    "a*b*",
    "(a*)*b",
    "(a|b)*c",
    "((a))",
    "(?:a|b){2}",
    "ab|ba",
    "\\d+",
    ".",
    ".*b",
    "(a+)+",
    "(a|a)*",
    "[abc]{1,2}c?",
    "a(b|c)*d",
  ];
  const alphabet = "abcd1";

  for (const src of patterns) {
    const nfa = build(src);
    const engine = new RegExp(`^(?:${src})$`, "s");
    for (const input of allStrings(alphabet, 4)) {
      assert.equal(
        simulate(nfa, input),
        engine.test(input),
        `/${src}/ disagreed on ${JSON.stringify(input)}`,
      );
    }
  }
});

test("case-insensitive compilation matches the engine", () => {
  for (const src of ["[a-c]+", "abc", "[^a]", "(a|B)*"]) {
    const nfa = build(src, "i");
    const engine = new RegExp(`^(?:${src})$`, "i");
    for (const input of allStrings("aAbBcC", 3)) {
      assert.equal(simulate(nfa, input), engine.test(input), `/${src}/i on ${input}`);
    }
  }
});

test("bounded repeats nest instead of flattening", () => {
  // `a?a?` would give two paths for a single "a"; `a{0,2}` must give one.
  const nfa = build("a{0,2}");
  assert.equal(simulate(nfa, ""), true);
  assert.equal(simulate(nfa, "aa"), true);
  assert.equal(simulate(nfa, "aaa"), false);
});

test("keeps duplicate branches distinct", () => {
  // The whole point: (a|a) must compile to two edges, not one.
  const nfa = build("(a|a)");
  const outgoing = nfa.transitions[nfa.initial];
  assert.equal(outgoing.length, 2);
  assert.notEqual(outgoing[0].to, outgoing[1].to);
});

test("collapses pure-epsilon ambiguity", () => {
  // `(?:|)a` has two ε-paths but only one way to consume input.
  const nfa = build("(?:|)a");
  assert.equal(nfa.transitions[nfa.initial].length, 1);
});

test("transitions carry source provenance", () => {
  const src = "ab(cd)*";
  const nfa = build(src);
  for (const row of nfa.transitions) {
    for (const t of row) {
      const text = src.slice(t.start, t.end);
      assert.ok(text.length > 0, "transition should point at real source");
    }
  }
  const first = nfa.transitions[nfa.initial][0];
  assert.equal(src.slice(first.start, first.end), "a");
});

test("detects start anchoring", () => {
  assert.equal(build("^abc").anchoredStart, true);
  assert.equal(build("^a|^b").anchoredStart, true);
  assert.equal(build("^a|b").anchoredStart, false);
  assert.equal(build("abc").anchoredStart, false);
  assert.equal(build("(^a)+").anchoredStart, true);
  assert.equal(build("(^a)*").anchoredStart, false);
});

test("records the approximations it made", () => {
  assert.equal(build("(?=a)b").approximations.lookaround, true);
  assert.equal(build("(a)\\1").approximations.backreference, true);
  assert.equal(build("\\ba").approximations.wordBoundary, true);
  assert.equal(build("^a").approximations.anchor, true);
  assert.equal(build("a{1,5000}").approximations.widenedRepeat, true);
  assert.equal(build("a{1,5}").approximations.widenedRepeat, false);
  const clean = build("(a+)+b").approximations;
  assert.deepEqual(clean, {
    lookaround: false,
    backreference: false,
    wordBoundary: false,
    anchor: false,
    widenedRepeat: false,
  });
});

test("widened repeats stay analysable rather than exploding", () => {
  const nfa = build("(a{1,10000})+b");
  assert.ok(nfa.stateCount < 200, `expected a small automaton, got ${nfa.stateCount}`);
  assert.equal(nfa.approximations.widenedRepeat, true);
});

test("prunes states unreachable from the initial state", () => {
  const plain = build("abc");
  // 3 characters -> 4 live states once epsilon states collapse away.
  assert.ok(plain.stateCount <= 8, `got ${plain.stateCount}`);
  assert.ok(transitionCount(plain) >= 3);
});

test("an empty character class is dead, not accepting", () => {
  const nfa = build("[^\\s\\S]a");
  assert.equal(simulate(nfa, "a"), false);
  assert.equal(simulate(nfa, ""), false);
});

test("refuses patterns that would explode the state budget", () => {
  assert.throws(() => compile(parse("(((a{15}){15}){15}){15}"), { maxStates: 500 }), PatternTooLargeError);
});

test("nested quantifiers compile to compact automata", () => {
  const nfa = build("^(([a-z])+.)+[A-Z]([a-z])+$");
  assert.ok(nfa.stateCount < 60, `got ${nfa.stateCount}`);
});
