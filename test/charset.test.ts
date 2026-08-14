import { test } from "node:test";
import assert from "node:assert/strict";
import { CharSet, caseFold, escapeCodePoint, MAX_CODE_POINT } from "../src/charset.ts";

const cp = (ch: string) => ch.codePointAt(0)!;

test("normalizes into disjoint, non-adjacent intervals", () => {
  const s = CharSet.fromIntervals([
    [10, 20],
    [15, 25],
    [26, 30],
    [1, 2],
  ]);
  assert.deepEqual(s.intervals, [
    [1, 2],
    [10, 30],
  ]);
});

test("drops inverted intervals", () => {
  assert.ok(CharSet.fromIntervals([[10, 5]]).isEmpty());
  assert.ok(CharSet.range(10, 5).isEmpty());
});

test("union merges touching ranges", () => {
  const a = CharSet.range(cp("a"), cp("m"));
  const b = CharSet.range(cp("n"), cp("z"));
  assert.deepEqual(a.union(b).intervals, [[cp("a"), cp("z")]]);
});

test("intersect finds the overlap", () => {
  const a = CharSet.fromIntervals([
    [0, 10],
    [20, 30],
  ]);
  const b = CharSet.fromIntervals([
    [5, 25],
    [29, 40],
  ]);
  assert.deepEqual(a.intersect(b).intervals, [
    [5, 10],
    [20, 25],
    [29, 30],
  ]);
});

test("intersect of disjoint sets is empty", () => {
  const a = CharSet.range(0, 10);
  const b = CharSet.range(11, 20);
  assert.ok(a.intersect(b).isEmpty());
  assert.equal(a.overlaps(b), false);
  assert.equal(a.overlaps(CharSet.range(10, 20)), true);
});

test("subtract punches holes", () => {
  const a = CharSet.range(0, 100);
  const b = CharSet.fromIntervals([
    [10, 20],
    [50, 50],
  ]);
  assert.deepEqual(a.subtract(b).intervals, [
    [0, 9],
    [21, 49],
    [51, 100],
  ]);
});

test("subtract handles cuts spanning several intervals", () => {
  const a = CharSet.fromIntervals([
    [0, 10],
    [20, 30],
    [40, 50],
  ]);
  assert.deepEqual(a.subtract(CharSet.range(5, 45)).intervals, [
    [0, 4],
    [46, 50],
  ]);
});

test("negate round-trips", () => {
  const a = CharSet.fromIntervals([
    [0x41, 0x5a],
    [0x61, 0x7a],
  ]);
  assert.ok(a.negate().negate().equals(a));
  assert.equal(a.negate().has(cp("A")), false);
  assert.equal(a.negate().has(cp("0")), true);
  assert.equal(a.negate().size(), MAX_CODE_POINT + 1 - a.size());
});

test("negate of everything is empty and vice versa", () => {
  assert.ok(CharSet.all().negate().isEmpty());
  assert.ok(CharSet.empty().negate().equals(CharSet.all()));
});

test("has does binary search correctly across many intervals", () => {
  const intervals: Array<[number, number]> = [];
  for (let i = 0; i < 500; i++) intervals.push([i * 10, i * 10 + 4]);
  const s = CharSet.fromIntervals(intervals);
  for (let i = 0; i < 500; i++) {
    assert.equal(s.has(i * 10), true, `expected ${i * 10}`);
    assert.equal(s.has(i * 10 + 4), true);
    assert.equal(s.has(i * 10 + 5), false);
  }
});

test("sample prefers readable characters", () => {
  assert.equal(CharSet.range(0, MAX_CODE_POINT).sample(), cp("a"));
  assert.equal(CharSet.range(cp("0"), cp("9")).sample(), cp("0"));
  assert.equal(CharSet.of(0x2028, cp("Z")).sample(), cp("Z"));
  assert.equal(CharSet.of(0x2028).sample(), 0x2028);
});

test("sample throws on the empty set", () => {
  assert.throws(() => CharSet.empty().sample(), /empty/);
});

test("case folding closes ASCII and Greek", () => {
  const folded = caseFold(CharSet.range(cp("a"), cp("c")));
  assert.equal(folded.has(cp("A")), true);
  assert.equal(folded.has(cp("C")), true);
  assert.equal(folded.has(cp("D")), false);

  const sigma = caseFold(CharSet.of(0x3c3)); // greek small sigma
  assert.equal(sigma.has(0x3a3), true); // greek capital sigma
});

test("case folding a huge set is a no-op on membership", () => {
  const all = caseFold(CharSet.all());
  assert.ok(all.equals(CharSet.all()));
});

test("escapeCodePoint stays paste-safe", () => {
  assert.equal(escapeCodePoint(cp("a")), "a");
  assert.equal(escapeCodePoint(0x0a), "\\n");
  assert.equal(escapeCodePoint(0x00), "\\0");
  assert.equal(escapeCodePoint(0x1f), "\\x1f");
  assert.equal(escapeCodePoint(0x2028), "\\u2028");
  assert.equal(escapeCodePoint(0x1f600), "\\u{1f600}");
  assert.equal(escapeCodePoint(cp("]")), "\\]");
});

test("key is canonical for equal sets", () => {
  const a = CharSet.fromIntervals([
    [1, 5],
    [6, 9],
  ]);
  const b = CharSet.range(1, 9);
  assert.equal(a.key(), b.key());
});
