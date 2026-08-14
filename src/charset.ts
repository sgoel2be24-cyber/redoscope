/**
 * Sets of Unicode code points, stored as sorted, disjoint, non-adjacent
 * closed intervals.
 *
 * Every transition in the NFA is labelled with one of these. Ambiguity
 * analysis lives or dies on `intersect`: two transitions can be taken on the
 * same input character exactly when their label sets overlap, so the product
 * automaton is built out of intersections, not out of individual characters.
 * Keeping labels as intervals is what makes `[\s\S]*` cost the same as `a*`.
 */

export const MAX_CODE_POINT = 0x10ffff;

/** Inclusive `[lo, hi]` range of code points. */
export type Interval = [number, number];

function normalize(raw: Interval[]): Interval[] {
  if (raw.length === 0) return [];
  const sorted = raw.filter((iv) => iv[0] <= iv[1]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  if (sorted.length === 0) return [];
  const out: Interval[] = [[sorted[0][0], sorted[0][1]]];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i];
    const last = out[out.length - 1];
    // Merge when overlapping *or* merely adjacent, so the representation is canonical.
    if (cur[0] <= last[1] + 1) {
      if (cur[1] > last[1]) last[1] = cur[1];
    } else {
      out.push([cur[0], cur[1]]);
    }
  }
  return out;
}

export class CharSet {
  intervals: Interval[];

  /** Assumes `intervals` is already normalized; use the static factories instead. */
  constructor(intervals: Interval[]) {
    this.intervals = intervals;
  }

  static empty(): CharSet {
    return EMPTY;
  }

  static all(): CharSet {
    return ALL;
  }

  static of(...codePoints: number[]): CharSet {
    return new CharSet(normalize(codePoints.map((cp) => [cp, cp] as Interval)));
  }

  static range(lo: number, hi: number): CharSet {
    return lo > hi ? EMPTY : new CharSet([[lo, hi]]);
  }

  /** Union of arbitrary intervals, in any order, possibly overlapping. */
  static fromIntervals(intervals: Interval[]): CharSet {
    return new CharSet(normalize(intervals.map((iv) => [iv[0], iv[1]] as Interval)));
  }

  /** Every code point in `s` (by code point, so surrogate pairs count once). */
  static fromString(s: string): CharSet {
    const cps: number[] = [];
    for (const ch of s) cps.push(ch.codePointAt(0)!);
    return CharSet.of(...cps);
  }

  isEmpty(): boolean {
    return this.intervals.length === 0;
  }

  /** Number of code points in the set. */
  size(): number {
    let n = 0;
    for (const [lo, hi] of this.intervals) n += hi - lo + 1;
    return n;
  }

  has(codePoint: number): boolean {
    let lo = 0;
    let hi = this.intervals.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const iv = this.intervals[mid];
      if (codePoint < iv[0]) hi = mid - 1;
      else if (codePoint > iv[1]) lo = mid + 1;
      else return true;
    }
    return false;
  }

  union(other: CharSet): CharSet {
    if (this.isEmpty()) return other;
    if (other.isEmpty()) return this;
    return new CharSet(normalize([...this.intervals, ...other.intervals]));
  }

  intersect(other: CharSet): CharSet {
    const out: Interval[] = [];
    let i = 0;
    let j = 0;
    const a = this.intervals;
    const b = other.intervals;
    while (i < a.length && j < b.length) {
      const lo = Math.max(a[i][0], b[j][0]);
      const hi = Math.min(a[i][1], b[j][1]);
      if (lo <= hi) out.push([lo, hi]);
      // Advance whichever interval ends first; the other may still overlap the next one.
      if (a[i][1] < b[j][1]) i++;
      else j++;
    }
    return out.length === 0 ? EMPTY : new CharSet(out);
  }

  subtract(other: CharSet): CharSet {
    if (this.isEmpty() || other.isEmpty()) return this;
    const out: Interval[] = [];
    let j = 0;
    for (const [lo0, hi0] of this.intervals) {
      let lo = lo0;
      const hi = hi0;
      // Skip cut intervals entirely to the left of the current one.
      while (j < other.intervals.length && other.intervals[j][1] < lo) j++;
      let k = j;
      while (k < other.intervals.length && other.intervals[k][0] <= hi) {
        const [clo, chi] = other.intervals[k];
        if (clo > lo) out.push([lo, Math.min(clo - 1, hi)]);
        lo = Math.max(lo, chi + 1);
        if (lo > hi) break;
        k++;
      }
      if (lo <= hi) out.push([lo, hi]);
    }
    return out.length === 0 ? EMPTY : new CharSet(out);
  }

  negate(): CharSet {
    return ALL.subtract(this);
  }

  overlaps(other: CharSet): boolean {
    let i = 0;
    let j = 0;
    const a = this.intervals;
    const b = other.intervals;
    while (i < a.length && j < b.length) {
      if (Math.max(a[i][0], b[j][0]) <= Math.min(a[i][1], b[j][1])) return true;
      if (a[i][1] < b[j][1]) i++;
      else j++;
    }
    return false;
  }

  equals(other: CharSet): boolean {
    if (this.intervals.length !== other.intervals.length) return false;
    for (let i = 0; i < this.intervals.length; i++) {
      if (this.intervals[i][0] !== other.intervals[i][0]) return false;
      if (this.intervals[i][1] !== other.intervals[i][1]) return false;
    }
    return true;
  }

  /** Canonical key, for use as a Map key. */
  key(): string {
    return this.intervals.map((iv) => `${iv[0]}-${iv[1]}`).join(",");
  }

  /**
   * A representative code point, biased towards characters that are safe to
   * paste into a terminal, a test file, or a bug report. Attack strings are
   * meant to be read by humans, so `aaaa!` beats a pump of control codes.
   */
  sample(): number {
    if (this.isEmpty()) throw new Error("cannot sample an empty CharSet");
    for (const cp of PREFERRED_SAMPLES) {
      if (this.has(cp)) return cp;
    }
    // Fall back to the first printable code point, then to anything at all.
    for (const [lo, hi] of this.intervals) {
      for (let cp = lo; cp <= Math.min(hi, lo + 64); cp++) {
        if (cp >= 0x21 && cp <= 0x7e) return cp;
      }
    }
    return this.intervals[0][0];
  }

  /** Human-readable form, e.g. `[a-z0-9_]`. */
  toString(): string {
    if (this.isEmpty()) return "[]";
    if (this.equals(ALL)) return "[\\s\\S]";
    const parts = this.intervals.map(([lo, hi]) =>
      lo === hi ? escapeCodePoint(lo) : `${escapeCodePoint(lo)}-${escapeCodePoint(hi)}`,
    );
    const body = parts.join("");
    return this.size() === 1 ? body : `[${body}]`;
  }
}

const EMPTY = new CharSet([]);
const ALL = new CharSet([[0, MAX_CODE_POINT]]);

const PREFERRED_SAMPLES: number[] = [
  ...codePointsOf("abcdefghijklmnopqrstuvwxyz"),
  ...codePointsOf("0123456789"),
  ...codePointsOf("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
  ...codePointsOf("_-.!@#$%^&*+=~:;,?/|\\<>()[]{}'\"`"),
  0x20,
  0x09,
  0x0a,
];

function codePointsOf(s: string): number[] {
  const out: number[] = [];
  for (const ch of s) out.push(ch.codePointAt(0)!);
  return out;
}

export function escapeCodePoint(cp: number): string {
  switch (cp) {
    case 0x09:
      return "\\t";
    case 0x0a:
      return "\\n";
    case 0x0b:
      return "\\v";
    case 0x0c:
      return "\\f";
    case 0x0d:
      return "\\r";
    case 0x00:
      return "\\0";
  }
  if (cp >= 0x20 && cp <= 0x7e) {
    return "]^\\-[".includes(String.fromCodePoint(cp)) ? `\\${String.fromCodePoint(cp)}` : String.fromCodePoint(cp);
  }
  if (cp <= 0xff) return `\\x${cp.toString(16).padStart(2, "0")}`;
  if (cp <= 0xffff) return `\\u${cp.toString(16).padStart(4, "0")}`;
  return `\\u{${cp.toString(16)}}`;
}

/* ------------------------------------------------------------------ *
 * Case folding
 * ------------------------------------------------------------------ */

let casedTable: Array<[number, number[]]> | null = null;

/**
 * All code points whose simple case mapping differs from themselves, paired
 * with their variants. Built once, lazily: the scan costs a few hundred
 * milliseconds, and skipping it entirely for patterns without `i` is worth
 * more than the memory.
 */
function getCasedTable(): Array<[number, number[]]> {
  if (casedTable) return casedTable;
  const table: Array<[number, number[]]> = [];
  for (let cp = 0; cp <= MAX_CODE_POINT; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogates have no case
    const ch = String.fromCodePoint(cp);
    const up = ch.toUpperCase();
    const down = ch.toLowerCase();
    if (up === ch && down === ch) continue;
    const variants: number[] = [];
    // Multi-character mappings (ß -> SS) have no single-code-point variant, so
    // they are skipped: JS regex `i` matching uses simple folding too.
    if (up !== ch && [...up].length === 1) variants.push(up.codePointAt(0)!);
    if (down !== ch && [...down].length === 1) variants.push(down.codePointAt(0)!);
    if (variants.length > 0) table.push([cp, variants]);
  }
  casedTable = table;
  return table;
}

/**
 * Close `set` under simple case mapping, as the `i` flag does.
 *
 * Runs in O(|cased table|) regardless of how large the set is, so folding
 * `[\s\S]` is no more expensive than folding `[a-c]`.
 */
export function caseFold(set: CharSet): CharSet {
  if (set.isEmpty()) return set;
  const extra: Interval[] = [];
  for (const [cp, variants] of getCasedTable()) {
    if (!set.has(cp)) continue;
    for (const v of variants) extra.push([v, v]);
  }
  if (extra.length === 0) return set;
  return set.union(CharSet.fromIntervals(extra));
}
