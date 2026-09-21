/**
 * Turns an abstract pump into a string you can paste into a bug report.
 *
 * An attack has three parts:
 *
 *     prefix · pump^n · suffix
 *
 * The prefix walks the automaton to the ambiguous state, the pump is the word
 * that can be consumed two ways, and the suffix is the part that matters most
 * and gets the least attention elsewhere: it has to make the overall match
 * *fail*. A backtracking engine only explores every path when it is denied a
 * successful one, so `(a+)+` on "aaaaaaa" returns instantly while `(a+)+$` on
 * "aaaaaaa!" does not. Without a failing suffix the pump is free.
 */

import { CharSet } from "./charset.ts";
import type { NFA } from "./nfa.ts";
import type { Witness } from "./analysis.ts";

export interface Attack {
  prefix: string;
  pump: string;
  suffix: string;
  /** How the suffix was chosen, so a report can explain itself. */
  suffixKind: "rejected-char" | "empty";
}

/** Characters to try as a failing suffix, in order of how obvious they look. */
const SUFFIX_CANDIDATES = [
  0x21, // !
  0x23, // #
  0x25, // %
  0x7e, // ~
  0x5a, // Z
  0x30, // 0
  0x00,
  0xffff,
];

export function fromCodePoints(codePoints: number[]): string {
  return codePoints.map((cp) => String.fromCodePoint(cp)).join("");
}

/** Every character the pattern itself can consume anywhere. */
function alphabetOf(nfa: NFA): CharSet {
  let alphabet = CharSet.empty();
  for (const row of nfa.transitions) {
    // Negative offsets mark the synthetic search loop, which consumes anything.
    for (const t of row) if (t.start >= 0) alphabet = alphabet.union(t.set);
  }
  return alphabet;
}

/** \w, for building pump variants on either side of a word boundary. */
const WORD = CharSet.fromIntervals([
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x5f, 0x5f],
  [0x61, 0x7a],
]);

/** Most attacks a single witness may contribute; each one costs a measurement. */
const MAX_ATTACKS_PER_WITNESS = 5;

/**
 * Does the attempt that starts at the beginning of `input` certainly fail?
 *
 * The automaton over-approximates the engine (assertions are ε), so a
 * rejection here is a rejection there. Two ways to succeed are ruled out: an
 * accepting state at the end, and an *unconditionally* accepting state
 * anywhere along the way, where an unanchored pattern would simply stop.
 */
function attemptFails(nfa: NFA, input: string): boolean {
  let current = new Set<number>([nfa.initial]);
  if (nfa.acceptsUnconditionally.has(nfa.initial)) return false;
  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    const next = new Set<number>();
    for (const q of current) {
      for (const t of nfa.transitions[q]) if (t.start >= 0 && t.set.has(cp)) next.add(t.to);
    }
    if (next.size === 0) return true;
    for (const q of next) if (nfa.acceptsUnconditionally.has(q)) return false;
    current = next;
  }
  for (const q of current) if (nfa.accepting.has(q)) return false;
  return true;
}

/** One printable-leaning sample per distinct character set the pattern uses. */
function representatives(nfa: NFA, alphabet: CharSet): number[] {
  const seen = new Set<number>(SUFFIX_CANDIDATES);
  const out = [...SUFFIX_CANDIDATES];
  const add = (cp: number) => {
    if (!seen.has(cp)) {
      seen.add(cp);
      out.push(cp);
    }
  };
  add(0x0a);
  add(0x20);
  const outside = alphabet.negate();
  if (!outside.isEmpty()) add(outside.sample());
  for (const row of nfa.transitions) {
    for (const t of row) {
      if (t.start < 0) continue;
      add(t.set.sample());
      const nonWord = t.set.subtract(WORD);
      if (!nonWord.isEmpty()) add(nonWord.sample());
      if (out.length >= 40) return out;
    }
  }
  return out;
}

/**
 * Suffixes proven, on the automaton, to make the attempt fail — shortest
 * first. A suffix outside the pattern's alphabet is the obvious choice, but
 * `[^:]+` consumes nearly everything, and there the character that fails is
 * one the pattern *does* use (":", which then demands digits). Two
 * characters are tried when one is not enough: `\s*$` accepts a lone "\n",
 * not "\n0".
 */
function failingSuffixes(nfa: NFA, head: string, pump: string, alphabet: CharSet): string[] {
  const reps = representatives(nfa, alphabet);
  const fails = (suffix: string) =>
    attemptFails(nfa, head + pump.repeat(2) + suffix) && attemptFails(nfa, head + pump.repeat(3) + suffix);

  // Characters the pattern never consumes read best in a report; try them first.
  const ordered = [...reps.filter((cp) => !alphabet.has(cp)), ...reps.filter((cp) => alphabet.has(cp))];
  const found: string[] = [];
  for (const cp of ordered) {
    const suffix = String.fromCodePoint(cp);
    if (fails(suffix)) found.push(suffix);
    if (found.length >= 2) return found;
  }
  if (found.length > 0) return found;

  const pairs = ordered.slice(0, 16);
  for (const a of pairs) {
    for (const b of pairs) {
      const suffix = String.fromCodePoint(a) + String.fromCodePoint(b);
      if (fails(suffix)) return [suffix];
    }
  }
  return [];
}

/**
 * The same pump drawn from a different character class. Which class matters
 * whenever an assertion does: `[\da-z-]*\b` can end a match between "a"
 * and ".", but not between "-" and ".", so only the second pump forces the
 * engine to try everything.
 */
function pumpVariants(witness: Witness): string[] {
  const variants = [fromCodePoints(witness.pump)];
  for (const pick of [(set: CharSet) => set.subtract(WORD), (set: CharSet) => set.intersect(WORD)]) {
    const codePoints = witness.pumpSets.map((set, i) => {
      const narrowed = pick(set);
      return narrowed.isEmpty() ? witness.pump[i] : narrowed.sample();
    });
    const variant = fromCodePoints(codePoints);
    if (!variants.includes(variant)) variants.push(variant);
  }
  return variants;
}

/**
 * Candidate attacks for a witness, best guess first.
 *
 * More than one is offered on purpose. Whether a given attack actually
 * defeats the match depends on anchoring, on what the engine's literal
 * prefilters do, and on optimisations no static model should pretend to
 * predict — so the timing harness tries them and keeps whichever hurts most.
 */
export function buildAttacks(nfa: NFA, witness: Witness): Attack[] {
  const prefix = fromCodePoints(witness.prefix);
  const alphabet = alphabetOf(nfa);
  const [pump, ...otherPumps] = pumpVariants(witness);
  const attacks: Attack[] = [];
  const push = (attack: Attack) => {
    if (attacks.length >= MAX_ATTACKS_PER_WITNESS) return;
    if (!attacks.some((a) => a.prefix === attack.prefix && a.pump === attack.pump && a.suffix === attack.suffix)) {
      attacks.push(attack);
    }
  };

  const proven = failingSuffixes(nfa, prefix, pump, alphabet);
  for (const suffix of proven) push({ prefix, pump, suffix, suffixKind: "rejected-char" });

  for (const variant of otherPumps) {
    const suffix = failingSuffixes(nfa, prefix, variant, alphabet)[0] ?? proven[0];
    if (suffix !== undefined) push({ prefix, pump: variant, suffix, suffixKind: "rejected-char" });
  }

  // A retry-driven pump is useless if the attempt at offset 0 matches: in
  // `^\W+|\W+$` the first branch takes a leading run of "-" and succeeds.
  // A character that fails at offset 0 moves every attempt onto the pump.
  // No suffix can be proven from offset 0 when a `^` branch accepts there,
  // so a character the pattern never consumes stands in.
  const unconsumed = SUFFIX_CANDIDATES.find((cp) => !alphabet.has(cp));
  const leadSuffix = proven[0] ?? (unconsumed === undefined ? undefined : String.fromCodePoint(unconsumed));
  if (witness.retried && leadSuffix !== undefined) {
    const lead = representatives(nfa, alphabet).find((cp) => attemptFails(nfa, String.fromCodePoint(cp)));
    if (lead !== undefined) push({ prefix: String.fromCodePoint(lead) + prefix, pump, suffix: leadSuffix, suffixKind: "rejected-char" });
  }

  // Nothing could be proven to fail. Fall back to characters the pattern
  // never consumes, and finally to the empty suffix: an unanchored pattern
  // that matches everything has no rejecting character, and measurement will
  // say so.
  if (proven.length === 0) {
    for (const cp of SUFFIX_CANDIDATES) {
      if (alphabet.has(cp)) continue;
      push({ prefix, pump, suffix: String.fromCodePoint(cp), suffixKind: "rejected-char" });
      if (attacks.length >= 2) break;
    }
    if (attacks.length === 0) {
      const outside = alphabet.negate();
      if (!outside.isEmpty()) push({ prefix, pump, suffix: String.fromCodePoint(outside.sample()), suffixKind: "rejected-char" });
    }
    push({ prefix, pump, suffix: "", suffixKind: "empty" });
  }
  return attacks;
}

export function renderAttack(attack: Attack, repetitions: number): string {
  return attack.prefix + attack.pump.repeat(repetitions) + attack.suffix;
}

/** `prefix + pump×n + suffix`, for display. */
export function describeAttack(attack: Attack, repetitions: number): string {
  const quote = (s: string) => JSON.stringify(s);
  const parts: string[] = [];
  if (attack.prefix) parts.push(quote(attack.prefix));
  parts.push(`${quote(attack.pump)} × ${repetitions}`);
  if (attack.suffix) parts.push(quote(attack.suffix));
  return parts.join(" + ");
}
