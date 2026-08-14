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

/** Every character the automaton can consume anywhere. */
function alphabetOf(nfa: NFA): CharSet {
  let alphabet = CharSet.empty();
  for (const row of nfa.transitions) {
    for (const t of row) alphabet = alphabet.union(t.set);
  }
  return alphabet;
}

/**
 * Candidate attacks for a witness, best guess first.
 *
 * More than one is offered on purpose. Whether a given suffix actually
 * defeats the match depends on anchoring, on what the engine's literal
 * prefilters do, and on optimisations no static model should pretend to
 * predict — so the timing harness tries them and keeps whichever hurts most.
 */
export function buildAttacks(nfa: NFA, witness: Witness): Attack[] {
  const prefix = fromCodePoints(witness.prefix);
  const pump = fromCodePoints(witness.pump);
  const alphabet = alphabetOf(nfa);

  const attacks: Attack[] = [];
  for (const cp of SUFFIX_CANDIDATES) {
    if (alphabet.has(cp)) continue; // a consumable suffix might extend the match
    attacks.push({ prefix, pump, suffix: String.fromCodePoint(cp), suffixKind: "rejected-char" });
    if (attacks.length >= 2) break;
  }

  // An unanchored pattern that matches everything has no rejecting character;
  // the empty suffix is still worth measuring, and is the honest fallback.
  attacks.push({ prefix, pump, suffix: "", suffixKind: "empty" });
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
