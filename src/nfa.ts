/**
 * Compiles a parsed pattern into an ε-free NFA whose transitions are labelled
 * with character *sets*.
 *
 * The automaton models what a backtracking engine explores, which is not the
 * same thing as the language the regex accepts:
 *
 *  - Distinct paths are kept distinct. `(a|a)` compiles to two 'a'
 *    transitions, not one, because the engine really does try both.
 *  - Laziness is ignored. `a*?` and `a*` admit the same set of paths; lazy
 *    quantifiers only change the order they are tried, and a failing match
 *    exhausts every path regardless of order.
 *  - Constructs that a plain NFA cannot express — lookaround,
 *    backreferences, word boundaries — become ε and are recorded in
 *    `approximations`. That direction is deliberate: it over-approximates the
 *    paths available, so the analysis may over-report but will not miss.
 */

import { CharSet } from "./charset.ts";
import type { Node, Pattern } from "./ast.ts";

export class PatternTooLargeError extends Error {
  constructor(limit: number) {
    super(`pattern expands to more than ${limit} automaton states`);
    this.name = "PatternTooLargeError";
  }
}

/** A repeat bound above this is widened to unbounded rather than unrolled. */
const MAX_UNROLL = 20;
const DEFAULT_MAX_STATES = 6000;

export interface CharTransition {
  set: CharSet;
  to: number;
  /** Start offset in the pattern source of the sub-expression that created this edge. */
  start: number;
  /** End offset, exclusive. */
  end: number;
  /**
   * True when two or more distinct ε-routes lead from the owning state into
   * this edge.
   *
   * This is what keeps `(a*)*` honest. After ε-elimination it looks like a
   * single self-loop on one state, yet the engine really has two ways to get
   * back to that 'a': stay in the inner loop, or leave it, take another turn
   * of the outer loop, and re-enter. Same character, different backtracking
   * state — so a matcher can be made to try both, and the flag records it.
   */
  multiPath: boolean;
}

/** Modelling shortcuts taken during compilation, each one a possible false positive. */
export interface Approximations {
  lookaround: boolean;
  backreference: boolean;
  wordBoundary: boolean;
  anchor: boolean;
  /** A `{n,m}` bound was too large to unroll and became unbounded. */
  widenedRepeat: boolean;
}

export interface NFA {
  stateCount: number;
  initial: number;
  accepting: Set<number>;
  /** Outgoing transitions, indexed by state. */
  transitions: CharTransition[][];
  pattern: Pattern;
  approximations: Approximations;
  /** True when the pattern is anchored at the start, so the engine cannot retry at later offsets. */
  anchoredStart: boolean;
}

interface Fragment {
  start: number;
  end: number;
}

class Builder {
  charTrans: CharTransition[][] = [];
  epsTrans: number[][] = [];
  maxStates: number;
  approximations: Approximations = {
    lookaround: false,
    backreference: false,
    wordBoundary: false,
    anchor: false,
    widenedRepeat: false,
  };

  constructor(maxStates: number) {
    this.maxStates = maxStates;
  }

  newState(): number {
    if (this.charTrans.length >= this.maxStates) throw new PatternTooLargeError(this.maxStates);
    this.charTrans.push([]);
    this.epsTrans.push([]);
    return this.charTrans.length - 1;
  }

  addEps(from: number, to: number): void {
    this.epsTrans[from].push(to);
  }

  addChar(from: number, set: CharSet, to: number, node: Node): void {
    this.charTrans[from].push({ set, to, start: node.start, end: node.end, multiPath: false });
  }

  /** A fragment matching the empty string. */
  empty(): Fragment {
    const s = this.newState();
    return { start: s, end: s };
  }

  build(node: Node): Fragment {
    switch (node.type) {
      case "Empty":
        return this.empty();

      case "Char": {
        const start = this.newState();
        const end = this.newState();
        // An empty set can never be taken; leaving the edge off makes the
        // state dead, which is exactly right.
        if (!node.set.isEmpty()) this.addChar(start, node.set, end, node);
        return { start, end };
      }

      case "Concat": {
        let frag: Fragment | null = null;
        for (const child of node.body) {
          const next = this.build(child);
          if (frag === null) frag = next;
          else {
            this.addEps(frag.end, next.start);
            frag = { start: frag.start, end: next.end };
          }
        }
        return frag ?? this.empty();
      }

      case "Alt": {
        const start = this.newState();
        const end = this.newState();
        for (const child of node.body) {
          const frag = this.build(child);
          this.addEps(start, frag.start);
          this.addEps(frag.end, end);
        }
        return { start, end };
      }

      case "Group":
        // Capture bookkeeping does not change which paths exist.
        return this.build(node.body);

      case "Repeat":
        return this.buildRepeat(node);

      case "Assertion":
        // `^`, `$`, `\b` constrain *where* a path may run, not how many paths
        // there are. Treating them as ε keeps the over-approximation honest.
        if (node.kind === "\\b" || node.kind === "\\B") this.approximations.wordBoundary = true;
        else this.approximations.anchor = true;
        return this.empty();

      case "Lookaround":
        this.approximations.lookaround = true;
        return this.empty();

      case "Backref":
        // A backreference can consume input, but how much depends on a capture
        // this model does not track. ε is the conservative stand-in.
        this.approximations.backreference = true;
        return this.empty();
    }
  }

  buildRepeat(node: Extract<Node, { type: "Repeat" }>): Fragment {
    let { min, max } = node;

    if (min > MAX_UNROLL) {
      this.approximations.widenedRepeat = true;
      min = MAX_UNROLL;
    }
    if (Number.isFinite(max) && max - min > MAX_UNROLL) {
      this.approximations.widenedRepeat = true;
      max = Infinity;
    }

    const parts: Fragment[] = [];
    for (let i = 0; i < min; i++) parts.push(this.build(node.body));

    if (max === Infinity) {
      parts.push(this.buildStar(node.body));
    } else if (max > min) {
      parts.push(this.buildNestedOptional(node.body, max - min));
    }

    if (parts.length === 0) return this.empty();

    let frag = parts[0];
    for (let i = 1; i < parts.length; i++) {
      this.addEps(frag.end, parts[i].start);
      frag = { start: frag.start, end: parts[i].end };
    }
    return frag;
  }

  /** Kleene star: one body fragment with a back edge, plus a bypass. */
  buildStar(body: Node): Fragment {
    const start = this.newState();
    const end = this.newState();
    const frag = this.build(body);
    this.addEps(start, frag.start);
    this.addEps(frag.end, frag.start);
    this.addEps(frag.end, end);
    this.addEps(start, end);
    return { start, end };
  }

  /**
   * `X{0,n}` as nested optionals — `(X(X(X)?)?)?` rather than `X?X?X?`.
   *
   * The flat form is ambiguous by construction: `a?a?` matches a single "a"
   * two ways, which would be reported as ambiguity that the engine never
   * actually pays for. Nesting removes it.
   */
  buildNestedOptional(body: Node, count: number): Fragment {
    if (count <= 0) return this.empty();
    const inner = this.build(body);
    let tail: Fragment = inner;
    if (count > 1) {
      const rest = this.buildNestedOptional(body, count - 1);
      this.addEps(inner.end, rest.start);
      tail = { start: inner.start, end: rest.end };
    }
    const start = this.newState();
    const end = this.newState();
    this.addEps(start, tail.start);
    this.addEps(tail.end, end);
    this.addEps(start, end);
    return { start, end };
  }

  /**
   * States reachable from `state` by two or more *distinct simple* ε-paths.
   *
   * Simple, because a path that repeats a state is an ε-loop, and engines
   * break those with an empty-progress check rather than exploring them.
   *
   * Each node is expanded at most twice: the first arrival discovers whatever
   * lies beyond it, the second proves multiplicity, and a third would tell us
   * nothing we do not already know. That cap turns what is worst-case
   * exponential path enumeration into a linear walk.
   */
  multiRouteStates(state: number): Set<number> {
    const counts = new Int32Array(this.epsTrans.length);
    const onPath = new Uint8Array(this.epsTrans.length);
    const multi = new Set<number>();
    const stack: Array<{ node: number; cursor: number }> = [{ node: state, cursor: 0 }];
    onPath[state] = 1;

    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      const edges = this.epsTrans[top.node];
      if (top.cursor >= edges.length) {
        onPath[top.node] = 0;
        stack.pop();
        continue;
      }
      const next = edges[top.cursor++];
      if (onPath[next]) continue; // would close a cycle
      counts[next]++;
      if (counts[next] >= 2) multi.add(next);
      if (counts[next] <= 2) {
        onPath[next] = 1;
        stack.push({ node: next, cursor: 0 });
      }
    }
    return multi;
  }

  epsilonClosure(state: number): number[] {
    const seen = new Set<number>([state]);
    const stack = [state];
    while (stack.length > 0) {
      const q = stack.pop()!;
      for (const next of this.epsTrans[q]) {
        if (!seen.has(next)) {
          seen.add(next);
          stack.push(next);
        }
      }
    }
    return [...seen];
  }
}

/**
 * Is the pattern anchored so that a match can only start at offset 0?
 *
 * This matters for attack construction: an unanchored pattern is retried at
 * every offset, which adds a linear factor, while `^` pins the search and the
 * whole cost comes from one starting position.
 */
function isAnchoredStart(node: Node): boolean {
  switch (node.type) {
    case "Assertion":
      return node.kind === "^";
    case "Concat":
      return node.body.length > 0 && isAnchoredStart(node.body[0]);
    case "Alt":
      return node.body.every(isAnchoredStart);
    case "Group":
      return isAnchoredStart(node.body);
    case "Repeat":
      return node.min > 0 && isAnchoredStart(node.body);
    default:
      return false;
  }
}

/** Merge parallel edges to the same target, so the product stays small. */
function mergeTransitions(transitions: CharTransition[]): CharTransition[] {
  if (transitions.length <= 1) return transitions;
  const byTarget = new Map<number, CharTransition>();
  for (const t of transitions) {
    const existing = byTarget.get(t.to);
    if (existing) {
      existing.set = existing.set.union(t.set);
      existing.multiPath ||= t.multiPath;
    } else {
      byTarget.set(t.to, { ...t });
    }
  }
  return [...byTarget.values()];
}

export interface CompileOptions {
  maxStates?: number;
}

export function compile(pattern: Pattern, options: CompileOptions = {}): NFA {
  const maxStates = options.maxStates ?? DEFAULT_MAX_STATES;
  const builder = new Builder(maxStates);
  const frag = builder.build(pattern.root);

  // ε-elimination: δ'(q, a) = { p' | p ∈ closure(q), p --a--> p' }.
  // Closure is applied before consuming and not after, which keeps distinct
  // paths distinct while collapsing pure-ε ambiguity — the kind that costs a
  // constant, not a curve.
  const closures: number[][] = [];
  for (let q = 0; q < builder.charTrans.length; q++) closures.push(builder.epsilonClosure(q));

  const rawTransitions: CharTransition[][] = [];
  const rawAccepting = new Set<number>();
  for (let q = 0; q < builder.charTrans.length; q++) {
    const multi = builder.multiRouteStates(q);
    const out: CharTransition[] = [];
    for (const p of closures[q]) {
      if (p === frag.end) rawAccepting.add(q);
      for (const t of builder.charTrans[p]) out.push({ ...t, multiPath: multi.has(p) });
    }
    rawTransitions.push(mergeTransitions(out));
  }

  // Keep only states reachable from the initial one. States that cannot reach
  // an accepting state are deliberately kept: a backtracking engine still
  // walks into dead ends, and that work is part of the attack.
  const remap = new Map<number, number>();
  const order: number[] = [];
  const queue = [frag.start];
  remap.set(frag.start, 0);
  order.push(frag.start);
  while (queue.length > 0) {
    const q = queue.shift()!;
    for (const t of rawTransitions[q]) {
      if (!remap.has(t.to)) {
        remap.set(t.to, order.length);
        order.push(t.to);
        queue.push(t.to);
      }
    }
  }

  const transitions: CharTransition[][] = order.map((q) =>
    rawTransitions[q].map((t) => ({ ...t, to: remap.get(t.to)! })),
  );
  const accepting = new Set<number>();
  for (const q of order) if (rawAccepting.has(q)) accepting.add(remap.get(q)!);

  return {
    stateCount: order.length,
    initial: 0,
    accepting,
    transitions,
    pattern,
    approximations: builder.approximations,
    anchoredStart: isAnchoredStart(pattern.root),
  };
}

/** Total number of transitions, for reporting and budgeting. */
export function transitionCount(nfa: NFA): number {
  let n = 0;
  for (const row of nfa.transitions) n += row.length;
  return n;
}

/**
 * Run the automaton as a plain (non-backtracking) simulation.
 *
 * Used by tests and by witness validation to confirm that a generated string
 * really is accepted or rejected by the modelled language.
 */
export function simulate(nfa: NFA, input: string): boolean {
  let current = new Set<number>([nfa.initial]);
  for (const ch of input) {
    const cp = ch.codePointAt(0)!;
    const next = new Set<number>();
    for (const q of current) {
      for (const t of nfa.transitions[q]) {
        if (t.set.has(cp)) next.add(t.to);
      }
    }
    if (next.size === 0) return false;
    current = next;
  }
  for (const q of current) if (nfa.accepting.has(q)) return true;
  return false;
}
