/**
 * Decides whether a backtracking engine can be made to do super-linear work.
 *
 * The theory, in one paragraph. A backtracking matcher explores every path
 * through the NFA before it can report failure, so its worst-case cost on an
 * input of length n is the number of distinct paths that spell that input.
 * That number is governed by the automaton's *degree of ambiguity*:
 *
 *   - Exponential (EDA). Some state q and word w admit two distinct paths
 *     q ⟶w⟶ q. Pumping w then gives 2^n paths.
 *   - Polynomial (IDA). Distinct states q1 ≠ q2 and a word w admit
 *     q1 ⟶w⟶ q1, q1 ⟶w⟶ q2, and q2 ⟶w⟶ q2. A chain of k such states
 *     gives Θ(n^k).
 *   - Otherwise the automaton is finitely ambiguous and matching is linear.
 *
 * Both conditions are checked on product automata, where "two paths on the
 * same word" becomes "one path in the product". Following Weideman et al.,
 * *Analyzing Matching Time Behavior of Backtracking Regular Expression
 * Matchers* (CIAA 2016).
 *
 * One thing the automaton of a single match attempt does not show: an
 * unanchored regex that fails at offset 0 is retried at offset 1, 2, … n.
 * That search loop is itself a pump. `\s*,\s*` is unambiguous, yet on a run
 * of n spaces every one of the n attempts consumes the rest of the run before
 * failing — Θ(n²), and the single most common shape of ReDoS in real
 * advisories. So polynomial ambiguity is decided on Σ*·A, with the Σ* loop
 * standing for the engine's retries.
 */

import { CharSet } from "./charset.ts";
import type { NFA } from "./nfa.ts";
import { walk } from "./ast.ts";

export type Verdict = "safe" | "polynomial" | "exponential";

/** A source range, used to point at the culprit sub-expression. */
export interface SourceSpan {
  start: number;
  end: number;
}

export interface Witness {
  /** Code points that drive the automaton from its initial state to the pump. */
  prefix: number[];
  /** Code points of one repetition of the pumpable word. */
  pump: number[];
  /** The automaton states the pump loops on. */
  pumpStates: number[];
  /**
   * Every character each pump position could have been. `pump` holds one
   * sample; the rest let attack construction try other character classes
   * when an assertion like `\b` depends on which one is chosen.
   */
  pumpSets: CharSet[];
  /** True when the pump relies on the engine retrying at later offsets. */
  retried: boolean;
}

export interface AnalysisResult {
  verdict: Verdict;
  /**
   * Weaker witnesses worth measuring when the best one turns out harmless.
   * The highest-degree pump is not always the one that fails: for
   * `\s*\n\s*` the degree-3 pump "\n" always matches, while the degree-2
   * pump " " makes every retry fail.
   */
  alternatives: Witness[];
  /** 1 for linear, k for Θ(n^k), `Infinity` for exponential. */
  degree: number;
  witness: Witness | null;
  /** The part of the pattern responsible, as an offset range into the source. */
  hotspot: SourceSpan | null;
  /** True when a budget was hit, so a "safe" verdict is not a proof. */
  truncated: boolean;
}

export interface AnalysisOptions {
  /** Cap on explored product states, across both checks. */
  maxProductStates?: number;
  /** Model the engine retrying an unanchored pattern at every offset. On by default. */
  searchLoop?: boolean;
}

const DEFAULT_MAX_PRODUCT_STATES = 250_000;

/* ------------------------------------------------------------------ *
 * Graph utilities
 * ------------------------------------------------------------------ */

/**
 * Tarjan's strongly connected components, iterative so that deep automata do
 * not overflow the call stack. Returns a component id per node.
 */
function stronglyConnectedComponents(
  nodeCount: number,
  successors: (node: number) => number[],
): { component: Int32Array; count: number } {
  const index = new Int32Array(nodeCount).fill(-1);
  const lowlink = new Int32Array(nodeCount);
  const onStack = new Uint8Array(nodeCount);
  const component = new Int32Array(nodeCount).fill(-1);
  const stack: number[] = [];
  let nextIndex = 0;
  let count = 0;

  for (let root = 0; root < nodeCount; root++) {
    if (index[root] !== -1) continue;

    // Each frame is [node, position in its successor list].
    const frames: Array<[number, number, number[]]> = [[root, 0, successors(root)]];
    index[root] = lowlink[root] = nextIndex++;
    stack.push(root);
    onStack[root] = 1;

    while (frames.length > 0) {
      const frame = frames[frames.length - 1];
      const [node, cursor, succ] = frame;

      if (cursor < succ.length) {
        frame[1]++;
        const next = succ[cursor];
        if (index[next] === -1) {
          index[next] = lowlink[next] = nextIndex++;
          stack.push(next);
          onStack[next] = 1;
          frames.push([next, 0, successors(next)]);
        } else if (onStack[next]) {
          if (index[next] < lowlink[node]) lowlink[node] = index[next];
        }
        continue;
      }

      frames.pop();
      if (frames.length > 0) {
        const parent = frames[frames.length - 1][0];
        if (lowlink[node] < lowlink[parent]) lowlink[parent] = lowlink[node];
      }
      if (lowlink[node] === index[node]) {
        for (;;) {
          const member = stack.pop()!;
          onStack[member] = 0;
          component[member] = count;
          if (member === node) break;
        }
        count++;
      }
    }
  }
  return { component, count };
}

/** States that lie on at least one cycle — the only places a pump can live. */
function cycleStates(nfa: NFA): { members: Set<number>; component: Int32Array } {
  const succ = (q: number) => nfa.transitions[q].map((t) => t.to);
  const { component } = stronglyConnectedComponents(nfa.stateCount, succ);

  const sizes = new Map<number, number>();
  for (let q = 0; q < nfa.stateCount; q++) {
    sizes.set(component[q], (sizes.get(component[q]) ?? 0) + 1);
  }

  const members = new Set<number>();
  for (let q = 0; q < nfa.stateCount; q++) {
    if ((sizes.get(component[q]) ?? 0) > 1) members.add(q);
    // A singleton component still cycles if it has a self-loop.
    else if (nfa.transitions[q].some((t) => t.to === q)) members.add(q);
  }
  return { members, component };
}

/* ------------------------------------------------------------------ *
 * Path reconstruction
 * ------------------------------------------------------------------ */

interface StepInfo {
  from: number;
  codePoint: number;
  set: CharSet;
  span: SourceSpan;
}

interface Path {
  codePoints: number[];
  sets: CharSet[];
  spans: SourceSpan[];
}

/** Walk parent pointers back to the seed, producing the code points read. */
function reconstruct(parents: Map<number, StepInfo>, from: number, to: number): Path {
  const codePoints: number[] = [];
  const sets: CharSet[] = [];
  const spans: SourceSpan[] = [];
  let cursor = to;
  while (cursor !== from) {
    const step = parents.get(cursor);
    if (!step) break;
    codePoints.push(step.codePoint);
    sets.push(step.set);
    spans.push(step.span);
    cursor = step.from;
  }
  codePoints.reverse();
  sets.reverse();
  spans.reverse();
  return { codePoints, sets, spans };
}

/** Shortest input that drives the automaton from `from` to `to`. */
function shortestInput(nfa: NFA, from: number, to: number): number[] | null {
  if (from === to) return [];
  const parents = new Map<number, StepInfo>();
  const seen = new Set<number>([from]);
  const queue = [from];
  while (queue.length > 0) {
    const q = queue.shift()!;
    for (const t of nfa.transitions[q]) {
      if (seen.has(t.to)) continue;
      seen.add(t.to);
      parents.set(t.to, { from: q, codePoint: t.set.sample(), set: t.set, span: { start: t.start, end: t.end } });
      if (t.to === to) return reconstruct(parents, from, to).codePoints;
      queue.push(t.to);
    }
  }
  return null;
}

/** Transitions with a negative offset belong to the synthetic search loop, not the source. */
function sourceSpan(...edges: { start: number; end: number }[]): SourceSpan {
  const real = edges.filter((e) => e.start >= 0);
  if (real.length === 0) return { start: -1, end: -1 };
  return { start: Math.min(...real.map((e) => e.start)), end: Math.max(...real.map((e) => e.end)) };
}

function spanOf(spans: SourceSpan[]): SourceSpan | null {
  spans = spans.filter((s) => s.start >= 0);
  if (spans.length === 0) return null;
  let start = Infinity;
  let end = -Infinity;
  for (const s of spans) {
    if (s.start < start) start = s.start;
    if (s.end > end) end = s.end;
  }
  return { start, end };
}

/* ------------------------------------------------------------------ *
 * Exponential ambiguity (EDA)
 * ------------------------------------------------------------------ */

interface ProductEdge {
  from: number;
  to: number;
  codePoint: number;
  set: CharSet;
  span: SourceSpan;
  /** True when the two components did not take the same transition in the same way. */
  divergent: boolean;
}

/**
 * Search the pair product A × A for a strongly connected component that
 * contains a diagonal state (q, q) and, inside that same component, at least
 * one divergent edge.
 *
 * Mutual reachability inside the component then gives a cycle
 * (q,q) ⟶ u ⟶ v ⟶ (q,q) that passes through the divergent edge, and reading
 * its label off each component yields two *different* paths from q to q on
 * one word — the definition of exponential ambiguity.
 *
 * "Divergent" is broader than "off the diagonal". Two components sitting on
 * the same state can still be exploring different things if they arrived by
 * different ε-routes, which is how `(a*)*` blows up while looking, after
 * ε-elimination, like a single innocent self-loop.
 */
function findExponentialAmbiguity(
  nfa: NFA,
  budget: { remaining: number },
): { witness: Witness; hotspot: SourceSpan | null }[] {
  const n = nfa.stateCount;
  const encode = (a: number, b: number) => a * n + b;

  // Explore forward from every diagonal state. The result is closed under
  // successors, so components computed here match components of the full product.
  const adjacency = new Map<number, ProductEdge[]>();
  const queue: number[] = [];
  for (let q = 0; q < n; q++) {
    const id = encode(q, q);
    adjacency.set(id, []);
    queue.push(id);
  }

  while (queue.length > 0) {
    const id = queue.shift()!;
    const a = Math.floor(id / n);
    const b = id % n;
    const edges = adjacency.get(id)!;
    const outA = nfa.transitions[a];
    const outB = nfa.transitions[b];

    for (let i = 0; i < outA.length; i++) {
      const t1 = outA[i];
      for (let j = 0; j < outB.length; j++) {
        const t2 = outB[j];
        const shared = t1.set.intersect(t2.set);
        if (shared.isEmpty()) continue;

        // The pair has diverged if it was already off the diagonal, if the two
        // components picked different edges, or if this one edge is reachable
        // by more than one ε-route and so can be taken two different ways.
        const divergent = a !== b || i !== j || t1.multiPath;
        const next = encode(t1.to, t2.to);
        edges.push({
          from: id,
          to: next,
          codePoint: shared.sample(),
          set: shared,
          span: { start: Math.min(t1.start, t2.start), end: Math.max(t1.end, t2.end) },
          divergent,
        });
        if (!adjacency.has(next)) {
          if (budget.remaining-- <= 0) return [];
          adjacency.set(next, []);
          queue.push(next);
        }
      }
    }
  }

  // Compact the sparse product ids into a dense range for Tarjan.
  const ids = [...adjacency.keys()];
  const dense = new Map<number, number>();
  ids.forEach((id, i) => dense.set(id, i));
  const succ = (i: number) => adjacency.get(ids[i])!.map((e) => dense.get(e.to)!);
  const { component } = stronglyConnectedComponents(ids.length, succ);
  const componentOf = (id: number) => component[dense.get(id)!];

  const diagonalOf = new Map<number, number>();
  for (const id of ids) {
    if (Math.floor(id / n) !== id % n) continue;
    const comp = componentOf(id);
    if (!diagonalOf.has(comp)) diagonalOf.set(comp, id);
  }

  // A divergent edge counts only if it stays inside its component; otherwise
  // it leaves the cycle and cannot be part of a pump.
  const divergentIn = new Map<number, ProductEdge>();
  for (const edges of adjacency.values()) {
    for (const edge of edges) {
      if (!edge.divergent) continue;
      const comp = componentOf(edge.from);
      if (componentOf(edge.to) !== comp) continue;
      if (!divergentIn.has(comp)) divergentIn.set(comp, edge);
    }
  }

  // Every exponential loop, not just the first: which one can be driven to
  // failure depends on what surrounds it, and that is for measurement to say.
  const found: { witness: Witness; hotspot: SourceSpan | null }[] = [];
  for (const [comp, diagonalId] of diagonalOf) {
    if (found.length >= 3) break;
    const edge = divergentIn.get(comp);
    if (!edge) continue;

    const inComponent = (id: number) => componentOf(id) === comp;
    const legIn = pathWithin(adjacency, diagonalId, edge.from, inComponent);
    const legOut = pathWithin(adjacency, edge.to, diagonalId, inComponent);
    if (!legIn || !legOut) continue;

    const pumpState = Math.floor(diagonalId / n);
    const prefix = shortestInput(nfa, nfa.initial, pumpState);
    if (prefix === null) continue;

    const pump = [...legIn.codePoints, edge.codePoint, ...legOut.codePoints];
    if (pump.length === 0) continue;

    found.push({
      witness: { prefix, pump, pumpStates: [pumpState], pumpSets: [...legIn.sets, edge.set, ...legOut.sets], retried: false },
      hotspot: spanOf([...legIn.spans, edge.span, ...legOut.spans]),
    });
  }
  return found;
}

/** `productPath`, but an empty walk is a valid answer when the ends coincide. */
function pathWithin(
  adjacency: Map<number, ProductEdge[]>,
  from: number,
  to: number,
  allowed: (id: number) => boolean,
): Path | null {
  if (from === to) return { codePoints: [], sets: [], spans: [] };
  return productPath(adjacency, from, to, allowed);
}

/**
 * Shortest path between two distinct product states, restricted to a subgraph.
 *
 * `to` is recognised on arrival rather than after dequeuing, so it is never
 * entered as an interior node and the returned path is a genuine walk.
 */
function productPath(
  adjacency: Map<number, ProductEdge[]>,
  from: number,
  to: number,
  allowed: (id: number) => boolean,
): Path | null {
  if (from === to) throw new Error("productPath requires distinct endpoints");
  const parents = new Map<number, StepInfo>();
  const seen = new Set<number>([from]);
  const queue = [from];

  while (queue.length > 0) {
    const id = queue.shift()!;
    for (const edge of adjacency.get(id) ?? []) {
      if (!allowed(edge.to)) continue;
      if (edge.to === to) {
        parents.set(to, { from: id, codePoint: edge.codePoint, set: edge.set, span: edge.span });
        return reconstruct(parents, from, to);
      }
      if (seen.has(edge.to)) continue;
      seen.add(edge.to);
      parents.set(edge.to, { from: id, codePoint: edge.codePoint, set: edge.set, span: edge.span });
      queue.push(edge.to);
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Polynomial ambiguity (IDA)
 * ------------------------------------------------------------------ */

/**
 * Does some word w satisfy q1 ⟶w⟶ q1, q1 ⟶w⟶ q2, q2 ⟶w⟶ q2?
 *
 * Searched as a path in the triple product from (q1, q1, q2) to (q1, q2, q2).
 * The first component can only travel inside q1's SCC (it has to come back to
 * q1) and the third only inside q2's, which is what keeps the cube small
 * enough to explore directly.
 */
function findPumpBetween(
  nfa: NFA,
  q1: number,
  q2: number,
  component: Int32Array,
  budget: { remaining: number },
): Path | null {
  const n = nfa.stateCount;
  const encode = (a: number, b: number, c: number) => (a * n + b) * n + c;
  const start = encode(q1, q1, q2);
  const target = encode(q1, q2, q2);
  const comp1 = component[q1];
  const comp3 = component[q2];

  const parents = new Map<number, StepInfo>();
  const seen = new Set<number>([start]);
  const queue = [start];

  while (queue.length > 0) {
    const id = queue.shift()!;
    const c = id % n;
    const b = Math.floor(id / n) % n;
    const a = Math.floor(id / (n * n));

    for (const t1 of nfa.transitions[a]) {
      if (component[t1.to] !== comp1) continue;
      for (const t2 of nfa.transitions[b]) {
        const shared12 = t1.set.intersect(t2.set);
        if (shared12.isEmpty()) continue;
        for (const t3 of nfa.transitions[c]) {
          if (component[t3.to] !== comp3) continue;
          const shared = shared12.intersect(t3.set);
          if (shared.isEmpty()) continue;

          const next = encode(t1.to, t2.to, t3.to);
          if (seen.has(next)) continue;
          seen.add(next);
          parents.set(next, {
            from: id,
            codePoint: shared.sample(),
            set: shared,
            span: sourceSpan(t1, t2, t3),
          });
          if (next === target) return reconstruct(parents, start, target);
          if (budget.remaining-- <= 0) return null;
          queue.push(next);
        }
      }
    }
  }
  return null;
}

/**
 * Longest chain in the IDA relation. A chain of k states means Θ(n^k).
 *
 * A cycle in the relation would mean unbounded degree, which in fact implies
 * exponential ambiguity, so it is reported as such rather than as a number.
 */
function longestChain(
  nodes: number[],
  edges: Map<number, number[]>,
): { length: number; path: number[]; cyclic: boolean } {
  const dense = new Map<number, number>();
  nodes.forEach((q, i) => dense.set(q, i));
  const succ = (i: number): number[] => {
    const out: number[] = [];
    for (const q of edges.get(nodes[i]) ?? []) {
      const j = dense.get(q);
      if (j !== undefined) out.push(j);
    }
    return out;
  };
  const { component } = stronglyConnectedComponents(nodes.length, succ);

  const sizes = new Map<number, number>();
  for (const c of component) sizes.set(c, (sizes.get(c) ?? 0) + 1);
  for (const size of sizes.values()) {
    if (size > 1) return { length: Infinity, path: [], cyclic: true };
  }

  const best = new Map<number, { length: number; path: number[] }>();
  const visiting = new Set<number>();

  const walk = (i: number): { length: number; path: number[] } => {
    const cached = best.get(i);
    if (cached) return cached;
    if (visiting.has(i)) return { length: 1, path: [nodes[i]] };
    visiting.add(i);

    let result = { length: 1, path: [nodes[i]] };
    for (const j of succ(i)) {
      const sub = walk(j);
      if (sub.length + 1 > result.length) {
        result = { length: sub.length + 1, path: [nodes[i], ...sub.path] };
      }
    }
    visiting.delete(i);
    best.set(i, result);
    return result;
  };

  let overall = { length: 1, path: [] as number[] };
  for (let i = 0; i < nodes.length; i++) {
    const r = walk(i);
    if (r.length > overall.length) overall = r;
  }
  return { length: overall.length, path: overall.path, cyclic: false };
}

interface PolynomialCandidate {
  degree: number;
  witness: Witness;
  hotspot: SourceSpan | null;
}

function findPolynomialAmbiguity(
  nfa: NFA,
  budget: { remaining: number },
  searchState: number | null,
  trustFirstAttempt: boolean,
): PolynomialCandidate[] {
  const { members, component } = cycleStates(nfa);
  if (members.size < 2) return [];

  const pumps = [...members].sort((a, b) => a - b);

  // A retry only repeats work if the attempt can fail. If the loop it enters
  // passes through an unconditionally accepting state, the attempt matches
  // and the search stops: `(ab)*` and `\d+` are found at the first offset.
  const succeedingComponents = new Set<number>();
  for (const q of nfa.acceptsUnconditionally) succeedingComponents.add(component[q]);

  // Chains are grouped by pump word. A chain q1 → q2 → q3 whose two links
  // needed *different* words is real ambiguity, but no single string
  // prefix·w^n exercises it, and a degree we cannot hand someone an input for
  // is a degree we have no business claiming. Grouping keeps the reported
  // exponent and the generated witness describing the same attack.
  const byWord = new Map<
    string,
    { edges: Map<number, number[]>; nodes: Set<number>; word: Path }
  >();

  for (const q1 of pumps) {
    for (const q2 of pumps) {
      if (q1 === q2) continue;
      // A retry that reaches an unconditionally accepting loop simply
      // succeeds; the search never gets to repeat the work.
      if (q1 === searchState && succeedingComponents.has(component[q2])) continue;
      const found = findPumpBetween(nfa, q1, q2, component, budget);
      if (!found || found.codePoints.length === 0) continue;

      const key = found.codePoints.join(",");
      let group = byWord.get(key);
      if (!group) {
        group = { edges: new Map(), nodes: new Set(), word: found };
        byWord.set(key, group);
      }
      if (!group.edges.has(q1)) group.edges.set(q1, []);
      group.edges.get(q1)!.push(q2);
      group.nodes.add(q1);
      group.nodes.add(q2);
    }
  }
  const candidates: PolynomialCandidate[] = [];
  for (const group of byWord.values()) {
    let chain = longestChain([...group.nodes], group.edges);

    // The search loop only earns its link if the attempt at offset 0 fails.
    // If pumping reaches an unconditional accept, that attempt matches and
    // there is no second offset: drop the loop and keep what remains.
    if (trustFirstAttempt && searchState !== null && chain.path[0] === searchState && firstAttemptSucceeds(nfa, searchState, group.word.codePoints, chain.length + 2)) {
      group.nodes.delete(searchState);
      group.edges.delete(searchState);
      if (group.nodes.size < 2) continue;
      chain = longestChain([...group.nodes], group.edges);
    }
    if (chain.cyclic) continue; // an IDA cycle implies EDA, already checked

    const head = chain.path[0];
    const prefix = shortestInput(nfa, nfa.initial, head);
    if (prefix === null) continue;

    candidates.push({
      degree: chain.length,
      witness: { prefix, pump: group.word.codePoints, pumpStates: chain.path, pumpSets: group.word.sets, retried: chain.path[0] === searchState },
      hotspot: spanOf(group.word.spans),
    });
  }
  // Highest degree first; among equals, the shorter pump is the clearer attack.
  return candidates.sort((a, b) => b.degree - a.degree || a.witness.pump.length - b.witness.pump.length);
}

/**
 * Run the single attempt that starts at offset 0 over pump^repetitions and
 * report whether it ever reaches an unconditionally accepting state.
 */
function firstAttemptSucceeds(nfa: NFA, searchState: number, pump: number[], repetitions: number): boolean {
  // The search state's non-loop edges are exactly the original initial state's.
  let current = new Set<number>([searchState]);
  const accepts = (states: Set<number>) => [...states].some((q) => q !== searchState && nfa.acceptsUnconditionally.has(q));
  for (let r = 0; r < repetitions; r++) {
    for (const cp of pump) {
      const next = new Set<number>();
      for (const q of current) {
        for (const t of nfa.transitions[q]) {
          if (t.start < 0) continue; // do not follow the retry loop itself
          if (t.set.has(cp)) next.add(t.to);
        }
      }
      if (next.size === 0) return false;
      if (accepts(next)) return true;
      current = next;
    }
  }
  return false;
}

/**
 * Σ*·A: a new initial state that loops on every character and can also start
 * the pattern. Its self-loop is marked with a negative source offset so it
 * never shows up in a hotspot or in the attack alphabet.
 */
function withSearchLoop(nfa: NFA): { nfa: NFA; searchState: number } {
  const searchState = nfa.stateCount;
  const loop = { set: CharSet.all(), to: searchState, start: -1, end: -1, multiPath: false };
  const transitions = [...nfa.transitions, [loop, ...nfa.transitions[nfa.initial]]];
  const accepting = new Set(nfa.accepting);
  const acceptsUnconditionally = new Set(nfa.acceptsUnconditionally);
  if (accepting.has(nfa.initial)) accepting.add(searchState);
  if (acceptsUnconditionally.has(nfa.initial)) acceptsUnconditionally.add(searchState);
  return {
    nfa: { ...nfa, stateCount: nfa.stateCount + 1, initial: searchState, transitions, accepting, acceptsUnconditionally },
    searchState,
  };
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

export function analyze(nfa: NFA, options: AnalysisOptions = {}): AnalysisResult {
  const budget = { remaining: options.maxProductStates ?? DEFAULT_MAX_PRODUCT_STATES };

  // The search loop cannot create exponential ambiguity (nothing returns to
  // it), so EDA is decided on the plain automaton, which is smaller.
  const exponentials = findExponentialAmbiguity(nfa, budget);
  const exponential = exponentials[0];

  // `^` pins the first attempt; `y` forbids later ones.
  // A pattern that can match the empty string unconditionally succeeds at
  // offset 0 and is never retried either.
  const retried =
    !nfa.anchoredStart &&
    !nfa.pattern.flags.includes("y") &&
    !nfa.acceptsUnconditionally.has(nfa.initial) &&
    options.searchLoop !== false;
  const searched = retried ? withSearchLoop(nfa) : { nfa, searchState: null };
  // The first-attempt check reads `^` as ε, so a success that goes through a
  // `^` branch may be one only offset 0 can have: in `^\W+|\W+$` a leading
  // "Z" defeats it and every later retry takes the `\W+$` branch.
  let pinnedBranch = false;
  walk(nfa.pattern.root, (node) => {
    if (node.type === "Assertion" && node.kind === "^") pinnedBranch = true;
  });
  const polynomial = findPolynomialAmbiguity(searched.nfa, budget, searched.searchState, !pinnedBranch).filter((c) => c.degree >= 2);

  if (exponential) {
    return {
      verdict: "exponential",
      degree: Infinity,
      witness: exponential.witness,
      alternatives: [...exponentials.slice(1).map((e) => e.witness), ...polynomial.slice(0, 2).map((c) => c.witness)],
      hotspot: exponential.hotspot,
      truncated: false,
    };
  }

  if (polynomial.length > 0) {
    const [best, ...rest] = polynomial;
    return {
      verdict: "polynomial",
      degree: best.degree,
      witness: best.witness,
      alternatives: rest.slice(0, 2).map((c) => c.witness),
      hotspot: best.hotspot ?? polynomial.find((c) => c.hotspot)?.hotspot ?? null,
      truncated: budget.remaining <= 0,
    };
  }

  return {
    verdict: "safe",
    degree: 1,
    witness: null,
    alternatives: [],
    hotspot: null,
    truncated: budget.remaining <= 0,
  };
}
