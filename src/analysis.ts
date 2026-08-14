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
 */

import type { CharSet } from "./charset.ts";
import type { NFA } from "./nfa.ts";

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
}

export interface AnalysisResult {
  verdict: Verdict;
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
  span: SourceSpan;
}

/** Walk parent pointers back to the seed, producing the code points read. */
function reconstruct(parents: Map<number, StepInfo>, from: number, to: number): {
  codePoints: number[];
  spans: SourceSpan[];
} {
  const codePoints: number[] = [];
  const spans: SourceSpan[] = [];
  let cursor = to;
  while (cursor !== from) {
    const step = parents.get(cursor);
    if (!step) break;
    codePoints.push(step.codePoint);
    spans.push(step.span);
    cursor = step.from;
  }
  codePoints.reverse();
  spans.reverse();
  return { codePoints, spans };
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
      parents.set(t.to, { from: q, codePoint: t.set.sample(), span: { start: t.start, end: t.end } });
      if (t.to === to) return reconstruct(parents, from, to).codePoints;
      queue.push(t.to);
    }
  }
  return null;
}

function spanOf(spans: SourceSpan[]): SourceSpan | null {
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
): { witness: Witness; hotspot: SourceSpan | null } | null {
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
          span: { start: Math.min(t1.start, t2.start), end: Math.max(t1.end, t2.end) },
          divergent,
        });
        if (!adjacency.has(next)) {
          if (budget.remaining-- <= 0) return null;
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

  for (const [comp, diagonalId] of diagonalOf) {
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

    return {
      witness: { prefix, pump, pumpStates: [pumpState] },
      hotspot: spanOf([...legIn.spans, edge.span, ...legOut.spans]),
    };
  }
  return null;
}

/** `productPath`, but an empty walk is a valid answer when the ends coincide. */
function pathWithin(
  adjacency: Map<number, ProductEdge[]>,
  from: number,
  to: number,
  allowed: (id: number) => boolean,
): { codePoints: number[]; spans: SourceSpan[] } | null {
  if (from === to) return { codePoints: [], spans: [] };
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
): { codePoints: number[]; spans: SourceSpan[] } | null {
  if (from === to) throw new Error("productPath requires distinct endpoints");
  const parents = new Map<number, StepInfo>();
  const seen = new Set<number>([from]);
  const queue = [from];

  while (queue.length > 0) {
    const id = queue.shift()!;
    for (const edge of adjacency.get(id) ?? []) {
      if (!allowed(edge.to)) continue;
      if (edge.to === to) {
        parents.set(to, { from: id, codePoint: edge.codePoint, span: edge.span });
        return reconstruct(parents, from, to);
      }
      if (seen.has(edge.to)) continue;
      seen.add(edge.to);
      parents.set(edge.to, { from: id, codePoint: edge.codePoint, span: edge.span });
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
): { codePoints: number[]; spans: SourceSpan[] } | null {
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
            span: { start: Math.min(t1.start, t2.start, t3.start), end: Math.max(t1.end, t2.end, t3.end) },
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

function findPolynomialAmbiguity(
  nfa: NFA,
  budget: { remaining: number },
): { degree: number; witness: Witness; hotspot: SourceSpan | null } | null {
  const { members, component } = cycleStates(nfa);
  if (members.size < 2) return null;

  const pumps = [...members].sort((a, b) => a - b);

  // Chains are grouped by pump word. A chain q1 → q2 → q3 whose two links
  // needed *different* words is real ambiguity, but no single string
  // prefix·w^n exercises it, and a degree we cannot hand someone an input for
  // is a degree we have no business claiming. Grouping keeps the reported
  // exponent and the generated witness describing the same attack.
  const byWord = new Map<
    string,
    { edges: Map<number, number[]>; nodes: Set<number>; word: { codePoints: number[]; spans: SourceSpan[] } }
  >();

  for (const q1 of pumps) {
    for (const q2 of pumps) {
      if (q1 === q2) continue;
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
  if (byWord.size === 0) return null;

  let best: { degree: number; witness: Witness; hotspot: SourceSpan | null } | null = null;
  for (const group of byWord.values()) {
    const chain = longestChain([...group.nodes], group.edges);
    if (chain.cyclic) continue; // an IDA cycle implies EDA, already checked
    if (best !== null && chain.length <= best.degree) continue;

    const head = chain.path[0];
    const prefix = shortestInput(nfa, nfa.initial, head);
    if (prefix === null) continue;

    best = {
      degree: chain.length,
      witness: { prefix, pump: group.word.codePoints, pumpStates: chain.path },
      hotspot: spanOf(group.word.spans),
    };
  }
  return best;
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

export function analyze(nfa: NFA, options: AnalysisOptions = {}): AnalysisResult {
  const budget = { remaining: options.maxProductStates ?? DEFAULT_MAX_PRODUCT_STATES };

  const exponential = findExponentialAmbiguity(nfa, budget);
  if (exponential) {
    return {
      verdict: "exponential",
      degree: Infinity,
      witness: exponential.witness,
      hotspot: exponential.hotspot,
      truncated: false,
    };
  }

  const polynomial = findPolynomialAmbiguity(nfa, budget);
  if (polynomial && polynomial.degree >= 2) {
    return {
      verdict: "polynomial",
      degree: polynomial.degree,
      witness: polynomial.witness,
      hotspot: polynomial.hotspot,
      truncated: budget.remaining <= 0,
    };
  }

  return {
    verdict: "safe",
    degree: 1,
    witness: null,
    hotspot: null,
    truncated: budget.remaining <= 0,
  };
}
