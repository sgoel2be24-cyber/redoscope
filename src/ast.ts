import type { CharSet } from "./charset.ts";

/**
 * A deliberately small regex AST.
 *
 * Everything that consumes exactly one character — literals, classes, `.`,
 * `\d`, `\p{L}` — collapses into a single `Char` node carrying a CharSet.
 * The analyser never needs to know how a set was spelled, only what it
 * matches, so `[0-9]` and `\d` are indistinguishable downstream by design.
 */
export type Node =
  | EmptyNode
  | CharNode
  | ConcatNode
  | AltNode
  | RepeatNode
  | GroupNode
  | AssertionNode
  | LookaroundNode
  | BackrefNode;

export interface NodeBase {
  /** Offset of the first character of this node in the pattern source. */
  start: number;
  /** Offset just past the last character of this node. */
  end: number;
}

/** Matches the empty string. Produced by `(?:)`, `a|`, `a{0}`. */
export interface EmptyNode extends NodeBase {
  type: "Empty";
}

/** Consumes exactly one code point drawn from `set`. */
export interface CharNode extends NodeBase {
  type: "Char";
  set: CharSet;
}

export interface ConcatNode extends NodeBase {
  type: "Concat";
  body: Node[];
}

export interface AltNode extends NodeBase {
  type: "Alt";
  body: Node[];
}

export interface RepeatNode extends NodeBase {
  type: "Repeat";
  body: Node;
  min: number;
  /** `Infinity` for unbounded quantifiers. */
  max: number;
  /** `true` for `*?`, `+?`, `{n,m}?`. */
  lazy: boolean;
}

export interface GroupNode extends NodeBase {
  type: "Group";
  body: Node;
  /** 1-based capture index, or `null` for `(?:...)`. */
  index: number | null;
  name: string | null;
}

export interface AssertionNode extends NodeBase {
  type: "Assertion";
  kind: "^" | "$" | "\\b" | "\\B";
}

export interface LookaroundNode extends NodeBase {
  type: "Lookaround";
  body: Node;
  behind: boolean;
  negate: boolean;
}

export interface BackrefNode extends NodeBase {
  type: "Backref";
  ref: number | string;
}

/** Which constructs a pattern actually used. Drives analysis confidence. */
export interface PatternFeatures {
  backreferences: boolean;
  lookaround: boolean;
  anchors: boolean;
  wordBoundaries: boolean;
  /** A quantifier with a large finite bound, e.g. `a{1,5000}`. */
  largeBoundedRepeat: boolean;
}

export interface Pattern {
  /** The pattern body, without delimiters. */
  source: string;
  flags: string;
  root: Node;
  captureCount: number;
  groupNames: string[];
  features: PatternFeatures;
}

export class RegexParseError extends Error {
  index: number;
  source: string;

  constructor(message: string, index: number, source: string) {
    super(`${message} (at offset ${index} in /${source}/)`);
    this.name = "RegexParseError";
    this.index = index;
    this.source = source;
  }
}

/** Depth-first walk over every node, parents before children. */
export function walk(node: Node, visit: (n: Node) => void): void {
  visit(node);
  switch (node.type) {
    case "Concat":
    case "Alt":
      for (const child of node.body) walk(child, visit);
      break;
    case "Repeat":
    case "Group":
    case "Lookaround":
      walk(node.body, visit);
      break;
    default:
      break;
  }
}
