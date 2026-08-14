/**
 * A recursive-descent parser for JavaScript regular expression syntax.
 *
 * Scope note: this parses for *analysis*, not for execution. It accepts the
 * ECMAScript grammar including Annex B legacy forms, because real-world
 * regexes in real-world repos use them, but it does not attempt to reject
 * every pattern the spec would reject — a pattern that only `new RegExp`
 * can adjudicate is validated by handing it to `new RegExp` up front.
 */

import { CharSet, caseFold, MAX_CODE_POINT } from "./charset.ts";
import {
  type Node,
  type Pattern,
  type PatternFeatures,
  RegexParseError,
} from "./ast.ts";

/** Quantifiers with a bound above this are treated as effectively unbounded. */
const LARGE_REPEAT_THRESHOLD = 100;

const DIGIT = CharSet.range(0x30, 0x39);
const WORD = CharSet.fromIntervals([
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x5f, 0x5f],
  [0x61, 0x7a],
]);
const SPACE = CharSet.fromIntervals([
  [0x09, 0x0d],
  [0x20, 0x20],
  [0xa0, 0xa0],
  [0x1680, 0x1680],
  [0x2000, 0x200a],
  [0x2028, 0x2029],
  [0x202f, 0x202f],
  [0x205f, 0x205f],
  [0x3000, 0x3000],
  [0xfeff, 0xfeff],
]);
const LINE_TERMINATOR = CharSet.fromIntervals([
  [0x0a, 0x0a],
  [0x0d, 0x0d],
  [0x2028, 0x2029],
]);

const CONTROL_ESCAPES: Record<string, number> = {
  t: 0x09,
  n: 0x0a,
  v: 0x0b,
  f: 0x0c,
  r: 0x0d,
};

class Parser {
  source: string;
  flags: string;
  pos: number;
  unicode: boolean;
  ignoreCase: boolean;
  dotAll: boolean;
  captureCount: number;
  groupNames: string[];
  /** Total captures in the whole pattern, pre-scanned to resolve `\1` vs octal. */
  totalCaptures: number;
  features: PatternFeatures;

  constructor(source: string, flags: string) {
    this.source = source;
    this.flags = flags;
    this.pos = 0;
    this.unicode = flags.includes("u") || flags.includes("v");
    this.ignoreCase = flags.includes("i");
    this.dotAll = flags.includes("s");
    this.captureCount = 0;
    this.groupNames = [];
    this.totalCaptures = countCaptures(source);
    this.features = {
      backreferences: false,
      lookaround: false,
      anchors: false,
      wordBoundaries: false,
      largeBoundedRepeat: false,
    };
  }

  error(message: string, at: number = this.pos): never {
    throw new RegexParseError(message, at, this.source);
  }

  eof(): boolean {
    return this.pos >= this.source.length;
  }

  peek(offset = 0): string {
    return this.source[this.pos + offset] ?? "";
  }

  eat(ch: string): boolean {
    if (this.source.startsWith(ch, this.pos)) {
      this.pos += ch.length;
      return true;
    }
    return false;
  }

  expect(ch: string): void {
    if (!this.eat(ch)) this.error(`expected '${ch}'`);
  }

  /** Wrap a raw code-point set with the `i` flag's case closure. */
  charSet(set: CharSet, start: number, end: number): Node {
    return { type: "Char", set: this.ignoreCase ? caseFold(set) : set, start, end };
  }

  /* ---------------------------------------------------------------- *
   * Grammar
   * ---------------------------------------------------------------- */

  parsePattern(): Node {
    const node = this.parseAlternation();
    if (!this.eof()) this.error(`unexpected '${this.peek()}'`);
    return node;
  }

  parseAlternation(): Node {
    const start = this.pos;
    const branches: Node[] = [this.parseConcat()];
    while (this.eat("|")) branches.push(this.parseConcat());
    if (branches.length === 1) return branches[0];
    return { type: "Alt", body: branches, start, end: this.pos };
  }

  parseConcat(): Node {
    const start = this.pos;
    const body: Node[] = [];
    while (!this.eof() && this.peek() !== "|" && this.peek() !== ")") {
      body.push(this.parseTerm());
    }
    if (body.length === 0) return { type: "Empty", start, end: this.pos };
    if (body.length === 1) return body[0];
    return { type: "Concat", body, start, end: this.pos };
  }

  parseTerm(): Node {
    const start = this.pos;
    const atom = this.parseAtom();
    return this.parseQuantifier(atom, start);
  }

  parseQuantifier(atom: Node, start: number): Node {
    const ch = this.peek();
    let min: number;
    let max: number;

    if (ch === "*") {
      this.pos++;
      min = 0;
      max = Infinity;
    } else if (ch === "+") {
      this.pos++;
      min = 1;
      max = Infinity;
    } else if (ch === "?") {
      this.pos++;
      min = 0;
      max = 1;
    } else if (ch === "{") {
      const braced = this.tryParseBraces();
      if (!braced) return atom;
      [min, max] = braced;
    } else {
      return atom;
    }

    if (min > max) this.error("quantifier range is out of order", start);
    if (
      atom.type === "Assertion" ||
      (atom.type === "Lookaround" && this.unicode)
    ) {
      this.error("nothing to repeat", start);
    }

    const lazy = this.eat("?");
    if (Number.isFinite(max) && max > LARGE_REPEAT_THRESHOLD) {
      this.features.largeBoundedRepeat = true;
    }
    return { type: "Repeat", body: atom, min, max, lazy, start, end: this.pos };
  }

  /**
   * `{n}`, `{n,}`, `{n,m}`. Returns null and rewinds when the brace is not a
   * quantifier at all — outside Unicode mode a bare `{` is a literal.
   */
  tryParseBraces(): [number, number] | null {
    const save = this.pos;
    this.pos++; // '{'
    const minDigits = this.readDigits();
    if (minDigits === null) {
      if (this.unicode) this.error("incomplete quantifier", save);
      this.pos = save;
      return null;
    }
    let max: number;
    if (this.eat(",")) {
      const maxDigits = this.readDigits();
      max = maxDigits === null ? Infinity : maxDigits;
    } else {
      max = minDigits;
    }
    if (!this.eat("}")) {
      if (this.unicode) this.error("unterminated quantifier", save);
      this.pos = save;
      return null;
    }
    return [minDigits, max];
  }

  readDigits(): number | null {
    const start = this.pos;
    while (this.peek() >= "0" && this.peek() <= "9") this.pos++;
    if (this.pos === start) return null;
    return Number(this.source.slice(start, this.pos));
  }

  parseAtom(): Node {
    const start = this.pos;
    const ch = this.peek();

    switch (ch) {
      case "^":
        this.pos++;
        this.features.anchors = true;
        return { type: "Assertion", kind: "^", start, end: this.pos };
      case "$":
        this.pos++;
        this.features.anchors = true;
        return { type: "Assertion", kind: "$", start, end: this.pos };
      case ".": {
        this.pos++;
        const set = this.dotAll ? CharSet.all() : CharSet.all().subtract(LINE_TERMINATOR);
        return this.charSet(set, start, this.pos);
      }
      case "(":
        return this.parseGroup();
      case "[":
        return this.parseCharacterClass();
      case "\\":
        return this.parseEscape();
      case ")":
        this.error("unmatched ')'");
        break;
      case "*":
      case "+":
      case "?":
        this.error("nothing to repeat");
        break;
    }

    const cp = this.readCodePoint();
    return this.charSet(CharSet.of(cp), start, this.pos);
  }

  parseGroup(): Node {
    const start = this.pos;
    this.expect("(");

    if (this.eat("?")) {
      if (this.eat(":")) {
        const body = this.parseAlternation();
        this.expect(")");
        return { type: "Group", body, index: null, name: null, start, end: this.pos };
      }
      if (this.eat("=") || this.eat("!")) {
        const negate = this.source[this.pos - 1] === "!";
        const body = this.parseAlternation();
        this.expect(")");
        this.features.lookaround = true;
        return { type: "Lookaround", body, behind: false, negate, start, end: this.pos };
      }
      if (this.eat("<=") || this.eat("<!")) {
        const negate = this.source[this.pos - 1] === "!";
        const body = this.parseAlternation();
        this.expect(")");
        this.features.lookaround = true;
        return { type: "Lookaround", body, behind: true, negate, start, end: this.pos };
      }
      if (this.peek() === "<") {
        this.pos++;
        const name = this.readGroupName();
        const index = ++this.captureCount;
        this.groupNames.push(name);
        const body = this.parseAlternation();
        this.expect(")");
        return { type: "Group", body, index, name, start, end: this.pos };
      }
      // Modifier groups, `(?i:...)`, and anything else exotic.
      this.error("unsupported group prefix");
    }

    const index = ++this.captureCount;
    const body = this.parseAlternation();
    this.expect(")");
    return { type: "Group", body, index, name: null, start, end: this.pos };
  }

  readGroupName(): string {
    const start = this.pos;
    while (!this.eof() && this.peek() !== ">") this.pos++;
    if (this.eof()) this.error("unterminated group name", start);
    const name = this.source.slice(start, this.pos);
    this.pos++; // '>'
    if (name.length === 0) this.error("empty group name", start);
    return name;
  }

  /* ---------------------------------------------------------------- *
   * Escapes
   * ---------------------------------------------------------------- */

  parseEscape(): Node {
    const start = this.pos;
    this.expect("\\");
    if (this.eof()) this.error("trailing backslash", start);
    const ch = this.peek();

    if (ch === "b" || ch === "B") {
      this.pos++;
      this.features.wordBoundaries = true;
      return { type: "Assertion", kind: ch === "b" ? "\\b" : "\\B", start, end: this.pos };
    }

    // Named backreference. `\k` outside Unicode mode with no `<` is a literal k.
    if (ch === "k") {
      if (this.peek(1) === "<") {
        this.pos += 2;
        const name = this.readGroupName();
        this.features.backreferences = true;
        return { type: "Backref", ref: name, start, end: this.pos };
      }
      if (this.unicode) this.error("invalid named backreference", start);
    }

    // Numeric backreference: only when the index actually exists, otherwise
    // Annex B says treat it as a legacy octal escape.
    if (ch >= "1" && ch <= "9") {
      const save = this.pos;
      const n = this.readDigits()!;
      if (n <= this.totalCaptures) {
        this.features.backreferences = true;
        return { type: "Backref", ref: n, start, end: this.pos };
      }
      this.pos = save;
    }

    const set = this.tryParseClassEscape();
    if (set) return this.charSet(set, start, this.pos);

    const cp = this.parseCharacterEscape();
    return this.charSet(CharSet.of(cp), start, this.pos);
  }

  /**
   * `\d \D \w \W \s \S \p{..} \P{..}` — the escapes that denote a whole set.
   * Assumes the leading backslash is already consumed. Returns null for
   * escapes that denote a single character.
   */
  tryParseClassEscape(): CharSet | null {
    const ch = this.peek();
    switch (ch) {
      case "d":
        this.pos++;
        return DIGIT;
      case "D":
        this.pos++;
        return DIGIT.negate();
      case "w":
        this.pos++;
        return WORD;
      case "W":
        this.pos++;
        return WORD.negate();
      case "s":
        this.pos++;
        return SPACE;
      case "S":
        this.pos++;
        return SPACE.negate();
      case "p":
      case "P": {
        if (!this.unicode) return null; // `\p` is a literal 'p' without the u flag
        const negate = ch === "P";
        const start = this.pos;
        this.pos++;
        if (!this.eat("{")) this.error("expected '{' after \\p", start);
        const bodyStart = this.pos;
        while (!this.eof() && this.peek() !== "}") this.pos++;
        if (this.eof()) this.error("unterminated unicode property escape", start);
        const body = this.source.slice(bodyStart, this.pos);
        this.pos++; // '}'
        const set = unicodePropertySet(body, this.source, start);
        return negate ? set.negate() : set;
      }
    }
    return null;
  }

  /** A single-code-point escape, with the backslash already consumed. */
  parseCharacterEscape(): number {
    const start = this.pos;
    const ch = this.peek();

    if (ch in CONTROL_ESCAPES) {
      this.pos++;
      return CONTROL_ESCAPES[ch];
    }

    if (ch === "c") {
      const letter = this.peek(1);
      if (/[A-Za-z]/.test(letter)) {
        this.pos += 2;
        return letter.toUpperCase().charCodeAt(0) - 64;
      }
      if (this.unicode) this.error("invalid control escape", start);
      this.pos++;
      return 0x5c; // Annex B: a bare `\c` is a literal backslash
    }

    if (ch === "x") {
      const hex = this.source.slice(this.pos + 1, this.pos + 3);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        this.pos += 3;
        return parseInt(hex, 16);
      }
      if (this.unicode) this.error("invalid hex escape", start);
      this.pos++;
      return 0x78; // literal 'x'
    }

    if (ch === "u") {
      const cp = this.tryParseUnicodeEscape();
      if (cp !== null) return cp;
      if (this.unicode) this.error("invalid unicode escape", start);
      this.pos++;
      return 0x75; // literal 'u'
    }

    if (ch === "0" && !/[0-9]/.test(this.peek(1))) {
      this.pos++;
      return 0x00;
    }

    // Annex B legacy octal, e.g. `\101` for 'A'.
    if (!this.unicode && ch >= "0" && ch <= "7") {
      let value = 0;
      let digits = 0;
      while (digits < 3 && this.peek() >= "0" && this.peek() <= "7") {
        const next = value * 8 + Number(this.peek());
        if (next > 0xff) break;
        value = next;
        this.pos++;
        digits++;
      }
      return value;
    }

    return this.readCodePoint();
  }

  /** `\uXXXX`, a surrogate pair, or `\u{X..}`. Rewinds and returns null if malformed. */
  tryParseUnicodeEscape(): number | null {
    const save = this.pos;
    this.pos++; // 'u'

    if (this.unicode && this.eat("{")) {
      const start = this.pos;
      while (/[0-9a-fA-F]/.test(this.peek())) this.pos++;
      const hex = this.source.slice(start, this.pos);
      if (hex.length === 0 || !this.eat("}")) {
        this.pos = save;
        return null;
      }
      const cp = parseInt(hex, 16);
      if (cp > MAX_CODE_POINT) this.error("code point out of range", save);
      return cp;
    }

    const hex = this.source.slice(this.pos, this.pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
      this.pos = save;
      return null;
    }
    this.pos += 4;
    const unit = parseInt(hex, 16);

    // In Unicode mode a leading surrogate followed by `\uDC00`-style trailing
    // surrogate denotes one astral code point.
    if (this.unicode && unit >= 0xd800 && unit <= 0xdbff && this.source.startsWith("\\u", this.pos)) {
      const tailHex = this.source.slice(this.pos + 2, this.pos + 6);
      if (/^[0-9a-fA-F]{4}$/.test(tailHex)) {
        const tail = parseInt(tailHex, 16);
        if (tail >= 0xdc00 && tail <= 0xdfff) {
          this.pos += 6;
          return (unit - 0xd800) * 0x400 + (tail - 0xdc00) + 0x10000;
        }
      }
    }
    return unit;
  }

  /** Read one literal character, honouring surrogate pairs in Unicode mode. */
  readCodePoint(): number {
    if (this.eof()) this.error("unexpected end of pattern");
    const cp = this.unicode
      ? this.source.codePointAt(this.pos)!
      : this.source.charCodeAt(this.pos);
    this.pos += cp > 0xffff ? 2 : 1;
    return cp;
  }

  /* ---------------------------------------------------------------- *
   * Character classes
   * ---------------------------------------------------------------- */

  parseCharacterClass(): Node {
    const start = this.pos;
    this.expect("[");
    const negate = this.eat("^");
    let set = CharSet.empty();

    while (!this.eof() && this.peek() !== "]") {
      const lowStart = this.pos;
      const low = this.parseClassAtom();

      // A range only forms when '-' is followed by something other than ']'.
      if (this.peek() === "-" && this.peek(1) !== "]" && this.peek(1) !== "") {
        this.pos++;
        const high = this.parseClassAtom();
        if (typeof low !== "number" || typeof high !== "number") {
          // `[\d-x]` is a literal '-' under Annex B, an error in Unicode mode.
          if (this.unicode) this.error("invalid character class range", lowStart);
          set = set.union(typeof low === "number" ? CharSet.of(low) : low);
          set = set.union(CharSet.of(0x2d));
          set = set.union(typeof high === "number" ? CharSet.of(high) : high);
          continue;
        }
        if (low > high) this.error("character class range is out of order", lowStart);
        set = set.union(CharSet.range(low, high));
        continue;
      }

      set = set.union(typeof low === "number" ? CharSet.of(low) : low);
    }

    if (!this.eat("]")) this.error("unterminated character class", start);

    // Case folding applies to the class *contents*, before complementing.
    // ECMAScript canonicalizes the input character and the class members and
    // then tests membership, so /[^a]/i rejects 'A' as well as 'a'. Folding
    // after the complement would wrongly let 'A' back in.
    if (this.ignoreCase) set = caseFold(set);
    return { type: "Char", set: negate ? set.negate() : set, start, end: this.pos };
  }

  /** One element inside `[...]`: a code point, or a set for `\d`-style escapes. */
  parseClassAtom(): number | CharSet {
    if (this.peek() === "\\") {
      this.pos++;
      if (this.eof()) this.error("trailing backslash");
      // `\b` means backspace inside a class, not a word boundary.
      if (this.peek() === "b") {
        this.pos++;
        return 0x08;
      }
      if (this.peek() === "-") {
        this.pos++;
        return 0x2d;
      }
      const set = this.tryParseClassEscape();
      if (set) return set;
      return this.parseCharacterEscape();
    }
    return this.readCodePoint();
  }
}

/**
 * Count capturing groups without parsing, so `\1` can be told apart from an
 * octal escape on the first pass. Skips escaped parens and parens inside
 * character classes.
 */
function countCaptures(source: string): number {
  let count = 0;
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      continue;
    }
    if (ch === "(") {
      const next = source[i + 1];
      // `(` starts a capture unless it is `(?...`, except for `(?<name>`.
      if (next !== "?") count++;
      else if (source[i + 2] === "<" && source[i + 3] !== "=" && source[i + 3] !== "!") count++;
    }
  }
  return count;
}

const propertyCache = new Map<string, CharSet>();

/**
 * Resolve `\p{...}` by asking the host engine about every code point, once,
 * and caching the answer. Shelling the question out to V8 keeps the table
 * exactly as accurate as the engine the analysis is predicting.
 */
function unicodePropertySet(body: string, source: string, at: number): CharSet {
  const cached = propertyCache.get(body);
  if (cached) return cached;

  let probe: RegExp;
  try {
    probe = new RegExp(`^\\p{${body}}$`, "u");
  } catch {
    throw new RegexParseError(`unknown unicode property '${body}'`, at, source);
  }

  const intervals: Array<[number, number]> = [];
  let runStart = -1;
  for (let cp = 0; cp <= MAX_CODE_POINT; cp++) {
    if (cp === 0xd800) cp = 0xe000; // skip the surrogate range
    const inSet = probe.test(String.fromCodePoint(cp));
    if (inSet && runStart < 0) runStart = cp;
    else if (!inSet && runStart >= 0) {
      intervals.push([runStart, cp - 1]);
      runStart = -1;
    }
  }
  if (runStart >= 0) intervals.push([runStart, MAX_CODE_POINT]);

  const set = CharSet.fromIntervals(intervals);
  propertyCache.set(body, set);
  return set;
}

/**
 * Parse a regex into an AST.
 *
 * @param source pattern body, without the `/` delimiters
 * @param flags  ECMAScript flag string
 */
export function parse(source: string, flags = ""): Pattern {
  for (const flag of flags) {
    if (!"dgimsuvy".includes(flag)) {
      throw new RegexParseError(`unknown flag '${flag}'`, 0, source);
    }
  }

  const parser = new Parser(source, flags);
  const root = parser.parsePattern();
  return {
    source,
    flags,
    root,
    captureCount: parser.captureCount,
    groupNames: parser.groupNames,
    features: parser.features,
  };
}
