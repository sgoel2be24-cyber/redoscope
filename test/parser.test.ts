import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "../src/parser.ts";
import { RegexParseError, type Node } from "../src/ast.ts";

const cp = (ch: string) => ch.codePointAt(0)!;

/** Compact structural summary, so assertions stay readable. */
function shape(node: Node): string {
  switch (node.type) {
    case "Empty":
      return "ε";
    case "Char":
      return node.set.toString();
    case "Concat":
      return node.body.map(shape).join(" ");
    case "Alt":
      return `(${node.body.map(shape).join(" | ")})`;
    case "Repeat": {
      const bound =
        node.min === 0 && node.max === Infinity
          ? "*"
          : node.min === 1 && node.max === Infinity
            ? "+"
            : node.min === 0 && node.max === 1
              ? "?"
              : `{${node.min},${node.max === Infinity ? "" : node.max}}`;
      return `${shape(node.body)}${bound}${node.lazy ? "?" : ""}`;
    }
    case "Group":
      return `(${shape(node.body)})`;
    case "Assertion":
      return node.kind;
    case "Lookaround":
      return `(?${node.behind ? "<" : ""}${node.negate ? "!" : "="}${shape(node.body)})`;
    case "Backref":
      return `\\${node.ref}`;
  }
}

const shapeOf = (src: string, flags = "") => shape(parse(src, flags).root);

test("parses concatenation and alternation", () => {
  assert.equal(shapeOf("abc"), "a b c");
  assert.equal(shapeOf("a|b"), "(a | b)");
  assert.equal(shapeOf("ab|cd|"), "(a b | c d | ε)");
});

test("parses all quantifier forms", () => {
  assert.equal(shapeOf("a*"), "a*");
  assert.equal(shapeOf("a+"), "a+");
  assert.equal(shapeOf("a?"), "a?");
  assert.equal(shapeOf("a{3}"), "a{3,3}");
  assert.equal(shapeOf("a{3,}"), "a{3,}");
  assert.equal(shapeOf("a{3,5}"), "a{3,5}");
  assert.equal(shapeOf("a*?"), "a*?");
  assert.equal(shapeOf("a{2,4}?"), "a{2,4}?");
});

test("a quantifier binds only the preceding atom", () => {
  assert.equal(shapeOf("ab*"), "a b*");
  assert.equal(shapeOf("(ab)*"), "(a b)*");
});

test("a non-quantifier brace is a literal outside unicode mode", () => {
  assert.equal(shapeOf("a{"), "a {");
  assert.equal(shapeOf("a{x}"), "a { x }");
  assert.equal(shapeOf("a{2,"), "a { 2 ,");
  assert.throws(() => parse("a{", "u"), RegexParseError);
});

test("parses groups and records capture indices", () => {
  const p = parse("(a)(?:b)(?<tail>c)");
  assert.equal(p.captureCount, 2);
  assert.deepEqual(p.groupNames, ["tail"]);
});

test("parses lookaround in both directions", () => {
  assert.equal(shapeOf("(?=a)"), "(?=a)");
  assert.equal(shapeOf("(?!a)"), "(?!a)");
  assert.equal(shapeOf("(?<=a)"), "(?<=a)");
  assert.equal(shapeOf("(?<!a)"), "(?<!a)");
  assert.equal(parse("(?=a)").features.lookaround, true);
});

test("parses anchors and word boundaries", () => {
  assert.equal(shapeOf("^a$"), "^ a $");
  assert.equal(shapeOf("\\ba\\B"), "\\b a \\B");
  const p = parse("^a\\b");
  assert.equal(p.features.anchors, true);
  assert.equal(p.features.wordBoundaries, true);
});

test("expands predefined class escapes", () => {
  assert.equal(shapeOf("\\d"), "[0-9]");
  assert.equal(shapeOf("\\w"), "[0-9A-Z_a-z]");
  assert.ok(parse("\\D").root.type === "Char");
  const s = parse("\\s").root as Extract<Node, { type: "Char" }>;
  assert.equal(s.set.has(0x20), true);
  assert.equal(s.set.has(0x09), true);
  assert.equal(s.set.has(cp("a")), false);
});

test("dot excludes line terminators unless dotAll", () => {
  const dot = parse(".").root as Extract<Node, { type: "Char" }>;
  assert.equal(dot.set.has(cp("a")), true);
  assert.equal(dot.set.has(0x0a), false);
  assert.equal(dot.set.has(0x2028), false);
  const dotAll = parse(".", "s").root as Extract<Node, { type: "Char" }>;
  assert.equal(dotAll.set.has(0x0a), true);
});

test("parses character classes with ranges and negation", () => {
  assert.equal(shapeOf("[a-z]"), "[a-z]");
  assert.equal(shapeOf("[abc]"), "[a-c]");
  assert.equal(shapeOf("[a-cx-z]"), "[a-cx-z]");
  const neg = parse("[^a-z]").root as Extract<Node, { type: "Char" }>;
  assert.equal(neg.set.has(cp("a")), false);
  assert.equal(neg.set.has(cp("A")), true);
});

test("handles the awkward corners of character classes", () => {
  // Trailing and leading '-' are literal.
  const dash = parse("[a-]").root as Extract<Node, { type: "Char" }>;
  assert.equal(dash.set.has(cp("-")), true);
  assert.equal(dash.set.has(cp("a")), true);
  // '\b' is backspace inside a class.
  const bs = parse("[\\b]").root as Extract<Node, { type: "Char" }>;
  assert.equal(bs.set.has(0x08), true);
  // ']' can be escaped, and a class can hold set escapes.
  const mixed = parse("[\\d\\]]").root as Extract<Node, { type: "Char" }>;
  assert.equal(mixed.set.has(cp("5")), true);
  assert.equal(mixed.set.has(cp("]")), true);
});

test("case folding happens before negation", () => {
  // /[^a]/i matches neither 'a' nor 'A' — verified against the engine below.
  for (const [src, ch, expected] of [
    ["[^a]", "A", false],
    ["[^a]", "a", false],
    ["[^a]", "b", true],
    ["[^a-z]", "Q", false],
    ["[^A]", "a", false],
  ] as const) {
    const set = (parse(src, "i").root as Extract<Node, { type: "Char" }>).set;
    assert.equal(set.has(cp(ch)), expected, `${src} vs ${ch}`);
    assert.equal(new RegExp(src, "i").test(ch), expected, `engine disagrees: ${src} vs ${ch}`);
  }
});

test("the i flag folds literals and ranges", () => {
  const lit = (parse("a", "i").root as Extract<Node, { type: "Char" }>).set;
  assert.equal(lit.has(cp("A")), true);
  const range = (parse("[a-c]", "i").root as Extract<Node, { type: "Char" }>).set;
  assert.equal(range.has(cp("B")), true);
  assert.equal(range.has(cp("D")), false);
});

test("parses character escapes", () => {
  const only = (src: string, flags = "") =>
    (parse(src, flags).root as Extract<Node, { type: "Char" }>).set.intervals[0][0];
  assert.equal(only("\\n"), 0x0a);
  assert.equal(only("\\t"), 0x09);
  assert.equal(only("\\0"), 0x00);
  assert.equal(only("\\x41"), 0x41);
  assert.equal(only("\\u0041"), 0x41);
  assert.equal(only("\\u{1F600}", "u"), 0x1f600);
  assert.equal(only("\\cJ"), 0x0a);
  assert.equal(only("\\101"), 0x41); // legacy octal
  assert.equal(only("\\."), cp("."));
});

test("surrogate pairs are one code point in unicode mode", () => {
  const astral = (parse("\u{1f600}", "u").root as Extract<Node, { type: "Char" }>).set;
  assert.equal(astral.size(), 1);
  assert.equal(astral.has(0x1f600), true);
  // Without the u flag the same source is two code units, so two nodes.
  assert.equal(parse("\u{1f600}").root.type, "Concat");
});

test("distinguishes backreferences from octal escapes", () => {
  const withGroup = parse("(a)\\1");
  assert.equal(withGroup.features.backreferences, true);
  const noGroup = parse("\\1");
  assert.equal(noGroup.features.backreferences, false);
  assert.equal(noGroup.root.type, "Char");
  assert.equal(parse("(?<x>a)\\k<x>").features.backreferences, true);
});

test("resolves forward backreferences", () => {
  // \1 precedes its group, and must still be a backreference.
  assert.equal(parse("\\1(a)").features.backreferences, true);
});

test("parses unicode property escapes", () => {
  const letters = (parse("\\p{L}", "u").root as Extract<Node, { type: "Char" }>).set;
  assert.equal(letters.has(cp("a")), true);
  assert.equal(letters.has(cp("Ω")), true);
  assert.equal(letters.has(cp("1")), false);
  const notLetters = (parse("\\P{L}", "u").root as Extract<Node, { type: "Char" }>).set;
  assert.equal(notLetters.has(cp("a")), false);
  assert.equal(notLetters.has(cp("1")), true);
  // Without the u flag, `\p` is just the letter p.
  assert.equal(shapeOf("\\p"), "p");
});

test("flags large bounded repeats", () => {
  assert.equal(parse("a{1,5}").features.largeBoundedRepeat, false);
  assert.equal(parse("a{1,5000}").features.largeBoundedRepeat, true);
});

test("rejects malformed patterns", () => {
  assert.throws(() => parse("("), RegexParseError);
  assert.throws(() => parse(")"), RegexParseError);
  assert.throws(() => parse("["), RegexParseError);
  assert.throws(() => parse("*a"), RegexParseError);
  assert.throws(() => parse("a\\"), RegexParseError);
  assert.throws(() => parse("a{3,1}"), RegexParseError);
  assert.throws(() => parse("[z-a]"), RegexParseError);
  assert.throws(() => parse("a", "q"), RegexParseError);
});

test("node positions point back into the source", () => {
  const p = parse("ab(cd)*");
  const group = (p.root as Extract<Node, { type: "Concat" }>).body[2];
  assert.equal(group.type, "Repeat");
  assert.equal(p.source.slice(group.start, group.end), "(cd)*");
});

test("agrees with the engine on what parses", () => {
  const patterns = [
    "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$",
    "(\\w+\\s?)*$",
    "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$",
    "\\/\\*[\\s\\S]*?\\*\\/",
    "(?<year>\\d{4})-(?<month>\\d{2})",
    "[\\u0041-\\u005A]+",
    "a{2,}b|c(?!d)",
  ];
  for (const src of patterns) {
    new RegExp(src); // sanity: the engine accepts it
    assert.doesNotThrow(() => parse(src), `failed to parse /${src}/`);
  }
});
