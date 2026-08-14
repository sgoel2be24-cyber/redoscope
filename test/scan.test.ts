import { test } from "node:test";
import assert from "node:assert/strict";
import { extractRegexes } from "../src/scan.ts";

const sources = (code: string) => extractRegexes(code).map((r) => r.source);

test("finds plain regex literals", () => {
  assert.deepEqual(sources("const re = /abc/g;"), ["abc"]);
  assert.deepEqual(sources("if (/^x$/.test(s)) {}"), ["^x$"]);
  assert.deepEqual(sources("s.replace(/a/, 'b').replace(/c/, 'd')"), ["a", "c"]);
});

test("captures flags", () => {
  const [found] = extractRegexes("const re = /ab+c/gimsu;");
  assert.equal(found.source, "ab+c");
  assert.equal(found.flags, "gimsu");
  assert.equal(found.kind, "literal");
});

test("tells division apart from a regex", () => {
  assert.deepEqual(sources("const x = a / b / c;"), []);
  assert.deepEqual(sources("const x = (a + b) / 2 / 3;"), []);
  assert.deepEqual(sources("const x = arr[0] / len;"), []);
  assert.deepEqual(sources("let ratio = total/count;"), []);
  // ...but after an operator or a keyword, a regex is expected.
  assert.deepEqual(sources("const x = cond ? /a/ : /b/;"), ["a", "b"]);
  assert.deepEqual(sources("return /done/;"), ["done"]);
  assert.deepEqual(sources("const parts = str.split(/,\\s*/);"), [",\\s*"]);
});

test("ignores regex-looking text in comments", () => {
  assert.deepEqual(sources("// const re = /nope/;\nconst r = /yes/;"), ["yes"]);
  assert.deepEqual(sources("/* /nope/ */ const r = /yes/;"), ["yes"]);
  assert.deepEqual(sources("/**\n * matches /nope/\n */\nconst r = /yes/;"), ["yes"]);
});

test("ignores regex-looking text in strings", () => {
  assert.deepEqual(sources(`const s = "/nope/"; const r = /yes/;`), ["yes"]);
  assert.deepEqual(sources(`const s = '/no/pe/'; const r = /yes/;`), ["yes"]);
  assert.deepEqual(sources("const s = `a /nope/ b`; const r = /yes/;"), ["yes"]);
  assert.deepEqual(sources(`const s = "it's \\"quoted\\""; const r = /yes/;`), ["yes"]);
});

test("handles slashes inside character classes", () => {
  assert.deepEqual(sources("const re = /[/]/;"), ["[/]"]);
  assert.deepEqual(sources("const re = /a[^/]*b/;"), ["a[^/]*b"]);
  assert.deepEqual(sources("const re = /\\/\\*[\\s\\S]*?\\*\\//g;"), ["\\/\\*[\\s\\S]*?\\*\\/"]);
});

test("finds RegExp constructors with literal arguments", () => {
  const [found] = extractRegexes(`const re = new RegExp("^a+$", "i");`);
  assert.equal(found.source, "^a+$");
  assert.equal(found.flags, "i");
  assert.equal(found.kind, "constructor");

  assert.deepEqual(sources(`RegExp('x*')`), ["x*"]);
});

test("unescapes constructor arguments the way the engine would", () => {
  // In source the author wrote "\\d+", which is the two characters \d.
  const [found] = extractRegexes(`new RegExp("\\\\d+")`);
  assert.equal(found.source, "\\d+");
  assert.doesNotThrow(() => new RegExp(found.source));
});

test("skips RegExp constructors it cannot resolve statically", () => {
  assert.deepEqual(sources("const re = new RegExp(userInput);"), []);
  assert.deepEqual(sources("const re = new RegExp(`^${prefix}$`);"), []);
});

test("skips a shebang line", () => {
  // `#!/usr/bin/env node` reads as the regex /usr/ with flags "bin".
  assert.deepEqual(sources("#!/usr/bin/env node\nconst r = /yes/;"), ["yes"]);
  assert.deepEqual(sources("#!/usr/bin/env node"), []);
});

test("does not mistake JSX for regexes", () => {
  assert.deepEqual(sources("return <h1>hi</h1></header>;"), []);
  assert.deepEqual(sources("const el = <Foo {...props} />;"), []);
  assert.deepEqual(sources("<div className={cx}>text</div>"), []);
  // A real regex in JSX is still found.
  assert.deepEqual(sources("<Input pattern={/^\\d+$/} />"), ["^\\d+$"]);
});

test("never emits something the engine would reject", () => {
  // Anything invalid is a mis-lex by definition: real code does not ship
  // broken regex literals, so the scanner rewinds instead of reporting.
  for (const code of ["a </b/ c", "x = y </z>", "const a = b < /c", "f(</g>)"]) {
    for (const found of extractRegexes(code)) {
      assert.doesNotThrow(() => new RegExp(found.source, found.flags), code);
    }
  }
});

test("reports accurate line and column", () => {
  const code = ["const a = 1;", "", "const re = /x+/;"].join("\n");
  const [found] = extractRegexes(code, "sample.ts");
  assert.equal(found.line, 3);
  assert.equal(found.column, 12);
  assert.equal(found.file, "sample.ts");
  assert.equal(code.split("\n")[2].slice(found.column - 1), "/x+/;");
});

test("survives a realistic file", () => {
  const code = `
import fs from "node:fs";

const EMAIL = /^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$/i;
const RATIO = total / count;           // division, not a regex
const COMMENT = /\\/\\*[\\s\\S]*?\\*\\//g;

export function check(s: string) {
  if (EMAIL.test(s)) return s.split(/[,;]\\s*/);
  return s.replace(new RegExp("\\\\s+", "g"), " ");
}

// A regex in a comment: /should-not-appear/
const template = \`slash / inside \${a / b} template\`;
`;
  const found = extractRegexes(code, "realistic.ts");
  const bodies = found.map((r) => r.source);

  assert.ok(bodies.includes("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$"));
  assert.ok(bodies.includes("[,;]\\s*"));
  assert.ok(bodies.includes("\\s+"));
  assert.ok(!bodies.some((b) => b.includes("should-not-appear")), "picked up a comment");
  assert.ok(!bodies.some((b) => b.includes("inside")), "picked up template text");

  // Everything found must be a regex the engine actually accepts.
  for (const r of found) assert.doesNotThrow(() => new RegExp(r.source, r.flags), r.source);
});

test("scans its own source without choking", async () => {
  const { collectFiles, scanFile } = await import("../src/scan.ts");
  const files = collectFiles(new URL("../src", import.meta.url).pathname);
  assert.ok(files.length >= 8, `expected to find the source files, got ${files.length}`);

  for (const file of files) {
    for (const found of scanFile(file)) {
      assert.doesNotThrow(
        () => new RegExp(found.source, found.flags),
        `${found.file}:${found.line} produced an invalid regex: ${found.raw}`,
      );
    }
  }
});
