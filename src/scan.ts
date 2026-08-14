/**
 * Finds regexes in JavaScript and TypeScript source.
 *
 * This is a scanner, not a parser, because a parser would mean a dependency
 * and the job is narrow enough not to need one. The only genuinely hard part
 * of lexing JS without parsing it is deciding whether `/` opens a regex or
 * divides — settled here the way every JS lexer settles it, by looking at the
 * previous significant token. Strings, template literals (including `${}`
 * nesting) and both comment styles are tracked so their contents never get
 * mistaken for code.
 */

import fs from "node:fs";
import path from "node:path";

export interface FoundRegex {
  source: string;
  flags: string;
  file: string;
  line: number;
  column: number;
  /** Exactly as written, for display. */
  raw: string;
  kind: "literal" | "constructor";
}

const SCANNABLE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const SKIPPED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  "vendor",
  ".venv",
]);

/**
 * Tokens after which a `/` starts a regex rather than a division.
 *
 * `}` is the one real gamble: it ends a block (regex may follow) or an object
 * literal (division may follow). Block is overwhelmingly more common before a
 * `/`, and a wrong guess here costs a missed or bogus pattern, not a crash.
 */
const REGEX_PRECEDING_PUNCTUATION = new Set([
  "",
  "(",
  ",",
  "=",
  ":",
  "[",
  "!",
  "&",
  "|",
  "?",
  "{",
  "}",
  ";",
  "+",
  "-",
  "*",
  "/",
  "%",
  "~",
  "^",
  "<",
  ">",
  "\n",
]);

const REGEX_PRECEDING_KEYWORDS = new Set([
  "return",
  "typeof",
  "instanceof",
  "in",
  "of",
  "new",
  "delete",
  "void",
  "throw",
  "case",
  "do",
  "else",
  "yield",
  "await",
  "match",
  "matchAll",
  "replace",
  "replaceAll",
  "split",
  "search",
  "test",
]);

function regexCanFollow(previous: string): boolean {
  if (REGEX_PRECEDING_PUNCTUATION.has(previous)) return true;
  return REGEX_PRECEDING_KEYWORDS.has(previous);
}

function isValidRegex(source: string, flags: string): boolean {
  try {
    new RegExp(source, flags);
    return true;
  } catch {
    return false;
  }
}

/** Interpret the escape sequences in a JS string literal body. */
function unescapeStringBody(body: string): string {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    if (body[i] !== "\\") {
      out += body[i];
      continue;
    }
    const next = body[++i];
    switch (next) {
      case "n": out += "\n"; break;
      case "t": out += "\t"; break;
      case "r": out += "\r"; break;
      case "b": out += "\b"; break;
      case "f": out += "\f"; break;
      case "v": out += "\v"; break;
      case "0": out += "\0"; break;
      case "\n": break; // line continuation
      case "x": {
        out += String.fromCharCode(parseInt(body.slice(i + 1, i + 3), 16));
        i += 2;
        break;
      }
      case "u": {
        if (body[i + 1] === "{") {
          const close = body.indexOf("}", i);
          out += String.fromCodePoint(parseInt(body.slice(i + 2, close), 16));
          i = close;
        } else {
          out += String.fromCharCode(parseInt(body.slice(i + 1, i + 5), 16));
          i += 4;
        }
        break;
      }
      default:
        // Includes `\\`, `\'`, `\"` and, importantly, `\d` — which in a
        // RegExp constructor argument is a literal 'd' unless double-escaped.
        out += next;
    }
  }
  return out;
}

class Scanner {
  code: string;
  file: string;
  pos = 0;
  /** Last significant token, used only to disambiguate `/`. */
  previous = "";
  found: FoundRegex[] = [];
  lineStarts: number[];

  constructor(code: string, file: string) {
    this.code = code;
    this.file = file;
    this.lineStarts = [0];
    for (let i = 0; i < code.length; i++) {
      if (code[i] === "\n") this.lineStarts.push(i + 1);
    }
  }

  positionOf(offset: number): { line: number; column: number } {
    let low = 0;
    let high = this.lineStarts.length - 1;
    while (low < high) {
      const mid = Math.ceil((low + high) / 2);
      if (this.lineStarts[mid] <= offset) low = mid;
      else high = mid - 1;
    }
    return { line: low + 1, column: offset - this.lineStarts[low] + 1 };
  }

  /** Consume a quoted string; returns its unescaped value, or null if unterminated. */
  readString(quote: string): string | null {
    const start = ++this.pos;
    while (this.pos < this.code.length) {
      const ch = this.code[this.pos];
      if (ch === "\\") {
        this.pos += 2;
        continue;
      }
      if (ch === quote) {
        const body = this.code.slice(start, this.pos);
        this.pos++;
        return unescapeStringBody(body);
      }
      if (ch === "\n" && quote !== "`") return null;
      this.pos++;
    }
    return null;
  }

  /** Consume a template literal, descending into each `${...}` as real code. */
  readTemplate(): void {
    this.pos++; // opening backtick
    while (this.pos < this.code.length) {
      const ch = this.code[this.pos];
      if (ch === "\\") {
        this.pos += 2;
        continue;
      }
      if (ch === "`") {
        this.pos++;
        return;
      }
      if (ch === "$" && this.code[this.pos + 1] === "{") {
        this.pos += 2;
        let depth = 1;
        // Substitutions can hold anything, regexes included, but tracking that
        // fully would mean recursing; skipping to the matching brace is enough
        // to avoid mistaking template text for code.
        while (this.pos < this.code.length && depth > 0) {
          const inner = this.code[this.pos];
          if (inner === "{") depth++;
          else if (inner === "}") depth--;
          else if (inner === '"' || inner === "'") {
            this.readString(inner);
            continue;
          }
          this.pos++;
        }
        continue;
      }
      this.pos++;
    }
  }

  /**
   * Try to read a regex literal at the current `/`.
   *
   * Returns null and rewinds when it does not look like one — an unterminated
   * body, or a newline before the closing slash, both of which mean the `/`
   * was division after all.
   */
  readRegexLiteral(): FoundRegex | null {
    const start = this.pos;
    let cursor = this.pos + 1;
    let inClass = false;

    while (cursor < this.code.length) {
      const ch = this.code[cursor];
      if (ch === "\\") {
        cursor += 2;
        continue;
      }
      if (ch === "\n") return null;
      if (inClass) {
        if (ch === "]") inClass = false;
      } else if (ch === "[") {
        inClass = true;
      } else if (ch === "/") {
        break;
      }
      cursor++;
    }
    if (cursor >= this.code.length || this.code[cursor] !== "/") return null;

    const source = this.code.slice(start + 1, cursor);
    cursor++;

    const flagStart = cursor;
    while (cursor < this.code.length && /[a-z]/.test(this.code[cursor])) cursor++;
    const flags = this.code.slice(flagStart, cursor);

    // An empty body is `//`, a comment, which the caller already handled.
    if (source.length === 0) return null;

    // Final arbiter: if the engine will not accept it, this was not a regex.
    // Real code does not ship invalid regex literals, so a rejection means
    // the lexer guessed wrong — most often on JSX, where `<Foo {...p} />`
    // offers a `/` right after a brace. Rewinding is better than reporting a
    // finding nobody wrote.
    if (!isValidRegex(source, flags)) return null;

    this.pos = cursor;
    const { line, column } = this.positionOf(start);
    return {
      source,
      flags,
      file: this.file,
      line,
      column,
      raw: this.code.slice(start, cursor),
      kind: "literal",
    };
  }

  skipSpace(): void {
    while (this.pos < this.code.length && /\s/.test(this.code[this.pos])) this.pos++;
  }

  /** After an identifier `RegExp`, pull out constant string arguments if present. */
  readRegExpConstructor(identifierStart: number): FoundRegex | null {
    const save = this.pos;
    this.skipSpace();
    if (this.code[this.pos] !== "(") {
      this.pos = save;
      return null;
    }
    this.pos++;
    this.skipSpace();

    const quote = this.code[this.pos];
    if (quote !== '"' && quote !== "'") {
      this.pos = save; // a variable, a template, something not statically known
      return null;
    }
    const source = this.readString(quote);
    if (source === null) {
      this.pos = save;
      return null;
    }
    if (!isValidRegex(source, "")) {
      this.pos = save;
      return null;
    }

    let flags = "";
    this.skipSpace();
    if (this.code[this.pos] === ",") {
      this.pos++;
      this.skipSpace();
      const flagQuote = this.code[this.pos];
      if (flagQuote === '"' || flagQuote === "'") {
        flags = this.readString(flagQuote) ?? "";
      }
    }

    const { line, column } = this.positionOf(identifierStart);
    return {
      source,
      flags,
      file: this.file,
      line,
      column,
      raw: this.code.slice(identifierStart, Math.min(this.pos + 1, this.code.length)),
      kind: "constructor",
    };
  }

  scan(): FoundRegex[] {
    // A shebang is not JavaScript, and `#!/usr/bin/env node` parses as a
    // regex `/usr/` with flags `bin` if you let it.
    if (this.code.startsWith("#!")) {
      const newline = this.code.indexOf("\n");
      this.pos = newline === -1 ? this.code.length : newline;
    }

    while (this.pos < this.code.length) {
      const ch = this.code[this.pos];

      if (ch === "\n") {
        this.previous = "\n";
        this.pos++;
        continue;
      }
      if (/\s/.test(ch)) {
        this.pos++;
        continue;
      }

      if (ch === "/" && this.code[this.pos + 1] === "/") {
        while (this.pos < this.code.length && this.code[this.pos] !== "\n") this.pos++;
        continue;
      }
      if (ch === "/" && this.code[this.pos + 1] === "*") {
        const close = this.code.indexOf("*/", this.pos + 2);
        this.pos = close === -1 ? this.code.length : close + 2;
        continue;
      }

      // `</` closes a JSX element. No regex ever starts there, and left alone
      // `</h1></header>` lexes as /h1></ with the flags "header".
      if (ch === "<" && this.code[this.pos + 1] === "/") {
        this.pos += 2;
        this.previous = "jsx-close";
        continue;
      }

      if (ch === '"' || ch === "'") {
        this.readString(ch);
        this.previous = "value";
        continue;
      }
      if (ch === "`") {
        this.readTemplate();
        this.previous = "value";
        continue;
      }

      if (ch === "/" && regexCanFollow(this.previous)) {
        const literal = this.readRegexLiteral();
        if (literal) {
          this.found.push(literal);
          this.previous = "value";
          continue;
        }
      }

      if (/[A-Za-z_$]/.test(ch)) {
        const start = this.pos;
        while (this.pos < this.code.length && /[A-Za-z0-9_$]/.test(this.code[this.pos])) this.pos++;
        const identifier = this.code.slice(start, this.pos);
        if (identifier === "RegExp") {
          const constructed = this.readRegExpConstructor(start);
          if (constructed) {
            this.found.push(constructed);
            this.previous = "value";
            continue;
          }
        }
        this.previous = identifier;
        continue;
      }

      if (/[0-9]/.test(ch)) {
        while (this.pos < this.code.length && /[0-9a-fA-FxXoObBeE._n]/.test(this.code[this.pos])) {
          this.pos++;
        }
        this.previous = "value";
        continue;
      }

      this.previous = ch;
      this.pos++;
    }
    return this.found;
  }
}

export function extractRegexes(code: string, file = "<input>"): FoundRegex[] {
  return new Scanner(code, file).scan();
}

/** Recursively collect scannable source files, skipping the usual noise. */
export function collectFiles(target: string): string[] {
  const stats = fs.statSync(target);
  if (stats.isFile()) return [target];

  const files: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name) || entry.name.startsWith(".")) continue;
        walk(full);
      } else if (SCANNABLE_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(full);
      }
    }
  };
  walk(target);
  return files.sort();
}

export function scanFile(file: string): FoundRegex[] {
  return extractRegexes(fs.readFileSync(file, "utf8"), file);
}
