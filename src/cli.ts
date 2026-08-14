#!/usr/bin/env node
/**
 * redoscope command line.
 *
 * Two shapes: inspect one pattern, or scan a tree. Both print the evidence,
 * not just the verdict — a finding you cannot reproduce is a finding nobody
 * will act on.
 */

import fs from "node:fs";
import process from "node:process";
import { inspect, type Report } from "./index.ts";
import { renderHtmlReport } from "./report.ts";
import { describeAttack } from "./witness.ts";
import { repetitionsToExceed } from "./dynamic.ts";
import { collectFiles, scanFile, type FoundRegex } from "./scan.ts";

/* ------------------------------------------------------------------ *
 * Output helpers
 * ------------------------------------------------------------------ */

const useColor =
  process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== "dumb";

/** Wrap text in an ANSI SGR pair, or return it untouched when colour is off. */
const paint = (code: string) => (text: string) =>
  useColor ? `\u001b[${code}m${text}\u001b[0m` : text;
const bold = paint("1");
const dim = paint("2");
const red = paint("31");
const yellow = paint("33");
const green = paint("32");
const cyan = paint("36");

function severityLabel(report: Report): string {
  if (report.error) return dim("error");
  if (report.verdict === "safe") return green("linear");
  if (report.exploitable === false) return dim("not exploitable");
  if (report.verdict === "exponential") return red("exponential");
  return yellow(`polynomial O(n^${report.degree})`);
}

/** `1.2s`, `340ms`, `0.8ms` — whichever reads best at that magnitude. */
function formatMs(ms: number): string {
  if (ms >= 10_000) return `${(ms / 1000).toFixed(0)}s`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms >= 10) return `${ms.toFixed(0)}ms`;
  return `${ms.toFixed(1)}ms`;
}

function measurementLine(report: Report): string | null {
  const dynamic = report.dynamic;
  if (!dynamic) return null;

  if (dynamic.engineError) return `engine rejected the pattern: ${dynamic.engineError}`;
  if (dynamic.growth === "constant" || dynamic.growth === "linear") {
    return `measured ${dynamic.growth} — the ambiguity is real but cannot be triggered`;
  }

  const pumpLength = report.attack?.pump.length ?? 1;
  const shape =
    dynamic.base !== null
      ? pumpLength === 1
        ? `${dynamic.base.toFixed(2)}^n`
        : `${dynamic.base.toFixed(2)}^n per ${pumpLength}-char pump`
      : dynamic.exponent !== null
        ? `O(n^${dynamic.exponent.toFixed(2)})`
        : dynamic.growth;

  const quality = dynamic.fitQuality !== null ? dim(` (R² ${dynamic.fitQuality.toFixed(3)})`) : "";
  return `measured ${bold(shape)}${quality}`;
}

/** A caret run under the sub-expression responsible. */
function hotspotLines(report: Report): string[] {
  if (!report.hotspot) return [`    /${report.source}/${report.flags}`];
  const { start, end } = report.hotspot;
  const gutter = "    /";
  const underline = " ".repeat(gutter.length + start) + red("~".repeat(Math.max(1, end - start)));
  return [`${gutter}${report.source}/${report.flags}`, underline];
}

function printReport(report: Report, indent = ""): void {
  const write = (line: string) => console.log(indent + line);

  if (report.error) {
    write(`${dim("error")}  ${report.error}`);
    return;
  }

  write(`${severityLabel(report)}${report.confidence === "reduced" ? dim("  (reduced confidence)") : ""}`);
  write("");
  for (const line of hotspotLines(report)) write(line);

  if (report.verdict === "safe") {
    write("");
    write(dim("  no ambiguous loop reachable; matching time is linear in input length"));
    return;
  }

  write("");
  const attack = report.attack!;
  const measured = measurementLine(report);

  // Only advertise an attack string that was shown to do damage. Printing a
  // 128 KB input next to "cannot be triggered" would undercut the finding.
  if (report.exploitable !== false) {
    const shown = report.dynamic?.worst?.repetitions ?? 25;
    write(`  ${bold("attack")}    ${cyan(describeAttack(attack, shown))}`);
  }

  if (measured) {
    write(`  ${bold("evidence")}  ${measured}`);

    const samples = (report.dynamic?.samples ?? []).filter((s) => s.ms >= 0.5 || s.timedOut);
    const shownSamples = samples.slice(-3);
    for (const sample of shownSamples) {
      const cost = sample.timedOut
        ? red(`killed after ${formatMs(sample.ms)}`)
        : formatMs(sample.ms);
      write(dim(`            n=${sample.repetitions}, ${sample.length} chars → ${cost}`));
    }

    if (report.dynamic) {
      const pumpLength = report.attack?.pump.length ?? 1;
      const oneSecond = repetitionsToExceed(report.dynamic, 1000, pumpLength);
      if (oneSecond) {
        write(
          dim(
            `            ${oneSecond.characters} characters of input costs ~1s of CPU`,
          ),
        );
      }
    }
  } else {
    write(`  ${dim("evidence")}  ${dim("not measured (--no-measure)")}`);
  }

  const notes: string[] = [];
  if (report.approximations.backreference) notes.push("backreferences modelled as empty");
  if (report.approximations.lookaround) notes.push("lookaround modelled as empty");
  if (report.approximations.widenedRepeat) notes.push("a large bounded repeat was widened");
  if (notes.length > 0) {
    write("");
    write(dim(`  note: ${notes.join("; ")}`));
  }
}

/* ------------------------------------------------------------------ *
 * Argument parsing
 * ------------------------------------------------------------------ */

interface Options {
  json: boolean;
  measure: boolean;
  timeoutMs: number;
  failOn: "exponential" | "polynomial" | "any" | "never";
  quiet: boolean;
  html: string | null;
}

const HELP = `redoscope — prove-it-or-lose-it ReDoS analysis

USAGE
  redoscope <pattern> [flags]      inspect a single regex
  redoscope scan <path>...         inspect every regex in a file or tree

OPTIONS
  --json              machine-readable output
  --html <file>       write a self-contained HTML report (scan only)
  --no-measure        static analysis only; do not run the engine
  --timeout <ms>      budget per attack candidate (default 2000)
  --fail-on <level>   exit non-zero on: exponential | polynomial | any | never
                      (default: exponential)
  --quiet             findings only, no per-pattern detail
  -h, --help          this text

EXAMPLES
  redoscope '^(a+)+$'
  redoscope '(\\w+\\s?)*$' i
  redoscope scan src/ --fail-on polynomial

A pattern may be given bare or as a literal: '/^(a+)+$/i'.
Exit status is 1 when something at or above --fail-on is found, 2 on usage errors.`;

function parseArgs(argv: string[]): { options: Options; rest: string[] } | null {
  const options: Options = {
    json: false,
    measure: true,
    timeoutMs: 2000,
    failOn: "exponential",
    quiet: false,
    html: null,
  };
  const rest: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--json":
        options.json = true;
        break;
      case "--no-measure":
        options.measure = false;
        break;
      case "--quiet":
      case "-q":
        options.quiet = true;
        break;
      case "--timeout": {
        const value = Number(argv[++i]);
        if (!Number.isFinite(value) || value <= 0) return null;
        options.timeoutMs = value;
        break;
      }
      case "--html": {
        const value = argv[++i];
        if (!value || value.startsWith("--")) return null;
        options.html = value;
        break;
      }
      case "--fail-on": {
        const value = argv[++i];
        if (!["exponential", "polynomial", "any", "never"].includes(value)) return null;
        options.failOn = value as Options["failOn"];
        break;
      }
      case "-h":
      case "--help":
        return null;
      default:
        if (arg.startsWith("--")) return null;
        rest.push(arg);
    }
  }
  return { options, rest };
}

/** Accept both `^(a+)+$` and `/^(a+)+$/i`. */
function splitPattern(input: string, explicitFlags?: string): { source: string; flags: string } {
  if (input.length > 1 && input.startsWith("/")) {
    const close = input.lastIndexOf("/");
    if (close > 0) {
      return { source: input.slice(1, close), flags: input.slice(close + 1) };
    }
  }
  return { source: input, flags: explicitFlags ?? "" };
}

function isFinding(report: Report, failOn: Options["failOn"]): boolean {
  if (failOn === "never" || report.error) return false;
  if (report.verdict === "safe") return false;
  // A measured "cannot be triggered" is not a finding. That is the entire
  // reason the measurement exists.
  if (report.exploitable === false) return false;
  if (failOn === "any") return true;
  if (failOn === "polynomial") return true;
  return report.verdict === "exponential";
}

/* ------------------------------------------------------------------ *
 * Commands
 * ------------------------------------------------------------------ */

function runSingle(args: string[], options: Options): number {
  const { source, flags } = splitPattern(args[0], args[1]);
  const report = inspect(source, flags, {
    measure: options.measure,
    timeoutMs: options.timeoutMs,
  });

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("");
    printReport(report);
    console.log("");
  }
  if (report.error) return 2;
  return isFinding(report, options.failOn) ? 1 : 0;
}

interface ScanFinding {
  location: FoundRegex;
  report: Report;
}

function runScan(paths: string[], options: Options): number {
  const files: string[] = [];
  for (const target of paths) {
    try {
      files.push(...collectFiles(target));
    } catch (error) {
      console.error(`redoscope: cannot read ${target}: ${(error as Error).message}`);
      return 2;
    }
  }

  // Identical patterns are common across a codebase and measurement is the
  // expensive part, so each distinct pattern is analysed once.
  const cache = new Map<string, Report>();
  const findings: ScanFinding[] = [];
  // Everything the analyser found ambiguous, including what it then ruled out
  // by measurement. A report that shows only confirmed hits hides the fact
  // that the tool considered and dismissed the lookalikes.
  const ambiguous: ScanFinding[] = [];
  let regexCount = 0;
  const tally = { exponential: 0, polynomial: 0, safe: 0, unexploitable: 0, errors: 0 };

  for (const file of files) {
    let found: FoundRegex[];
    try {
      found = scanFile(file);
    } catch {
      continue;
    }
    for (const location of found) {
      regexCount++;
      // NUL separates the two fields because a regex source may itself
      // contain spaces: /a b/ and /a/b would otherwise share a cache key.
      const key = `${location.source}\u0000${location.flags}`;
      let report = cache.get(key);
      if (!report) {
        report = inspect(location.source, location.flags, {
          measure: options.measure,
          timeoutMs: options.timeoutMs,
        });
        cache.set(key, report);
      }

      if (report.error) tally.errors++;
      else if (report.verdict === "safe") tally.safe++;
      else if (report.exploitable === false) tally.unexploitable++;
      else if (report.verdict === "exponential") tally.exponential++;
      else tally.polynomial++;

      if (!report.error && report.verdict !== "safe") ambiguous.push({ location, report });
      if (isFinding(report, options.failOn)) findings.push({ location, report });
    }
  }

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          files: files.length,
          regexes: regexCount,
          summary: tally,
          findings: findings.map((f) => ({ ...f.location, report: f.report })),
        },
        null,
        2,
      ),
    );
    return findings.length > 0 ? 1 : 0;
  }

  if (options.html) {
    const html = renderHtmlReport(
      ambiguous,
      {
        files: files.length,
        regexes: regexCount,
        exponential: tally.exponential,
        polynomial: tally.polynomial,
        unexploitable: tally.unexploitable,
        safe: tally.safe,
        errors: tally.errors,
      },
      paths.join(", "),
    );
    fs.writeFileSync(options.html, html, "utf8");
    console.log(dim(`wrote ${options.html}`));
  }

  console.log("");
  for (const { location, report } of findings) {
    const where = `${location.file}:${location.line}:${location.column}`;
    console.log(`${bold(where)}  ${severityLabel(report)}`);
    if (!options.quiet) {
      printReport(report, "  ");
      console.log("");
    }
  }

  const parts = [
    `${files.length} file${files.length === 1 ? "" : "s"}`,
    `${regexCount} regex${regexCount === 1 ? "" : "es"}`,
  ];
  console.log(dim(`scanned ${parts.join(", ")}`));

  const summary: string[] = [];
  if (tally.exponential > 0) summary.push(red(`${tally.exponential} exponential`));
  if (tally.polynomial > 0) summary.push(yellow(`${tally.polynomial} polynomial`));
  if (tally.unexploitable > 0) summary.push(dim(`${tally.unexploitable} ambiguous but not exploitable`));
  if (tally.errors > 0) summary.push(dim(`${tally.errors} unparseable`));
  summary.push(green(`${tally.safe} linear`));
  console.log(summary.join(dim(" · ")));
  console.log("");

  return findings.length > 0 ? 1 : 0;
}

function main(): number {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed || parsed.rest.length === 0) {
    console.log(HELP);
    return parsed && parsed.rest.length === 0 ? 2 : 0;
  }

  const { options, rest } = parsed;
  if (rest[0] === "scan") {
    const paths = rest.slice(1);
    if (paths.length === 0) {
      console.error("redoscope: scan needs at least one path");
      return 2;
    }
    return runScan(paths, options);
  }
  return runSingle(rest, options);
}

process.exitCode = main();
