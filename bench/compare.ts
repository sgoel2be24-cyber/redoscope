/**
 * Compares three ways of answering "is this regex dangerous", on whatever
 * corpus of real code you point it at.
 *
 *   1. star height  — the classic heuristic: an unbounded quantifier nested
 *                     inside another unbounded quantifier is "unsafe". This is
 *                     essentially what `safe-regex` checks.
 *   2. redoscope    — the automaton verdict, ambiguity only.
 *   3. measured     — the automaton verdict after the generated attack has
 *                     been run against the engine and timed.
 *
 * Usage: node bench/compare.ts <path>...
 */

import { parse } from "../src/parser.ts";
import { inspect } from "../src/index.ts";
import { collectFiles, scanFile } from "../src/scan.ts";
import type { Node } from "../src/ast.ts";

/**
 * Star height, counting only unbounded quantifiers.
 *
 * Height ≥ 2 means a loop inside a loop, which is what the common heuristic
 * treats as dangerous. It is cheap, it needs no automaton, and it is wrong in
 * both directions — which is the point of measuring it here.
 */
function starHeight(node: Node): number {
  switch (node.type) {
    case "Repeat": {
      const inner = starHeight(node.body);
      return node.max === Infinity ? inner + 1 : inner;
    }
    case "Concat":
    case "Alt":
      return Math.max(0, ...node.body.map(starHeight));
    case "Group":
    case "Lookaround":
      return starHeight(node.body);
    default:
      return 0;
  }
}

interface Row {
  source: string;
  flags: string;
  where: string;
  heuristic: boolean;
  redoscope: string;
  measured: string;
  exploitable: boolean | null;
}

function main(): void {
  const targets = process.argv.slice(2);
  if (targets.length === 0) {
    console.error("usage: node bench/compare.ts <path>...");
    process.exitCode = 2;
    return;
  }

  const seen = new Set<string>();
  const rows: Row[] = [];

  for (const target of targets) {
    for (const file of collectFiles(target)) {
      let found;
      try {
        found = scanFile(file);
      } catch {
        continue;
      }
      for (const location of found) {
        const key = `${location.source}\u0000${location.flags}`;
        if (seen.has(key)) continue;
        seen.add(key);

        let heuristic = false;
        try {
          heuristic = starHeight(parse(location.source, location.flags).root) >= 2;
        } catch {
          continue;
        }

        const report = inspect(location.source, location.flags, { timeoutMs: 1500 });
        if (report.error) continue;

        rows.push({
          source: location.source,
          flags: location.flags,
          where: `${location.file}:${location.line}`,
          heuristic,
          redoscope: report.verdict,
          measured: report.dynamic?.growth ?? (report.verdict === "safe" ? "linear" : "unknown"),
          exploitable: report.exploitable,
        });
      }
    }
  }

  const isReal = (r: Row) => r.exploitable === true;
  const heuristicFlags = rows.filter((r) => r.heuristic);
  const redoscopeFlags = rows.filter((r) => r.redoscope !== "safe");
  const confirmed = rows.filter(isReal);

  console.log(`corpus: ${rows.length} distinct regexes\n`);

  const table = [
    ["", "flagged", "false positives", "missed"],
    [
      "star height ≥ 2",
      String(heuristicFlags.length),
      String(heuristicFlags.filter((r) => !isReal(r)).length),
      String(confirmed.filter((r) => !r.heuristic).length),
    ],
    [
      "redoscope (static)",
      String(redoscopeFlags.length),
      String(redoscopeFlags.filter((r) => !isReal(r)).length),
      String(confirmed.filter((r) => r.redoscope === "safe").length),
    ],
    [
      "redoscope (measured)",
      String(confirmed.length),
      "0",
      "0",
    ],
  ];
  const widths = table[0].map((_, i) => Math.max(...table.map((row) => row[i].length)));
  for (const [index, row] of table.entries()) {
    console.log(row.map((cell, i) => cell.padEnd(widths[i])).join("   "));
    if (index === 0) console.log(widths.map((w) => "-".repeat(w)).join("   "));
  }

  console.log("\n'false positives' counts patterns flagged that measurement could not make slow.");
  console.log("The measured row is the reference, so it scores zero by construction.\n");

  const heuristicOnly = rows.filter((r) => r.heuristic && r.redoscope === "safe");
  if (heuristicOnly.length > 0) {
    console.log(`flagged by star height, provably safe (${heuristicOnly.length}):`);
    for (const row of heuristicOnly.slice(0, 8)) {
      console.log(`  /${row.source.slice(0, 78)}/${row.flags}`);
      console.log(`    ${row.where}`);
    }
  }

  const ambiguousButSafe = rows.filter((r) => r.redoscope !== "safe" && r.exploitable === false);
  if (ambiguousButSafe.length > 0) {
    console.log(`\nambiguous but not exploitable (${ambiguousButSafe.length}):`);
    for (const row of ambiguousButSafe.slice(0, 8)) {
      console.log(`  /${row.source.slice(0, 78)}/${row.flags}`);
      console.log(`    ${row.where} — measured ${row.measured}`);
    }
  }

  const missedByHeuristic = confirmed.filter((r) => !r.heuristic);
  if (missedByHeuristic.length > 0) {
    console.log(`\nconfirmed slow, missed by star height (${missedByHeuristic.length}):`);
    for (const row of missedByHeuristic.slice(0, 8)) {
      console.log(`  /${row.source.slice(0, 78)}/${row.flags}`);
      console.log(`    ${row.where} — measured ${row.measured}`);
    }
  }
}

main();
