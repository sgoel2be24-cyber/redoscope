/**
 * SARIF 2.1.0 output, so findings land in GitHub code scanning (and any other
 * SARIF consumer) as annotated alerts on the offending line.
 *
 * Only findings are emitted — the same set that drives the exit status. A
 * pattern that measured "not exploitable" is not an alert; putting it in the
 * Security tab would be exactly the noise this tool exists to remove.
 */

import path from "node:path";
import type { Report } from "./core.ts";
import type { FoundRegex } from "./scan.ts";
import { describeAttack } from "./witness.ts";
import { repetitionsToExceed } from "./growth.ts";

const HELP_URI = "https://github.com/sgoel2be24-cyber/redoscope#how-it-works";

const RULES = [
  {
    id: "redoscope/exponential",
    name: "ExponentialBacktracking",
    shortDescription: { text: "Regex backtracks exponentially on a crafted input" },
    fullDescription: {
      text: "Some input makes a backtracking engine explore exponentially many paths. redoscope generated such an input and timed it against the real engine.",
    },
    helpUri: HELP_URI,
    defaultConfiguration: { level: "error" },
    properties: { tags: ["security", "redos", "CWE-1333"], "security-severity": "7.5", precision: "very-high" },
  },
  {
    id: "redoscope/polynomial",
    name: "PolynomialBacktracking",
    shortDescription: { text: "Regex backtracks polynomially on a crafted input" },
    fullDescription: {
      text: "Matching time grows as a polynomial of degree two or more in input length. Dangerous when the input is attacker-controlled and unbounded.",
    },
    helpUri: HELP_URI,
    defaultConfiguration: { level: "warning" },
    properties: { tags: ["security", "redos", "CWE-1333"], "security-severity": "5.3", precision: "high" },
  },
];

function message(report: Report): string {
  const lines: string[] = [];
  const shape = report.verdict === "exponential" ? "Exponential backtracking" : `Polynomial backtracking, O(n^${report.degree})`;
  lines.push(`${shape} in /${report.source}/${report.flags}.`);

  if (report.attack) {
    const repetitions = report.dynamic?.worst?.repetitions ?? 25;
    lines.push(`Attack: ${describeAttack(report.attack, repetitions)}.`);
  }
  const dynamic = report.dynamic;
  if (dynamic) {
    const pumpLength = report.attack?.pump.length ?? 1;
    const oneSecond = repetitionsToExceed(dynamic, 1000, pumpLength);
    if (dynamic.timedOut && dynamic.worst) {
      lines.push(`Measured: the engine had to be killed on a ${dynamic.worst.length}-character input.`);
    } else if (oneSecond) {
      lines.push(`Measured: ~${oneSecond.characters} characters of input cost ~1s of CPU.`);
    }
  } else {
    lines.push("Not measured (--no-measure).");
  }
  return lines.join(" ");
}

export function renderSarif(findings: { location: FoundRegex; report: Report }[], version: string): string {
  const cwd = process.cwd();
  const results = findings.map(({ location, report }) => {
    const ruleId = report.verdict === "exponential" ? "redoscope/exponential" : "redoscope/polynomial";
    const relative = path.relative(cwd, path.resolve(location.file)).split(path.sep).join("/");
    return {
      ruleId,
      ruleIndex: RULES.findIndex((r) => r.id === ruleId),
      level: report.verdict === "exponential" ? "error" : "warning",
      message: { text: message(report) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: relative, uriBaseId: "%SRCROOT%" },
            region: {
              startLine: location.line,
              startColumn: location.column,
              endColumn: location.column + location.raw.length,
            },
          },
        },
      ],
      // Stable across unrelated edits to the file, so an alert is not
      // reopened every time a line is inserted above it.
      partialFingerprints: { "redoscopePattern/v1": `${report.flags}:${report.source}` },
    };
  });

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "redoscope", version, informationUri: HELP_URI, rules: RULES } },
          results,
        },
      ],
    },
    null,
    2,
  );
}
