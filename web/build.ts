/**
 * Builds the playground into one self-contained HTML file.
 *
 *   web/dist/index.html      full document, for GitHub Pages or opening locally
 *   web/dist/fragment.html   body-only, for hosts that supply their own <head>
 *
 * The CVE section is rendered here, from bench/cve/results, so the numbers are
 * in the HTML itself rather than fetched or computed at view time.
 *
 * Usage: node web/build.ts
 */

import fs from "node:fs";
import path from "node:path";
import { build } from "esbuild";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT = path.join(ROOT, "web", "dist");

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const pct = (x: number | null) => (x === null ? "—" : `${(x * 100).toFixed(0)}%`);
const ms = (x: number) => (x >= 1000 ? `${(x / 1000).toFixed(1)} s` : x >= 10 ? `${x.toFixed(0)} ms` : `${x.toFixed(1)} ms`);

function cveSection(): string {
  const dir = path.join(ROOT, "bench", "cve", "results");
  const summaryFile = path.join(dir, "summary.json");
  if (!fs.existsSync(summaryFile)) return "";
  const summary = JSON.parse(fs.readFileSync(summaryFile, "utf8"));
  const advisories = JSON.parse(fs.readFileSync(path.join(dir, "advisories.json"), "utf8"));
  const c = summary.corpus;
  const tools = summary.tools;
  const us = tools.redoscope;

  const rob = (name: string, key: string, note: string) => {
    const t = tools[key];
    const recall = t.recallRobust ?? t.recall;
    return `<tr${key.startsWith("redoscope") ? ' class="us"' : ""}><td>${name}<br><small class="note">${note}</small></td><td>${t.advisoriesDetectedRobust ?? t.advisoriesDetected} / ${c.confirmedRobust}</td><td>${pct(t.precision)}</td><td>${pct(recall)}</td><td>${t.falsePositives}</td></tr>`;
  };

  const TOOL_LABEL: Record<string, string> = { redoscope: "redoscope", recheck: "recheck", "safe-regex": "safe-regex" };
  const examples = advisories
    .slice()
    .filter((a: any) => a.regexes.some((r: any) => r.judge.killed || (r.judge.ms ?? 0) >= 1500))
    .sort((a: any, b: any) => (b.detectedBy.redoscope ? 1 : 0) - (a.detectedBy.redoscope ? 1 : 0) || String(b.advisory).localeCompare(String(a.advisory)))
    .slice(0, 8)
    .map((a: any) => {
      const r = a.regexes.find((x: any) => x.judge.killed || (x.judge.ms ?? 0) >= 1500) ?? a.regexes[0];
      const source = r.source.length > 140 ? `${r.source.slice(0, 140)}…` : r.source;
      const hits = ["redoscope", "recheck", "safe-regex"]
        .map((tool) => `<span class="hit ${a.detectedBy[tool] ? "yes" : "no"}">${TOOL_LABEL[tool]}</span>`)
        .join("");
      const judge = r.judge.killed ? `engine killed at ${r.judge.length?.toLocaleString("en-US") ?? "a short input"} chars` : `${ms(r.judge.ms)} at ${r.judge.length?.toLocaleString("en-US")} chars`;
      return `<div class="cve"><div class="id"><a href="https://github.com/advisories/${escapeHtml(a.advisory)}">${escapeHtml(a.cve ?? a.advisory)}</a><small>${escapeHtml(a.package)} ${escapeHtml(a.vulnerable)} → ${escapeHtml(a.patched)}</small></div><div><code>/${escapeHtml(source)}/${escapeHtml(r.flags)}</code><div class="meta">judge: ${judge}</div><div class="hits">${hits}</div></div></div>`;
    })
    .join("");

  return `<section id="cves">
    <h2>Tested on real CVEs</h2>
    <p class="sub">Every reviewed npm advisory in the GitHub Advisory Database tagged CWE-1333 (inefficient regular expression complexity). For each, the last vulnerable release is diffed against the first patched one; the regex literals the fix removed are the ground truth. Each tool sees one regex at a time with no hint, the way it would in CI. The table counts only <em>robustly</em> confirmed advisories — where the engine was killed or a run cleared 1.5 s — so the numbers do not move with machine load.</p>
    <div class="big">
      <div><strong>${us.advisoriesDetectedRobust} of ${c.confirmedRobust}</strong><span>robustly-confirmed advisories rediscovered with no hint, each with a working attack string</span></div>
      <div><strong>${pct(tools["redoscope-capped"].precision)}</strong><span>precision with a 50 KB input limit — ${tools["redoscope-capped"].falsePositives} false alarms, against recheck's ${tools.recheck.falsePositives}</span></div>
      <div><strong>${c.advisories}</strong><span>advisories examined, across ${c.releasePairs} vulnerable → patched release pairs</span></div>
    </div>
    <div class="scoreboard">
      <table>
        <thead><tr><th>Tool</th><th>Advisories found</th><th>Precision</th><th>Recall</th><th>False alarms</th></tr></thead>
        <tbody>
          ${rob("redoscope", "redoscope", "automaton + measurement")}
          ${rob("redoscope --max-input 50000", "redoscope-capped", "same run, alert only if 1 s fits in 50 KB")}
          ${rob("recheck 4.5", "recheck", "automaton + fuzzing")}
          ${rob("safe-regex 2.1", "safe-regex", "star-height heuristic")}
        </tbody>
      </table>
    </div>
    <p class="fine">Judge: a separate harness that shares no code with any tool and replays every attack string any tool produced. A regex is <em>confirmed</em> when an input of at most ${summary.judge.maxChars.toLocaleString("en-US")} characters makes one <code>RegExp.test</code> take ${summary.judge.slowMs / 1000} s or more with super-linear growth, or the engine has to be killed; <em>robustly</em> confirmed adds a 1.5 s floor so a borderline quadratic cannot flip between runs. redoscope and recheck are neck and neck on recall (${us.advisoriesDetectedRobust} and ${tools.recheck.advisoriesDetectedRobust} of ${c.confirmedRobust}); redoscope's edge is precision — measurement plus an input cap cut its false alarms to ${tools["redoscope-capped"].falsePositives}. A further ${c.confirmedBorderline} advisories are quadratics that pass 1 s only near the 50 KB limit; whether they count is exactly the question <code>--max-input</code> answers. safe-regex produces no attack strings, so it cannot confirm any. Advisories whose fix changed no regex literal (${c.noRegexLiteralChanged}) or rewrote too many (${c.diffTooLargeToAttribute}) are excluded. Node ${escapeHtml(summary.node)}, ${escapeHtml(summary.generated.slice(0, 10))}; reproduce with <code>node bench/cve/fetch.ts &amp;&amp; node bench/cve/run.ts</code>.</p>
    <div class="cves">${examples}</div>
  </section>`;
}

async function main(): Promise<void> {
  const bundle = await build({
    entryPoints: [path.join(ROOT, "web", "app.ts")],
    bundle: true,
    format: "iife",
    target: "es2022",
    minify: true,
    write: false,
    legalComments: "none",
  });
  // keepNames is off, so `probe.toString()` still yields a runnable function.
  const js = bundle.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");

  const template = fs.readFileSync(path.join(ROOT, "web", "template.html"), "utf8");
  const fragment = template.replace("<!--CVE-RESULTS-->", () => cveSection()).replace("/*APP*/", () => js);

  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, "fragment.html"), fragment);
  const [head, ...rest] = fragment.split("</style>");
  fs.writeFileSync(
    path.join(OUT, "index.html"),
    `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n${head}</style>\n</head>\n<body>\n${rest.join("</style>")}\n</body>\n</html>\n`,
  );
  console.log(`wrote web/dist/index.html (${(fs.statSync(path.join(OUT, "index.html")).size / 1024).toFixed(0)} KB)`);
}

await main();
