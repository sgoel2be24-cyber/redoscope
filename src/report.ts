/**
 * Self-contained HTML reports.
 *
 * No external assets, no scripts, no fonts — a report is something you attach
 * to a ticket or open from a CI artifact directory, and it has to render on a
 * machine with no network. Colours are defined for light and dark, with the
 * light palette on bare `:root` so a viewer that expresses no preference still
 * gets a complete theme.
 */

import type { Report } from "./index.ts";
import type { FoundRegex } from "./scan.ts";
import { describeAttack } from "./witness.ts";
import { repetitionsToExceed } from "./dynamic.ts";

export interface ReportEntry {
  location: FoundRegex;
  report: Report;
}

export interface ReportSummary {
  files: number;
  regexes: number;
  exponential: number;
  polynomial: number;
  unexploitable: number;
  safe: number;
  errors: number;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Render the pattern with the culprit sub-expression wrapped for highlighting. */
function markedPattern(report: Report): string {
  const { source, hotspot } = report;
  if (!hotspot) return escapeHtml(source);
  return (
    escapeHtml(source.slice(0, hotspot.start)) +
    `<mark>${escapeHtml(source.slice(hotspot.start, hotspot.end))}</mark>` +
    escapeHtml(source.slice(hotspot.end))
  );
}

function formatMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms >= 10) return `${ms.toFixed(0)}ms`;
  return `${ms.toFixed(1)}ms`;
}

function growthCell(report: Report): string {
  const dynamic = report.dynamic;
  if (!dynamic) return '<span class="muted">not measured</span>';
  if (dynamic.growth === "constant" || dynamic.growth === "linear") {
    return `<span class="muted">measured ${dynamic.growth}</span>`;
  }
  const pumpLength = report.attack?.pump.length ?? 1;
  if (dynamic.base !== null) {
    const shape =
      pumpLength === 1
        ? `${dynamic.base.toFixed(2)}<sup>n</sup>`
        : `${dynamic.base.toFixed(2)}<sup>n</sup> <span class="muted">per ${pumpLength}-char pump</span>`;
    return shape;
  }
  if (dynamic.exponent !== null) return `O(n<sup>${dynamic.exponent.toFixed(2)}</sup>)`;
  return escapeHtml(dynamic.growth);
}

function severityClass(report: Report): string {
  if (report.error) return "err";
  if (report.verdict === "safe") return "ok";
  if (report.exploitable === false) return "muted-badge";
  return report.verdict === "exponential" ? "bad" : "warn";
}

function severityText(report: Report): string {
  if (report.error) return "unparseable";
  if (report.verdict === "safe") return "linear";
  if (report.exploitable === false) return "not exploitable";
  if (report.verdict === "exponential") return "exponential";
  return `polynomial O(n^${report.degree})`;
}

function entryRow(entry: ReportEntry): string {
  const { location, report } = entry;
  const where = `${escapeHtml(location.file)}:${location.line}:${location.column}`;
  const attack = report.attack;
  const shown = report.dynamic?.worst?.repetitions ?? 25;

  const samples = (report.dynamic?.samples ?? [])
    .filter((s) => s.ms >= 0.5 || s.timedOut)
    .slice(-3)
    .map(
      (s) =>
        `<li><span class="n">n=${s.repetitions}</span> <span class="muted">${s.length} chars</span> → ${
          s.timedOut ? `<strong class="bad-text">killed after ${formatMs(s.ms)}</strong>` : formatMs(s.ms)
        }</li>`,
    )
    .join("");

  const budget = report.dynamic
    ? repetitionsToExceed(report.dynamic, 1000, attack?.pump.length ?? 1)
    : null;

  return `
<article class="finding">
  <header>
    <span class="badge ${severityClass(report)}">${severityText(report)}</span>
    <code class="where">${where}</code>
  </header>
  <pre class="pattern"><code>/${markedPattern(report)}/${escapeHtml(report.flags)}</code></pre>
  <dl>
    ${
      attack && report.exploitable !== false
        ? `<dt>Attack</dt><dd><code>${escapeHtml(describeAttack(attack, shown))}</code></dd>`
        : ""
    }
    <dt>Growth</dt><dd>${growthCell(report)}</dd>
    ${samples ? `<dt>Measured</dt><dd><ul class="samples">${samples}</ul></dd>` : ""}
    ${
      budget
        ? `<dt>Budget</dt><dd>${budget.characters.toLocaleString()} characters of input costs ~1s of CPU</dd>`
        : ""
    }
    ${
      report.confidence === "reduced"
        ? `<dt>Caveat</dt><dd class="muted">Reduced confidence: ${
            report.approximations.backreference ? "backreferences" : "lookaround"
          } are modelled as empty, which can over-report.</dd>`
        : ""
    }
  </dl>
</article>`;
}

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #fbfbfa;
  --panel: #ffffff;
  --ink: #1a1a19;
  --muted: #6b6b68;
  --line: #e3e3e0;
  --bad: #b3261e;
  --warn: #8a5a00;
  --ok: #1f6b3a;
  --mark: #ffe89e;
  --mark-ink: #3d2d00;
  --code: #f3f3f1;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #161615;
    --panel: #1e1e1d;
    --ink: #ececea;
    --muted: #9a9a96;
    --line: #32322f;
    --bad: #ff8a80;
    --warn: #ffc46b;
    --ok: #7fd0a0;
    --mark: #6b4e00;
    --mark-ink: #ffeab0;
    --code: #262625;
  }
}
:root[data-theme="dark"] {
  --bg: #161615;
  --panel: #1e1e1d;
  --ink: #ececea;
  --muted: #9a9a96;
  --line: #32322f;
  --bad: #ff8a80;
  --warn: #ffc46b;
  --ok: #7fd0a0;
  --mark: #6b4e00;
  --mark-ink: #ffeab0;
  --code: #262625;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2.5rem 1.25rem 4rem;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", system-ui, sans-serif;
}
.wrap { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
.sub { color: var(--muted); margin: 0 0 2rem; }
code, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(8.5rem, 1fr)); gap: .75rem; margin-bottom: 2.5rem; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: .5rem; padding: .85rem 1rem; }
.tile .v { font-size: 1.6rem; font-weight: 600; line-height: 1.1; }
.tile .k { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.tile.bad .v { color: var(--bad); }
.tile.warn .v { color: var(--warn); }
.tile.ok .v { color: var(--ok); }
.finding { background: var(--panel); border: 1px solid var(--line); border-radius: .5rem; padding: 1rem 1.15rem; margin-bottom: 1rem; }
.finding header { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; margin-bottom: .7rem; }
.badge { font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; padding: .18rem .5rem; border-radius: .3rem; border: 1px solid currentColor; }
.badge.bad { color: var(--bad); }
.badge.warn { color: var(--warn); }
.badge.ok { color: var(--ok); }
.badge.muted-badge, .badge.err { color: var(--muted); }
.where { color: var(--muted); font-size: .82rem; }
.pattern { background: var(--code); border-radius: .35rem; padding: .6rem .75rem; overflow-x: auto; margin: 0 0 .8rem; font-size: .85rem; }
mark { background: var(--mark); color: var(--mark-ink); border-radius: 2px; padding: 0 1px; }
dl { display: grid; grid-template-columns: 6.5rem 1fr; gap: .35rem .9rem; margin: 0; font-size: .88rem; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
.samples { list-style: none; margin: 0; padding: 0; }
.samples .n { display: inline-block; min-width: 4.5rem; }
.muted, .muted-text { color: var(--muted); }
.bad-text { color: var(--bad); }
footer { color: var(--muted); font-size: .82rem; margin-top: 2.5rem; border-top: 1px solid var(--line); padding-top: 1rem; }
.empty { background: var(--panel); border: 1px solid var(--line); border-radius: .5rem; padding: 2rem; text-align: center; color: var(--muted); }
`;

export function renderHtmlReport(
  entries: ReportEntry[],
  summary: ReportSummary,
  target: string,
): string {
  const tiles = [
    { k: "exponential", v: summary.exponential, cls: summary.exponential > 0 ? "bad" : "" },
    { k: "polynomial", v: summary.polynomial, cls: summary.polynomial > 0 ? "warn" : "" },
    { k: "not exploitable", v: summary.unexploitable, cls: "" },
    { k: "linear", v: summary.safe, cls: "ok" },
  ]
    .map(
      (t) =>
        `<div class="tile ${t.cls}"><div class="v">${t.v}</div><div class="k">${t.k}</div></div>`,
    )
    .join("");

  const body =
    entries.length > 0
      ? entries.map(entryRow).join("")
      : `<div class="empty">No findings. ${summary.regexes} regexes across ${summary.files} files are linear.</div>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>redoscope — ${escapeHtml(target)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>redoscope report</h1>
  <p class="sub">${escapeHtml(target)} · ${summary.regexes} regexes in ${summary.files} files · generated ${new Date().toISOString().slice(0, 16).replace("T", " ")}</p>
  <div class="tiles">${tiles}</div>
  ${body}
  <footer>
    Every finding above was confirmed by running the generated attack string against the
    engine and measuring it. Findings describe the pattern, not the program: a quadratic
    regex behind a length check may be perfectly safe.
  </footer>
</div>
</body>
</html>`;
}
