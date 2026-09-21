/**
 * The playground. Static analysis runs on every keystroke; the attack runs in
 * terminable workers once typing pauses, and the chart fills in as each rung
 * of the ladder comes back.
 */

import { prepare, withMeasurement, type Report } from "../src/core.ts";
import { describeAttack, type Attack } from "../src/witness.ts";
import { repetitionsToExceed, type TimingSample } from "../src/growth.ts";
import { verifyInBrowser } from "./measure.ts";
import { suggestFixesInBrowser } from "./suggest.ts";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const patternInput = $<HTMLInputElement>("pattern");
const flagsInput = $<HTMLInputElement>("flags");
const rendered = $("rendered");
const verdictChip = $("verdict");
const verdictNote = $("verdict-note");
const attackOut = $("attack");
const evidenceOut = $("evidence");
const costOut = $("cost");
const copyButton = $<HTMLButtonElement>("copy-attack");
const chart = $("chart") as unknown as SVGSVGElement;
const status = $("status");
const fixPanel = $("fix-panel");
const fixList = $("fix-list");

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function formatMs(ms: number): string {
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)} s`;
  if (ms >= 10) return `${ms.toFixed(0)} ms`;
  return `${ms.toFixed(2)} ms`;
}

/* ---------------------------------------------------------------- chart */

const W = 640;
const H = 280;
const PAD = { left: 56, right: 16, top: 18, bottom: 40 };
// The x domain follows the data: an exponential attack lives between 10 and
// 60 characters, a quadratic one between 1k and 100k.
let X_MIN = 5;
let X_MAX = 500;
const Y_MIN = 0.01;
const Y_MAX = 5_000;
const sx = (chars: number) =>
  PAD.left + ((Math.log10(Math.max(chars, X_MIN)) - Math.log10(X_MIN)) / (Math.log10(X_MAX) - Math.log10(X_MIN))) * (W - PAD.left - PAD.right);
const sy = (ms: number) =>
  H - PAD.bottom - ((Math.log10(Math.min(Math.max(ms, Y_MIN), Y_MAX)) - Math.log10(Y_MIN)) / (Math.log10(Y_MAX) - Math.log10(Y_MIN))) * (H - PAD.top - PAD.bottom);

const NS = "http://www.w3.org/2000/svg";
function el(name: string, attrs: Record<string, string | number>, text?: string): SVGElement {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  if (text !== undefined) node.textContent = text;
  return node;
}

let seriesLayer: SVGGElement;
function drawAxes(): void {
  chart.replaceChildren();
  chart.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const grid = el("g", { class: "grid" });
  for (const ms of [0.01, 0.1, 1, 10, 100, 1000]) {
    grid.append(el("line", { x1: PAD.left, x2: W - PAD.right, y1: sy(ms), y2: sy(ms) }));
    grid.append(el("text", { x: PAD.left - 8, y: sy(ms) + 4, "text-anchor": "end", class: "tick" }, ms >= 1000 ? "1 s" : `${ms} ms`));
  }
  for (const chars of [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10_000, 20_000, 50_000, 100_000, 200_000].filter((c) => c >= X_MIN && c <= X_MAX)) {
    grid.append(el("line", { x1: sx(chars), x2: sx(chars), y1: PAD.top, y2: H - PAD.bottom, class: "v" }));
    grid.append(el("text", { x: sx(chars), y: H - PAD.bottom + 16, "text-anchor": "middle", class: "tick" }, chars >= 1000 ? `${chars / 1000}k` : String(chars)));
  }
  grid.append(el("text", { x: (W + PAD.left) / 2, y: H - 6, "text-anchor": "middle", class: "axis" }, "attack length, characters (log)"));
  const budget = el("g", { class: "budget" });
  budget.append(el("line", { x1: PAD.left, x2: W - PAD.right, y1: sy(1000), y2: sy(1000) }));
  budget.append(el("text", { x: W - PAD.right - 4, y: sy(1000) - 6, "text-anchor": "end" }, "1 second of CPU per request"));
  seriesLayer = el("g", {}) as SVGGElement;
  chart.append(grid, budget, seriesLayer);
}

const series = new Map<string, TimingSample[]>();
function plot(sample: TimingSample, attack: Attack): void {
  const key = `${attack.prefix}|${attack.pump}|${attack.suffix}`;
  if (!series.has(key)) series.set(key, []);
  const points = series.get(key)!;
  points.push(sample);
  // The polynomial ladder restarts at larger sizes; keep the curve monotone.
  points.sort((a, b) => a.length - b.length);

  const lengths = [...series.values()].flat().map((p) => p.length);
  X_MIN = Math.max(1, Math.min(...lengths) / 1.5);
  X_MAX = Math.max(X_MIN * 20, Math.max(...lengths) * 1.5);
  drawAxes();

  let index = 0;
  for (const pts of series.values()) {
    const cls = `trace-${Math.min(index++, 2)}`;
    seriesLayer.append(el("path", { class: `trace ${cls}`, d: pts.map((p, i) => `${i ? "L" : "M"}${sx(p.length).toFixed(1)},${sy(p.ms).toFixed(1)}`).join("") }));
    for (const p of pts) {
      if (!p.timedOut) {
        seriesLayer.append(el("circle", { cx: sx(p.length), cy: sy(p.ms), r: 2.6, class: `dot ${cls}` }));
        continue;
      }
      const x = sx(p.length);
      const y = sy(p.ms);
      const g = el("g", { class: "killed" });
      g.append(el("path", { d: `M${x - 6},${y - 6}L${x + 6},${y + 6}M${x + 6},${y - 6}L${x - 6},${y + 6}` }));
      g.append(el("text", { x: x - 10, y: y + 4, "text-anchor": "end" }, `killed at ${p.length} chars`));
      seriesLayer.append(g);
    }
  }
}

/* ----------------------------------------------------------------- view */

function setVerdict(kind: string, label: string, note: string): void {
  verdictChip.dataset.kind = kind;
  verdictChip.textContent = label;
  verdictNote.textContent = note;
}

function renderPattern(report: Report): void {
  const { source, hotspot } = report;
  const body = hotspot
    ? `${escapeHtml(source.slice(0, hotspot.start))}<mark>${escapeHtml(source.slice(hotspot.start, hotspot.end))}</mark>${escapeHtml(source.slice(hotspot.end))}`
    : escapeHtml(source);
  rendered.innerHTML = `<span class="slash">/</span>${body}<span class="slash">/</span>${escapeHtml(report.flags)}`;
}

let currentAttack: { attack: Attack; repetitions: number } | null = null;

function renderStatic(report: Report): void {
  renderPattern(report);
  currentAttack = null;
  copyButton.disabled = true;
  if (report.error) {
    setVerdict("error", "Cannot parse", report.error);
    attackOut.textContent = "—";
    evidenceOut.textContent = "—";
    costOut.textContent = "—";
    return;
  }
  if (report.verdict === "safe") {
    setVerdict("safe", "Linear", "No ambiguous loop is reachable. Matching time grows linearly with input, so there is nothing to attack.");
    attackOut.textContent = "none exists";
    evidenceOut.textContent = "decided statically, from the automaton";
    costOut.textContent = "—";
    return;
  }
  const shape = report.verdict === "exponential" ? "exponential" : `O(n^${report.degree})`;
  setVerdict("measuring", `Ambiguous, ${shape}`, "The automaton admits an attack. Running it against this browser's regex engine…");
  attackOut.textContent = report.attack ? describeAttack(report.attack, 20) : "—";
  evidenceOut.textContent = "measuring…";
  costOut.textContent = "measuring…";
}

function renderMeasured(report: Report): void {
  const d = report.dynamic!;
  const attack = report.attack!;
  const pumpLength = attack.pump.length;
  const shown = d.worst?.repetitions ?? 20;
  attackOut.textContent = describeAttack(attack, shown);
  currentAttack = { attack, repetitions: shown };
  copyButton.disabled = false;

  if (d.engineError) {
    setVerdict("error", "Engine rejected it", d.engineError);
    return;
  }
  if (!report.exploitable) {
    setVerdict(
      "dismissed",
      "Ambiguous, not exploitable",
      `The automaton is ${report.verdict === "exponential" ? "exponentially" : "polynomially"} ambiguous, but the attack measured ${d.growth}: the engine never has to explore the ambiguity. Not a bug.`,
    );
    evidenceOut.textContent = `measured ${d.growth}`;
    costOut.textContent = "—";
    return;
  }

  const rate =
    d.base !== null
      ? `${d.base.toFixed(2)}ⁿ${pumpLength > 1 ? ` per ${pumpLength}-char pump` : ""}`
      : d.exponent !== null
        ? `O(n^${d.exponent.toFixed(2)})`
        : d.growth;
  const fit = d.fitQuality !== null ? ` · R² ${d.fitQuality.toFixed(3)}` : "";
  evidenceOut.textContent = `measured ${rate}${fit}${d.timedOut ? ` · engine killed at ${d.worst?.length} chars` : ""}`;

  const oneSecond = repetitionsToExceed(d, 1000, pumpLength);
  costOut.textContent = oneSecond
    ? `${oneSecond.characters.toLocaleString()} characters of input ≈ 1 s of CPU`
    : d.timedOut && d.worst
      ? `${d.worst.length} characters did not finish in ${formatMs(d.worst.ms)}`
      : "—";

  setVerdict(
    report.verdict === "exponential" ? "exponential" : "polynomial",
    report.verdict === "exponential" ? "Exponential, confirmed" : `Polynomial O(n^${report.degree}), confirmed`,
    "The generated attack was run against this browser's regex engine, and it was slow. Every number below was measured, not estimated.",
  );
}

/* ------------------------------------------------------------ lifecycle */

let controller: AbortController | null = null;
let debounce: ReturnType<typeof setTimeout> | undefined;

async function run(): Promise<void> {
  controller?.abort();
  controller = new AbortController();
  const signal = controller.signal;

  const source = patternInput.value;
  const flags = flagsInput.value.replace(/[^dgimsuvy]/g, "");
  syncUrl(source, flags);
  series.clear();
  X_MIN = 5;
  X_MAX = 500;
  drawAxes();

  if (source === "") {
    rendered.textContent = "";
    setVerdict("idle", "Waiting for a pattern", "Type a regular expression, or pick one of the traps below.");
    return;
  }

  let prepared;
  try {
    prepared = prepare(source, flags);
  } catch (error) {
    setVerdict("error", "Analysis failed", String(error));
    return;
  }
  renderStatic(prepared.report);
  if (prepared.attacks.length === 0) {
    status.textContent = "";
    return;
  }

  status.textContent = "running attack in a worker";
  const dynamic = await verifyInBrowser(source, flags, prepared.attacks, plot, signal);
  if (signal.aborted) return;
  status.textContent = "";
  const measured = withMeasurement(prepared.report, dynamic);
  renderMeasured(measured);

  if (measured.exploitable) {
    await showSuggestions(source, flags, measured, signal);
  } else {
    fixPanel.hidden = true;
    fixList.innerHTML = "";
  }
}

async function showSuggestions(source: string, flags: string, report: Report, signal: AbortSignal): Promise<void> {
  fixPanel.hidden = false;
  fixList.innerHTML = `<p class="fix-status">Searching for a rewrite that runs fast and matches the same strings…</p>`;
  let suggestions;
  try {
    suggestions = await suggestFixesInBrowser(source, flags, report);
  } catch {
    fixPanel.hidden = true;
    return;
  }
  if (signal.aborted) return;

  if (suggestions.length === 0) {
    fixList.innerHTML = `<p class="fix-status">No automatic rewrite verified. Bound the input (see the cost above) or restructure the pattern by hand.</p>`;
    return;
  }
  fixList.innerHTML = "";
  for (const s of suggestions) {
    const kind = s.kind === "bounded" ? "mitigation" : "equivalent";
    const proof =
      s.kind === "bounded"
        ? `caps length at ${s.bound?.toLocaleString()}; rejects longer input — ${s.samplesChecked} samples otherwise agree`
        : `${s.samplesChecked} generated strings, accept/reject unchanged`;
    const card = document.createElement("div");
    card.className = "fix";
    card.innerHTML = `<div class="fix-head"><code></code><span class="fix-tag ${s.kind === "bounded" ? "warn" : "ok"}">${kind}</span></div><p class="fix-why"></p><p class="fix-proof"><span>verified</span> </p>`;
    card.querySelector("code")!.textContent = `/${s.rewrite}/${s.flags}`;
    card.querySelector(".fix-why")!.textContent = s.summary;
    card.querySelector(".fix-proof")!.append(document.createTextNode(proof));
    fixList.append(card);
  }
}

function schedule(): void {
  clearTimeout(debounce);
  debounce = setTimeout(run, 350);
}

function syncUrl(source: string, flags: string): void {
  try {
    const params = new URLSearchParams({ re: source });
    if (flags) params.set("flags", flags);
    history.replaceState(null, "", `#${params}`);
  } catch {
    /* sandboxed frames may refuse history access */
  }
}

patternInput.addEventListener("input", schedule);
flagsInput.addEventListener("input", schedule);

for (const button of document.querySelectorAll<HTMLButtonElement>("[data-pattern]")) {
  button.addEventListener("click", () => {
    patternInput.value = button.dataset.pattern!;
    flagsInput.value = button.dataset.flags ?? "";
    for (const b of document.querySelectorAll("[data-pattern]")) b.removeAttribute("aria-pressed");
    button.setAttribute("aria-pressed", "true");
    document.getElementById("instrument")?.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    run();
  });
}

copyButton.addEventListener("click", async () => {
  if (!currentAttack) return;
  const { attack, repetitions } = currentAttack;
  const text = `new RegExp(${JSON.stringify(patternInput.value)}, ${JSON.stringify(flagsInput.value)}).test(${JSON.stringify(attack.prefix)} + ${JSON.stringify(attack.pump)}.repeat(${repetitions}) + ${JSON.stringify(attack.suffix)})`;
  try {
    await navigator.clipboard.writeText(text);
    copyButton.textContent = "Copied";
  } catch {
    copyButton.textContent = "Copy blocked";
  }
  setTimeout(() => (copyButton.textContent = "Copy as JS"), 1600);
});

(function boot() {
  try {
    const params = new URLSearchParams(location.hash.slice(1));
    const re = params.get("re");
    if (re !== null) {
      patternInput.value = re;
      flagsInput.value = params.get("flags") ?? "";
    }
  } catch {
    /* fall back to the default example */
  }
  drawAxes();
  run();
})();
