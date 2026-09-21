# redoscope

Finds regular expressions that can be made to backtrack catastrophically,
**proves it** by building the attack string and timing the real engine, and
**suggests a rewrite** — checked to run fast and still match the same strings.

```
$ redoscope '^(a+)+$'

exponential

    /^(a+)+$/
      ~~~~~

  attack    "aa" + "aa" × 13 + "!"
  evidence  measured 3.93^n per 2-char pump (R² 1.000)
            n=11, 25 chars → 67ms
            n=12, 27 chars → 261ms
            n=13, 29 chars → killed after 2.0s
            29 characters of input costs ~1s of CPU
```

```
$ redoscope '^(a+)+$' --suggest

  suggested fixes  (each checked: run fast, and agree with the original)

    /^a+$/
    equivalent  Collapse the redundant nested quantifier; same language, no backtracking.
      verified  211 generated strings, accept/reject unchanged
```

**[Try it in the browser →](https://sgoel2be24-cyber.github.io/redoscope/)** Paste a regex, watch the attack run, and get a verified fix.

Zero runtime dependencies. No build step. No network. Node ≥ 22.18.
(`typescript` and `@types/node` are devDependencies, used only to typecheck.)

---

## Why another one of these

ReDoS tooling tends to sit at one of two extremes: fast heuristics that guess
from the shape of the pattern, or heavyweight solvers you have to adopt. Both
hand you a verdict. Neither hands you the input.

That gap matters more than it sounds, because **a verdict without a witness is
frequently wrong in the direction nobody checks.** Two examples from this
project's own test corpus:

- `^(\s|\w)+$` looks like the textbook nested-quantifier bug. It is provably
  safe: `\s` and `\w` are disjoint, so no string has two parses.
- `(a+)+` is genuinely, exponentially ambiguous — and completely harmless,
  because it is unanchored and always matches. The engine never has to explore
  the ambiguity. Flag it and you have burned a developer's afternoon.

Meanwhile `^([ab]|[bc])*$` really is exponential, but only on input that keeps
hitting `b`, the one letter both branches accept. Time it with the obvious
`"aaaa…"` and you will measure nothing and conclude it is fine.

redoscope answers with a string you can paste into a terminal, and the numbers
it produced when run.

## Tested on real CVEs

`bench/cve` takes every reviewed npm advisory in the GitHub Advisory Database
tagged CWE-1333 (152 advisories, 225 vulnerable → patched release pairs),
diffs the last vulnerable release against the first patched one, and treats
the regex literals the fix removed as ground truth. Each tool sees one regex at
a time, with no hint. A separate judge that shares no code with any tool
replays every attack string any tool produced. It confirms a regex when an
input of at most 50,000 characters makes one `RegExp.test` take a second or
more, with super-linear growth.

On the *robust* core — 56 advisories confirmed by a kill or a run clearing 1.5 s,
so machine load cannot move them — across 74 vulnerable regexes:

| | advisories | precision | recall | false alarms |
|---|---|---|---|---|
| **redoscope 0.3** | 55 / 56 | 85% | 97% | 26 |
| **redoscope 0.3 `--max-input 50000`** | 55 / 56 | **97%** | 89% | **5** |
| recheck 4.5 *(automaton + fuzzing)* | **56 / 56** | 84% | 96% | 29 |
| safe-regex 2.1 *(star height)* | 37 / 56 | 52% | 68% | 64 |

What the numbers say:

- **redoscope and recheck are now neck and neck on recall** (55 and 56 of 56).
  Modelling the engine's retry loop and validating each generated suffix took
  robust regex coverage from 43/47 in 0.1 to 72/74 in 0.3, closing almost the
  entire gap to recheck.
- **redoscope's edge is precision.** Because every alert is a measured attack,
  and `--max-input` asks whether that attack fits under your input limit,
  capped redoscope raises 5 false alarms to recheck's 29.
- **safe-regex misses a third** of the robust set and cries wolf four times as
  often as capped redoscope.
- redoscope still misses one advisory recheck catches: semver-regex's
  lookbehind, which its witness does not drive to a failing state.
- A further 60 advisories are quadratics that pass 1 s only near the 50 KB
  limit; whether they count is exactly what `--max-input` decides, so they are
  reported separately rather than folded into the headline.

**Found in the process:** pointing 0.3 at the current release of every package
ever patched for one of these bugs surfaced one whose fix is incomplete — an
~80-character string still drives its public API into exponential backtracking.
It is being reported privately to the maintainer before any public mention.

```bash
cd bench/cve && npm install && cd ../..
node bench/cve/fetch.ts && node bench/cve/run.ts    # ~1 hour, serial on purpose
```

## Does it actually help on ordinary code

`bench/compare.ts` runs three methods over whatever tree you point it at. This
table was measured with version 0.1, before retries were modelled. On
**627 distinct regexes** scraped from a `node_modules` directory:

|  | flagged | false positives | missed |
|---|---|---|---|
| star height ≥ 2 *(the classic heuristic)* | 10 | 10 | 14 |
| redoscope, static only | 23 | 9 | 0 |
| redoscope, measured | 14 | 0 | 0 |

The heuristic scored **zero true positives**: everything it flagged was
provably unambiguous, and it missed every confirmed-slow pattern. That is not
bad luck. Real-world ReDoS rarely looks like `(a+)+`. It looks like the anchored
duration parser in the `ms` package, built around `(?:\d+)?\.?\d+`, or a trim
like `\s*#?\s*$`. Both have star height 1 and pass the check, and both measure
quadratic.

Measurement then removed nine of redoscope's own false positives, taking 23
flags down to 14 real ones.

Read the table honestly: the "measured" row is the reference, so it scores zero
by construction. The two claims that stand on their own are that the 14 misses
are *measured* facts, and that the 10 false positives are *decidability*
results — those patterns have no ambiguous cycle at all, so no input can make
them backtrack.

```bash
node bench/compare.ts node_modules/
```

## Install

```bash
npx redoscope '^(a+)+$'            # from npm
node src/cli.ts '^(a+)+$'           # from a clone: no install, no build
```

From a clone, Node 22.18+ runs the TypeScript source directly. The npm package
ships compiled JavaScript (`npm run build`), because Node will not strip types
inside `node_modules`.

## Use

```bash
redoscope '<pattern>' [flags]      # inspect one regex
redoscope scan src/                # inspect every regex in a tree
```

| Option | |
|---|---|
| `--json` | machine-readable output |
| `--suggest` | propose a verified, faster rewrite for each finding |
| `--html <file>` | self-contained HTML report (scan only) |
| `--sarif <file>` | SARIF 2.1.0 for GitHub code scanning (scan only) |
| `--no-measure` | static analysis only; never runs the engine |
| `--timeout <ms>` | budget per attack candidate (default 2000) |
| `--fail-on <level>` | `exponential` (default), `polynomial`, `any`, `never` |
| `--quiet` | findings only |

Exit status is `1` when something at or above `--fail-on` is found, so it drops
into CI as-is.

### In GitHub Actions

Findings show up as code-scanning alerts on the offending line, each carrying
its attack string and measured cost. Patterns that measured *not exploitable*
are never raised.

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: sgoel2be24-cyber/redoscope@v0.3.0
    with:
      path: src
      fail-on: exponential   # or polynomial | any | never
```

### With ESLint

[`eslint-plugin-redoscope`](eslint-plugin-redoscope) flags unsafe regexes in
your editor, underlines the exact sub-expression, and offers the collapse
rewrite as a quick-fix. It uses the static verdict only (ESLint is synchronous),
so pair it with `redoscope scan` in CI for measured proof.

```js
// eslint.config.js
import redoscope from "eslint-plugin-redoscope";
export default [redoscope.configs.recommended];
```

### In the browser

`web/` builds the same engine into a single 50 KB HTML page. Static analysis
runs as you type; the attack runs in a Web Worker that is `terminate()`d when
it hangs, which is the browser's equivalent of the CLI's `SIGKILL`. The
curve-fitting code (`src/growth.ts`) and the static half of `inspect`
(`src/core.ts`) are shared, so the page and the CLI reach the same verdicts.

```bash
npm install && node web/build.ts   # writes web/dist/index.html
```

### As a library

```js
import { inspect, summarize } from "redoscope";

const report = inspect("^(a+)+$");
report.verdict;             // "exponential"
report.exploitable;         // true — measured, not assumed
report.dynamic.base;        // 3.93
report.attack;              // { prefix, pump, suffix }

import { suggestFixes } from "redoscope";

for (const fix of suggestFixes("^(a+)+$", "", report)) {
  fix.rewrite;              // "^a+$"
  fix.equivalent;           // true — same accept/reject on the tested corpus
  fix.samplesChecked;       // 211
}
```

## Suggesting a fix

`--suggest` (and `suggestFixes` in the library) proposes rewrites and refuses
to offer one it cannot stand behind. Each candidate has to clear two bars:

- **It is not slow.** The rewrite is verified by *measurement*, not by
  re-analysis: the attack is run against it at 100k characters and it is kept
  only if it stays linear. This matters because one of the rewrites — an atomic
  group emulated as `(?=(?<g>X))\k<g>` — hides its quantifier behind a
  lookahead, which the static analyser (correctly) models as empty and would
  otherwise wave through.
- **It still means the same thing.** The original and the rewrite are run
  against a corpus of generated strings — accepting walks over the automaton,
  one-edit neighbours, the attack itself, and random noise — and must agree on
  every one. The count is always reported, because this is a check, not a
  proof; any single disagreement discards the candidate.

Three rewrites are tried, best first: collapsing a redundant nested quantifier
(`(a+)+` → `a+`, exactly equivalent), making the culprit atomic, and — clearly
labelled as a mitigation that changes the language — bounding its repetition to
pair with `--max-input`. When none of them verifies, redoscope says so rather
than emitting a rewrite that does not hold.

## How it works

**1. Parse.** Full ECMAScript regex grammar, including the Annex B legacy forms
real code actually contains. Character classes, `\p{...}`, and case folding all
collapse into sets of code points, stored as intervals — which is why `[\s\S]*`
costs the same to analyse as `a*`.

**2. Compile to an NFA.** Not the automaton for the *language*, the automaton
for what a *backtracking engine explores*. Those differ: `(a|a)` becomes two
edges, not one, because the engine really does try both. Lookaround and
backreferences become ε and are recorded as approximations, which
over-approximates the available paths — so the analysis can over-report, but
will not silently miss.

**3. Decide ambiguity.** Matching time is governed by how many distinct paths
spell an input, so the question is the automaton's degree of ambiguity:

- **Exponential (EDA)** — some state `q` and word `w` admit two *different*
  paths `q ⟶w⟶ q`. Pump `w` and the path count doubles.
- **Polynomial (IDA)** — distinct `q₁ ≠ q₂` and a word `w` admit `q₁⟶q₁`,
  `q₁⟶q₂`, `q₂⟶q₂`. A chain of `k` such states gives Θ(n^k).

Both are decided on product automata, where "two paths on one word" becomes
"one path in the product" — following Weideman et al., *Analyzing Matching Time
Behavior of Backtracking Regular Expression Matchers* (CIAA 2016).

**…including the search loop.** A single match attempt is not the whole cost.
An unanchored regex that fails at offset 0 is retried at 1, 2, … n, and that
loop is a pump too. `\s*,\s*` has no ambiguity at all, yet on a run of spaces
each of the n attempts consumes the rest of the run before failing: Θ(n²). It
is the most common shape in real ReDoS advisories (koa, hono, axios, debug,
semver). So polynomial degree is decided on `Σ*·A`, with the `Σ*` loop standing
for the retries, unless the pattern is anchored with `^`, sticky, or the
attempt at offset 0 would simply succeed (`\d+`, `(ab)*`), in which case there
is no second attempt.

**4. Build a witness.** `prefix · pump^n · suffix`. The suffix is the part that
gets the least attention elsewhere and matters most: the engine only explores
every path when denied a successful one.

**5. Measure it.** The attack runs in a killable child process against an
escalating ladder of sizes, and the growth rate is fitted from the timings. A
kill is not a failure — it is the strongest available evidence.

Step 5 is what makes step 3 trustworthy, and it regularly disagrees with it.
That disagreement is reported rather than hidden.

## What it will not tell you

- **Backreferences and lookaround are modelled as empty.** Patterns using them
  are marked *reduced confidence*, and their static verdicts can over-report.
  The measurement still applies.
- **Findings are about the pattern, not the program.** `ms` ships a regex this
  tool rates O(n²) — and guards it with `if (str.length > 100) return`. The
  regex is quadratic; the package is fine. Only you know whether the input is
  attacker-controlled and unbounded.
- **Measurements describe the engine that ran them.** V8 defeats some ambiguity
  with literal prefilters. A pattern that measures linear here may not in
  another runtime, which is why the static verdict is always reported too.
- **`{n,m}` bounds above 20 are widened to unbounded**, and very large patterns
  are refused rather than analysed slowly. Both are reported.

## Development

```bash
node --test 'test/**/*.test.ts'   # 107 tests
npm run typecheck
```

The suite is designed to be able to falsify the project's central claim: every
pattern the analyser calls exponential must *measure* exponential using its own
generated witness. Two of the tests exist because they caught real bugs —
`/[^a]/i` (case folding must happen before complementing, verified against the
engine) and `(a*)*` (ε-elimination silently merges the iteration boundary, and
the pattern was being reported as safe).

## License

MIT
