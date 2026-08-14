# redoscope

Finds regular expressions that can be made to backtrack catastrophically — and
then **proves it**, by building the attack string and timing the real engine.

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

Meanwhile `([ab]|[bc])*` really is exponential, but only on input made of `b`.
Time it with the obvious `"aaaa…"` and you will measure nothing and conclude it
is fine.

redoscope answers with a string you can paste into a terminal, and the numbers
it produced when run.

## Does it actually help

`bench/compare.ts` runs three methods over whatever tree you point it at. On
**627 distinct regexes** scraped from a `node_modules` directory:

|  | flagged | false positives | missed |
|---|---|---|---|
| star height ≥ 2 *(the classic heuristic)* | 10 | 10 | 14 |
| redoscope, static only | 23 | 9 | 0 |
| redoscope, measured | 14 | 0 | 0 |

The heuristic scored **zero true positives**: everything it flagged was
provably unambiguous, and it missed every confirmed-slow pattern. That is not
bad luck. Real-world ReDoS rarely looks like `(a+)+` — it looks like
`(?:\d+)?\.?\d+` (the `ms` package) or `[\s]*"(.*)"[\s]*`, both of which have
star height 1 and sail straight through the check.

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
git clone <this repo> && cd redoscope
node src/cli.ts '^(a+)+$'
```

There is nothing to install. Node 22.18+ runs the TypeScript directly.

## Use

```bash
redoscope '<pattern>' [flags]      # inspect one regex
redoscope scan src/                # inspect every regex in a tree
```

| Option | |
|---|---|
| `--json` | machine-readable output |
| `--html <file>` | self-contained HTML report (scan only) |
| `--no-measure` | static analysis only; never runs the engine |
| `--timeout <ms>` | budget per attack candidate (default 2000) |
| `--fail-on <level>` | `exponential` (default), `polynomial`, `any`, `never` |
| `--quiet` | findings only |

Exit status is `1` when something at or above `--fail-on` is found, so it drops
into CI as-is.

As a library:

```js
import { inspect, summarize } from "redoscope";

const report = inspect("^(a+)+$");
report.verdict;             // "exponential"
report.exploitable;         // true — measured, not assumed
report.dynamic.base;        // 3.93
report.attack;              // { prefix, pump, suffix }
```

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
node --test 'test/**/*.test.ts'   # 86 tests
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
