# eslint-plugin-redoscope

Flags regular expressions that can be forced to backtrack catastrophically
(ReDoS, [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html)), right in
your editor, using [redoscope](https://github.com/sgoel2be24-cyber/redoscope)'s
automaton analysis.

ESLint runs synchronously, so this rule uses redoscope's **static** verdict — it
does not run the attack and time it the way the CLI does. It points at the exact
sub-expression responsible and, where a language-preserving rewrite exists,
offers it as an editor suggestion. For measured proof — and to filter out the
patterns that are ambiguous but not actually exploitable — run `redoscope scan`
in CI as well.

## Install

```bash
npm install --save-dev eslint-plugin-redoscope
```

## Use (flat config, ESLint 9+)

```js
// eslint.config.js
import redoscope from "eslint-plugin-redoscope";

export default [
  redoscope.configs.recommended,
];
```

Or configure the rule directly:

```js
import redoscope from "eslint-plugin-redoscope";

export default [
  {
    plugins: { redoscope },
    rules: {
      "redoscope/no-unsafe-regex": ["error", { level: "polynomial" }],
    },
  },
];
```

## Options

| option | default | meaning |
|---|---|---|
| `level` | `"exponential"` | Lowest verdict to report. `"exponential"` is high-confidence; `"polynomial"` also flags quadratic patterns, which usually only bite on unbounded attacker input. |
| `allow` | `[]` | Regex source strings to never report (an escape hatch for a pattern you have reviewed). |

## What it catches

```js
const email = /^([a-zA-Z0-9._-]+)+@example\.com$/;  // exponential — offers /^[a-zA-Z0-9._-]+@example\.com$/
const nested = /^(a+)+$/;                            // exponential — offers /^a+$/
const trim   = /\s*,\s*/;                            // polynomial (with level: "polynomial")
const built  = new RegExp("(x+x+)+y");               // exponential
const ok     = /^\d+$/;                              // not reported
```

The underline lands on the sub-expression that causes the blow-up, and the
"collapse the redundant nested quantifier" suggestion is offered as an
editor quick-fix whenever the rewrite is exactly equivalent.

MIT licensed. Part of the [redoscope](https://github.com/sgoel2be24-cyber/redoscope) project.
