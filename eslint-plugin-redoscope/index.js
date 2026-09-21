/**
 * eslint-plugin-redoscope
 *
 * One rule, `redoscope/no-unsafe-regex`, that flags a regular expression whose
 * automaton admits catastrophic backtracking. It uses redoscope's *static*
 * analysis only — ESLint runs synchronously, so there is no room to run the
 * attack and time it the way the CLI does. That trade is made explicit: the
 * rule reports the automaton's verdict, points at the exact sub-expression,
 * and, where a language-preserving rewrite exists, offers it as an editor
 * suggestion. For measured proof (and to rule out the ambiguous-but-harmless
 * cases), run `redoscope` or `redoscope scan` in CI.
 */

import { prepare, candidateFixes } from "redoscope";

const DOCS = "https://github.com/sgoel2be24-cyber/redoscope#eslint";

/** Static analysis of one pattern, tolerant of anything unparseable. */
function analyse(pattern, flags) {
  try {
    return prepare(pattern, flags);
  } catch {
    return null;
  }
}

/** The regex source and its offset inside the ESLint node, or null. */
function patternOf(node) {
  if (node.type === "Literal" && node.regex) {
    // `/pat/flags` — the source sits one character past the opening slash.
    return { pattern: node.regex.pattern, flags: node.regex.flags, offset: node.range[0] + 1 };
  }
  if (
    node.type === "NewExpression" &&
    node.callee.type === "Identifier" &&
    node.callee.name === "RegExp" &&
    node.arguments.length >= 1 &&
    node.arguments[0].type === "Literal" &&
    typeof node.arguments[0].value === "string"
  ) {
    const arg = node.arguments[0];
    const flagsArg = node.arguments[1];
    const flags = flagsArg && flagsArg.type === "Literal" && typeof flagsArg.value === "string" ? flagsArg.value : "";
    // `raw` still carries escaping, so offsets would not line up; skip the hotspot.
    return { pattern: arg.value, flags, offset: null };
  }
  return null;
}

const rule = {
  meta: {
    type: "problem",
    docs: {
      description: "flag regular expressions that can be forced to backtrack catastrophically (ReDoS)",
      recommended: true,
      url: DOCS,
    },
    hasSuggestions: true,
    schema: [
      {
        type: "object",
        properties: {
          // Which verdicts to report. Exponential is high-confidence; polynomial
          // is often only a problem on unbounded attacker input, so it is opt-in.
          level: { enum: ["exponential", "polynomial"] },
          allow: { type: "array", items: { type: "string" } },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      exponential: "This regex can be made to backtrack exponentially (ReDoS). The sub-expression `{{hotspot}}` is the cause.",
      polynomial: "This regex can be made to backtrack polynomially (ReDoS). The sub-expression `{{hotspot}}` is the cause.",
      collapse: "Collapse the redundant nested quantifier to `{{rewrite}}`.",
    },
  },

  create(context) {
    const options = context.options[0] || {};
    const level = options.level || "exponential";
    const allow = new Set(options.allow || []);
    const source = context.sourceCode || context.getSourceCode();

    function check(node) {
      const found = patternOf(node);
      if (!found || allow.has(found.pattern)) return;

      const prepared = analyse(found.pattern, found.flags);
      if (!prepared || prepared.report.error) return;
      const report = prepared.report;
      if (report.verdict === "safe") return;
      if (level === "exponential" && report.verdict !== "exponential") return;

      const hotspot = report.hotspot;
      const hotspotText = hotspot ? found.pattern.slice(hotspot.start, hotspot.end) : found.pattern;

      // Precise underline when the offsets are trustworthy (regex literal).
      let loc = node.loc;
      if (hotspot && found.offset !== null) {
        loc = {
          start: source.getLocFromIndex(found.offset + hotspot.start),
          end: source.getLocFromIndex(found.offset + hotspot.end),
        };
      }

      const suggest = [];
      const collapse = candidateFixes(found.pattern, found.flags, report).find((c) => c.kind === "collapse");
      if (collapse && node.type === "Literal") {
        suggest.push({
          messageId: "collapse",
          data: { rewrite: `/${collapse.rewrite}/${found.flags}` },
          fix: (fixer) => fixer.replaceText(node, `/${collapse.rewrite}/${found.flags}`),
        });
      }

      context.report({
        node,
        loc,
        messageId: report.verdict === "exponential" ? "exponential" : "polynomial",
        data: { hotspot: hotspotText },
        suggest,
      });
    }

    return { Literal: check, NewExpression: check };
  },
};

const plugin = {
  meta: { name: "eslint-plugin-redoscope", version: "0.3.0" },
  rules: { "no-unsafe-regex": rule },
};

// Flat-config presets (ESLint 9+).
plugin.configs = {
  recommended: {
    plugins: { redoscope: plugin },
    rules: { "redoscope/no-unsafe-regex": "error" },
  },
};

export default plugin;
export const rules = plugin.rules;
export const configs = plugin.configs;
