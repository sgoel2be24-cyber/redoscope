/**
 * RuleTester coverage for redoscope/no-unsafe-regex.
 *
 * Run with eslint installed:  node --test eslint-plugin-redoscope/test.js
 * (Kept out of the main suite because the analyser package does not depend on
 * eslint; CI installs it for this job.)
 */

import { RuleTester } from "eslint";
import { rules } from "./index.js";

const tester = new RuleTester();

tester.run("no-unsafe-regex", rules["no-unsafe-regex"], {
  valid: [
    "const ok = /^\\d+$/;",
    "const ok = /^[a-z0-9._%+-]+@[a-z0-9.-]+$/;",
    // Polynomial is not reported at the default (exponential) level.
    { code: "const q = /\\s*,\\s*/;" },
    // Anything on the allow-list is skipped.
    { code: "const skip = /^(a+)+$/;", options: [{ allow: ["^(a+)+$"] }] },
    // A non-regex RegExp argument is ignored.
    "const dyn = new RegExp(userInput);",
  ],
  invalid: [
    {
      code: "const bad = /^(a+)+$/;",
      errors: [
        {
          messageId: "exponential",
          suggestions: [
            {
              messageId: "collapse",
              output: "const bad = /^a+$/;",
            },
          ],
        },
      ],
    },
    {
      code: "const email = /^([a-zA-Z0-9._-]+)+@example\\.com$/;",
      errors: [
        {
          messageId: "exponential",
          suggestions: [
            {
              messageId: "collapse",
              output: "const email = /^[a-zA-Z0-9._-]+@example\\.com$/;",
            },
          ],
        },
      ],
    },
    {
      // Polynomial shows up once the level is lowered.
      code: "const trim = /\\s*,\\s*/;",
      options: [{ level: "polynomial" }],
      errors: [{ messageId: "polynomial" }],
    },
    {
      code: 'const built = new RegExp("(x+x+)+y");',
      errors: [{ messageId: "exponential" }],
    },
  ],
});

console.log("no-unsafe-regex: all RuleTester cases passed");
