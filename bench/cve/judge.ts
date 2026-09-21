/**
 * The neutral judge.
 *
 * A tool's verdict is a claim. The judge turns claims into facts by replaying
 * every attack string any tool produced, in a separate process it can kill,
 * and applying one fixed rule to the timings:
 *
 *   CONFIRMED  — an input of at most MAX_CHARS characters makes a single
 *                `RegExp.prototype.test` take at least SLOW_MS, *and* the time
 *                grows super-linearly with input size (or the engine had to be
 *                killed).
 *
 * The judge never looks at a tool's verdict, only at its strings, so it treats
 * redoscope and recheck identically.
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const MAX_CHARS = 50_000;
export const SLOW_MS = 1_000;
const KILL_MS = 6_000;
const PROBE = fileURLToPath(new URL("./judge-probe.mjs", import.meta.url));

export interface AttackFamily {
  /** Where the attack came from, for the audit trail. */
  by: string;
  pumps: { prefix: string; pump: string }[];
  suffix: string;
}

export interface Judgement {
  confirmed: boolean;
  /** How many replays the decision rests on: 1, or 3 when it was near the bar. */
  replays?: number;
  by: string | null;
  /** The slowest completed sample, or the size at which the engine was killed. */
  length: number | null;
  ms: number | null;
  killed: boolean;
}

interface Sample {
  n: number;
  length: number;
  ms: number;
}

function replay(source: string, flags: string, family: AttackFamily): Judgement {
  const request = JSON.stringify({
    source,
    flags,
    pumps: family.pumps,
    suffix: family.suffix,
    maxChars: MAX_CHARS,
    stopMs: SLOW_MS,
  });
  const result = spawnSync(process.execPath, ["--no-warnings", PROBE, request], {
    timeout: KILL_MS,
    killSignal: "SIGKILL",
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });

  const samples: Sample[] = [];
  for (const line of (result.stdout ?? "").split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (typeof parsed.ms === "number") samples.push(parsed);
      else return { confirmed: false, by: null, length: null, ms: null, killed: false };
    } catch {
      /* partial line from a killed process */
    }
  }

  const killed = result.signal === "SIGKILL" || result.error !== undefined;
  const last = samples.at(-1);
  if (killed) {
    // The engine was stuck on the rung after the last one it finished.
    return { confirmed: true, by: family.by, length: last?.length ?? null, ms: KILL_MS, killed: true };
  }
  if (!last || last.ms < SLOW_MS) {
    return { confirmed: false, by: null, length: last?.length ?? null, ms: last?.ms ?? null, killed: false };
  }

  // Slow is not enough: a huge linear pattern on 50k characters can be slow
  // too. Demand that doubling the input more than doubles the time.
  const half = [...samples].reverse().find((s) => s.length <= last.length / 2 && s.ms > 0);
  const superLinear = half === undefined || last.ms / half.ms >= 2.5;
  return { confirmed: superLinear, by: superLinear ? family.by : null, length: last.length, ms: last.ms, killed: false };
}

/** Within this factor of SLOW_MS, one timing is not enough to decide. */
const BORDERLINE = 0.3;

/**
 * Replay a family, and when the slowest sample lands near the bar, replay it
 * twice more and decide on the median. A single run at 0.97 s or 1.03 s says
 * more about the machine that moment than about the regex, and those were
 * exactly the advisories that flipped between full benchmark runs.
 */
function steadyReplay(source: string, flags: string, family: AttackFamily): Judgement {
  const first = replay(source, flags, family);
  const near = first.ms !== null && !first.killed && Math.abs(first.ms - SLOW_MS) <= SLOW_MS * BORDERLINE;
  if (!near) return { ...first, replays: 1 };

  const runs = [first, replay(source, flags, family), replay(source, flags, family)];
  // A kill in any replay is decisive on its own.
  const killed = runs.find((r) => r.killed);
  if (killed) return { ...killed, replays: 3 };
  runs.sort((a, b) => (a.ms ?? 0) - (b.ms ?? 0));
  return { ...runs[1], replays: 3 };
}

/** Replay every family; the worst one decides. */
export function judge(source: string, flags: string, families: AttackFamily[]): Judgement {
  let best: Judgement = { confirmed: false, by: null, length: null, ms: null, killed: false };
  for (const family of families) {
    if (family.pumps.length === 0 || family.pumps.every((p) => p.pump.length === 0)) continue;
    const judgement = steadyReplay(source, flags, family);
    if (judgement.confirmed) return judgement;
    if ((judgement.ms ?? 0) > (best.ms ?? 0)) best = judgement;
  }
  return best;
}
