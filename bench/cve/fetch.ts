/**
 * Builds the CVE corpus from primary sources only.
 *
 *  1. Every reviewed npm advisory in the GitHub Advisory Database tagged
 *     CWE-1333 (Inefficient Regular Expression Complexity).
 *  2. For each affected range with a published fix: the last release inside
 *     the vulnerable range, and the first patched release.
 *  3. Both tarballs, downloaded from the npm registry and unpacked with the
 *     system `tar` (which refuses absolute and `..` paths). Package code is
 *     never executed.
 *
 * Nothing here decides which regex is "the vulnerable one" — run.ts derives
 * that from the diff between the two releases.
 *
 * Usage: node bench/cve/fetch.ts [--limit N]
 */

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const semver = require("semver");

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const CACHE = path.join(HERE, ".cache");
export const PAIRS_FILE = path.join(CACHE, "pairs.json");
const MAX_TARBALL_BYTES = 12 * 1024 * 1024;

export interface Pair {
  ghsa: string;
  cve: string | null;
  severity: string;
  summary: string;
  published: string;
  name: string;
  range: string;
  vulnerable: string;
  patched: string;
  vulnerableDir: string;
  patchedDir: string;
}

async function getJson(url: string, headers: Record<string, string> = {}): Promise<any> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await fetch(url, { headers: { "user-agent": "redoscope-bench", ...headers } });
    if (response.ok) return response.json();
    if (response.status === 404) return null;
    await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  throw new Error(`GET ${url} failed`);
}

async function advisories(): Promise<any[]> {
  const file = path.join(CACHE, "advisories.json");
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, "utf8"));
  const all: any[] = [];
  let url: string | null =
    "https://api.github.com/advisories?ecosystem=npm&cwes=1333&type=reviewed&per_page=100";
  while (url) {
    const response = await fetch(url, { headers: { "user-agent": "redoscope-bench" } });
    if (!response.ok) throw new Error(`advisory API: ${response.status}`);
    all.push(...((await response.json()) as any[]));
    // No regex here on purpose: redoscope flags even `/<([^>]+)>/`, scanned
    // unanchored, as quadratic under its retry model — so the corpus fetcher
    // parses the Link header by hand and the whole repo passes its own scan.
    const link = (response.headers.get("link") ?? "").split(",").find((part) => part.includes('rel="next"'));
    const open = link?.indexOf("<") ?? -1;
    const close = link?.indexOf(">", open + 1) ?? -1;
    url = link && open >= 0 && close > open ? link.slice(open + 1, close) : null;
  }
  fs.writeFileSync(file, JSON.stringify(all));
  return all;
}

const packuments = new Map<string, any>();
async function packument(name: string): Promise<any> {
  if (!packuments.has(name)) {
    const url = `https://registry.npmjs.org/${name.replace("/", "%2f")}`;
    packuments.set(name, await getJson(url, { accept: "application/vnd.npm.install-v1+json" }));
  }
  return packuments.get(name);
}

async function unpack(name: string, version: string, tarball: string): Promise<string | null> {
  const dir = path.join(CACHE, "pkgs", `${name.replace("/", "__")}@${version}`);
  if (fs.existsSync(path.join(dir, ".ok"))) return dir;
  const response = await fetch(tarball);
  if (!response.ok) return null;
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_TARBALL_BYTES) return null;
  fs.mkdirSync(dir, { recursive: true });
  const archive = path.join(dir, "..", `${path.basename(dir)}.tgz`);
  fs.writeFileSync(archive, bytes);
  const result = spawnSync("tar", ["-xzf", archive, "-C", dir], { encoding: "utf8" });
  fs.rmSync(archive);
  if (result.status !== 0) return null;
  fs.writeFileSync(path.join(dir, ".ok"), "");
  return dir;
}

async function pool<T>(items: T[], size: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (next < items.length) await work(items[next++]);
    }),
  );
}

async function main(): Promise<void> {
  fs.mkdirSync(CACHE, { recursive: true });
  const limitIndex = process.argv.indexOf("--limit");
  const limit = limitIndex > 0 ? Number(process.argv[limitIndex + 1]) : Infinity;

  const all = await advisories();
  console.log(`${all.length} reviewed CWE-1333 npm advisories`);

  interface Candidate {
    advisory: any;
    name: string;
    range: string;
    patched: string;
  }
  const candidates: Candidate[] = [];
  const skipped: Record<string, number> = {};
  const skip = (why: string) => (skipped[why] = (skipped[why] ?? 0) + 1);

  for (const advisory of all) {
    if (advisory.withdrawn_at) continue;
    for (const v of advisory.vulnerabilities ?? []) {
      if (v.package?.ecosystem !== "npm") continue;
      if (!v.first_patched_version) {
        skip("no patched release");
        continue;
      }
      candidates.push({ advisory, name: v.package.name, range: v.vulnerable_version_range, patched: v.first_patched_version });
    }
  }

  const pairs: Pair[] = [];
  const seen = new Set<string>();
  await pool(candidates.slice(0, limit), 6, async ({ advisory, name, range, patched: declared }) => {
    // A few advisories write "4.16" for "4.16.0".
    const patched: string | null = semver.valid(declared) ?? semver.valid(semver.coerce(declared));
    if (!patched) return skip("unparseable patched version");
    const doc = await packument(name).catch(() => null);
    if (!doc?.versions) return skip("package unavailable");

    const npmRange = range.replace(/,\s*/g, " ");
    const allowPre = semver.prerelease(patched) !== null;
    const inRange = Object.keys(doc.versions).filter(
      (v) => semver.valid(v) && (allowPre || !semver.prerelease(v)) && semver.satisfies(v, npmRange, { includePrerelease: allowPre }) && semver.lt(v, patched),
    );
    if (inRange.length === 0 || !doc.versions[patched]) return skip("versions not on registry");
    const vulnerable = semver.rsort(inRange)[0];

    const key = `${advisory.ghsa_id}|${name}|${vulnerable}`;
    if (seen.has(key)) return;
    seen.add(key);

    const vulnerableDir = await unpack(name, vulnerable, doc.versions[vulnerable].dist.tarball).catch(() => null);
    const patchedDir = await unpack(name, patched, doc.versions[patched].dist.tarball).catch(() => null);
    if (!vulnerableDir || !patchedDir) return skip("tarball too large or unreadable");

    pairs.push({
      ghsa: advisory.ghsa_id,
      cve: advisory.cve_id,
      severity: advisory.severity,
      summary: advisory.summary,
      published: advisory.published_at,
      name,
      range,
      vulnerable,
      patched,
      vulnerableDir,
      patchedDir,
    });
    if (pairs.length % 25 === 0) console.log(`  ${pairs.length} release pairs ready`);
  });

  pairs.sort((a, b) => a.published.localeCompare(b.published) || a.name.localeCompare(b.name));
  fs.writeFileSync(PAIRS_FILE, JSON.stringify(pairs, null, 2));
  console.log(`${pairs.length} release pairs written to ${path.relative(process.cwd(), PAIRS_FILE)}`);
  console.log("skipped:", skipped);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
