// webcat audit: what an auditor can check about one domain from what it serves (spec auditing.md): the served bundles,
// the enrollment history the chain names, the manifest files, and every release archive reachable from them. Each
// archive carries the well-known directory of its time, so the archives are walked backwards until the first release.
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { WebcatError } from "@freedomofpress/webcat/webcat/interfaces/errors";
import { type BundleDocument, describeValidity, parseBundleObject, verifyBundle } from "./bundle.js";
import { bareDomain, enrollmentHashHex, fetchDomainStatus } from "./chain.js";
import { parseEnrollmentObject } from "./enrollment.js";
import { gitRemoteTagExists } from "./git.js";
import { HASH_FILE, WELL_KNOWN_DIR, checkHistory, fetchArchive, manifestFileName, verifyArchiveFiles } from "./history.js";
import { type ManifestDocument, canonicalizeManifestBody, parseManifestDocumentObject } from "./manifest.js";
import { causeOf, describeWebcatError, external } from "./utils.js";

export interface ReleaseAudit {
  version: string;
  source?: string;
  artifact?: string;
  problems: string[]; // what fails for this release
  notes: string[]; // what could not be checked
}

export interface AuditReport {
  bundle: string;
  previousBundle: string;
  enrollments: string[]; // one line per enrollment hash the chain or the bundles name
  manifests: string[]; // one line per served manifest file
  releases: ReleaseAudit[];
  problems: number;
}

const artifactUrl = (template: string, version: string): string => template.replace(/\$\{version\}/g, version);

// The repository, build and comparison an auditor runs for a release (spec manifest.md section 2; the recipe is TODO there).
export function reproGuideline(domain: string, release: ReleaseAudit): string[] {
  if (!release.source) return [`${release.version}: no source declared, cannot be rebuilt`];
  return [
    `${release.version}: rebuild from ${release.source}`,
    `  git clone --branch ${release.version} --depth 1 ${release.source} src && cd src`,
    "  # build with the repository's recipe (one command producing the web root, e.g. npm ci && npm run build -> dist/)",
    `  webcat audit ${domain} --version ${release.version} --built dist     # every path in files must hash as the manifest says`,
  ];
}

async function fetchJsonOrNull(url: string): Promise<unknown | null> {
  const response = await fetch(url).catch((err) => {
    throw external(`failed to fetch ${url}: ${causeOf(err)}`);
  });
  if (response.status === 404 || response.status === 410) return null;
  if (!response.ok) throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
  return response.json().catch(() => "not JSON");
}

export async function auditDomain(
  domain: string,
  options: { chainApi: string; origin?: string; built?: string; version?: string; onProgress?: (line: string) => void },
): Promise<AuditReport> {
  const origin = options.origin ?? `https://${bareDomain(domain)}`;
  const wellKnownUrl = (name: string) => `${origin}/${WELL_KNOWN_DIR}/${name}`;
  const progress = options.onProgress ?? (() => {});
  const describe = async (bundle: BundleDocument | null): Promise<string> => {
    if (!bundle) return "none";
    const result = await verifyBundle(bundle);
    return result instanceof WebcatError ? `FAILED: ${describeWebcatError(result)}` : `VERIFIED (${describeValidity(result)})`;
  };
  const loadBundle = async (name: string): Promise<BundleDocument | null> => {
    const parsed = await fetchJsonOrNull(wellKnownUrl(name));
    return parsed === null ? null : parseBundleObject(parsed, wellKnownUrl(name));
  };
  const current = await loadBundle("bundle.json");
  if (!current) throw external(`${wellKnownUrl("bundle.json")} is not found; nothing to audit`);
  const previous = await loadBundle("bundle-prev.json");
  const report: AuditReport = { bundle: await describe(current), previousBundle: await describe(previous), enrollments: [], manifests: [], releases: [], problems: 0 };

  // 2.1 Enrollment history: every hash the chain or a served bundle names has its file, and the file hashes to the name.
  const status = await fetchDomainStatus(options.chainApi, domain).catch((err) => err as Error);
  const hashes = new Set<string>([enrollmentHashHex(current.enrollment), ...(previous ? [enrollmentHashHex(previous.enrollment)] : [])]);
  if (status instanceof Error) report.enrollments.push(`chain not consulted: ${status.message}`);
  else for (const h of [status.canonical, ...status.pending.map((p) => p.hash)]) if (h) hashes.add(h);
  for (const hash of hashes) {
    const name = `enrollment.${hash}.json`;
    const parsed = await fetchJsonOrNull(wellKnownUrl(name));
    let line: string;
    try {
      line = parsed === null ? `${name}: MISSING` : enrollmentHashHex(parseEnrollmentObject(parsed)) === hash ? `${name}: ok` : `${name}: does not hash to its name`;
    } catch (err) {
      line = `${name}: ${causeOf(err)}`;
    }
    report.enrollments.push(line);
  }

  // 2.3 Manifest recovery: the served manifests are published under the name the log entry leads to.
  const expectManifestFile = async (bundle: BundleDocument, why: string): Promise<void> => {
    const name = manifestFileName(bundle.enrollment, bundle.manifest);
    const parsed = await fetchJsonOrNull(wellKnownUrl(name));
    let line: string;
    try {
      const stored = parsed === null ? null : parseManifestDocumentObject(parsed);
      line = stored === null ? `${name}: MISSING (${why})` : canonicalizeManifestBody(stored) === canonicalizeManifestBody(bundle.manifest) ? `${name}: ok (${why})` : `${name}: differs from ${why}`;
    } catch (err) {
      line = `${name}: ${causeOf(err)}`;
    }
    report.manifests.push(line);
  };
  await expectManifestFile(current, "the manifest in bundle.json");
  if (previous) await expectManifestFile(previous, "the manifest in bundle-prev.json");

  // 3. Each release reachable from the served manifests: its source tag, its archive, and the history the archive carries.
  const queue: ManifestDocument[] = [current.manifest, ...(previous ? [previous.manifest] : [])];
  const seen = new Set<string>();
  while (queue.length) {
    const document = queue.shift()!;
    const { version, source, artifact } = document.manifest;
    if (seen.has(version) || (options.version && options.version !== version)) continue;
    seen.add(version);
    const release: ReleaseAudit = { version, source, artifact, problems: [], notes: [] };
    report.releases.push(release);
    progress(`release ${version}`);
    if (options.built && (!options.version || options.version === version)) {
      release.problems.push(...(await verifyArchiveFiles(options.built, document)).map((p) => `built ${options.built}: ${p}`));
    }
    if (!source && !artifact) release.notes.push("neither source nor artifact declared: cannot be audited (spec auditing.md section 1)");
    if (source) {
      const tag = await gitRemoteTagExists(source, version);
      if (tag === null) release.notes.push(`cannot list the tags of ${source}`);
      else if (!tag) release.problems.push(`tag ${version} is not on ${source}`);
    }
    if (!artifact) continue;
    const url = artifactUrl(artifact, version);
    let archive: Awaited<ReturnType<typeof fetchArchive>>;
    try {
      archive = await fetchArchive(url);
    } catch (err) {
      release.problems.push(`archive ${url}: ${causeOf(err)}`);
      continue;
    }
    try {
      release.problems.push(...(await verifyArchiveFiles(archive.site, document)).map((p) => `archive ${url}: ${p}`));
      const names = await readdir(archive.wellKnown).catch(() => null);
      if (names === null) {
        release.notes.push(`archive ${url} carries no ${WELL_KNOWN_DIR}; releases before it cannot be found from it`);
        continue;
      }
      release.problems.push(...(await checkHistory(archive.wellKnown)).map((p) => `archive ${url}, ${WELL_KNOWN_DIR}: ${p}`));
      // Every hash-named file the archive carried must still be served unchanged (spec auditing.md section 4).
      for (const name of names.filter((n) => HASH_FILE.test(n))) {
        const inArchive = await readFile(path.join(archive.wellKnown, name), "utf8");
        const served = await fetchJsonOrNull(wellKnownUrl(name));
        if (served === null) release.problems.push(`${name} was in the ${version} archive but is no longer served`);
        else if (JSON.stringify(served) !== JSON.stringify(JSON.parse(inArchive))) release.problems.push(`${name} served differs from the ${version} archive`);
        if (name.startsWith("manifest.")) {
          try {
            queue.push(parseManifestDocumentObject(JSON.parse(inArchive)));
          } catch (err) {
            release.problems.push(`archive ${url}, ${name}: ${causeOf(err)}`);
          }
        }
      }
    } finally {
      await archive.cleanup();
    }
  }
  report.problems =
    report.releases.reduce((n, r) => n + r.problems.length, 0) +
    [...report.enrollments, ...report.manifests].filter((l) => /MISSING|does not hash|differs|not JSON/.test(l)).length +
    (report.bundle.startsWith("FAILED") ? 1 : 0);
  return report;
}

export function formatAudit(domain: string, report: AuditReport, repro: boolean): string {
  const out: string[] = [`Domain: ${domain}`, `bundle.json: ${report.bundle}`, `bundle-prev.json: ${report.previousBundle}`, "", "Enrollment history:"];
  out.push(...report.enrollments.map((l) => `  ${l}`), "", "Manifest files:", ...report.manifests.map((l) => `  ${l}`), "", "Releases:");
  for (const r of report.releases) {
    out.push(`  ${r.version}${r.source ? `  source ${r.source}` : ""}${r.artifact ? `  artifact ${artifactUrl(r.artifact, r.version)}` : ""}`);
    out.push(...r.problems.map((p) => `    PROBLEM: ${p}`), ...r.notes.map((n) => `    note: ${n}`));
    if (r.problems.length === 0 && r.notes.length === 0) out.push("    ok");
  }
  if (repro) out.push("", "Reproducing the releases:", ...report.releases.flatMap((r) => reproGuideline(domain, r).map((l) => `  ${l}`)));
  out.push("", report.problems === 0 ? "OK: no problems found" : `${report.problems} problem${report.problems > 1 ? "s" : ""} found`);
  return out.join("\n") + "\n";
}
