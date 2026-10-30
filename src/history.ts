// The well-known directory as an append-only ledger (spec server.md section 1): hash-named files are written once
// and never change; enrollment.json, bundle.json and bundle-prev.json are the current pointers derived from them.
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { type Enrollment, EnrollmentTypes, canonicalizeEnrollment, parseEnrollmentObject } from "./enrollment.js";
import { gitChangedSince } from "./git.js";
import { type ManifestDocument, canonicalizeManifestBody, parseManifestDocumentObject, scanDirectory } from "./manifest.js";
import { invalid, log, sha256, toBase64Url } from "./utils.js";

export const WELL_KNOWN_DIR = ".well-known/webcat";
const HASH_FILE = /^(enrollment|manifest\.sigsum|manifest\.sigstore)\.([0-9a-f]{64})\.json$/;
// Each fallback document of a manifest, under its base64url hash (spec manifest.md fallback_hashes).
export const HASHES_DIR = "hashes";

export const enrollmentHash = (enrollment: Enrollment): string => sha256(canonicalizeEnrollment(enrollment)).toString("hex");
export const enrollmentFileName = (enrollment: Enrollment): string => `enrollment.${enrollmentHash(enrollment)}.json`;

// Sigsum: the leaf checksum, sha256 of the submitted message (itself sha256 of the canonical manifest).
// Sigstore: the artifact digest in the Rekor entry, sha256 of the canonical manifest.
export function manifestFileName(enrollment: Enrollment, document: ManifestDocument): string {
  const digest = sha256(canonicalizeManifestBody(document));
  return enrollment.type === EnrollmentTypes.Sigsum ? `manifest.sigsum.${sha256(digest).toString("hex")}.json` : `manifest.sigstore.${digest.toString("hex")}.json`;
}

// Writes a hash-named file once; the same content again is a no-op, different content is a mistake.
export async function writeOnce(dir: string, name: string, content: string): Promise<boolean> {
  const file = path.join(dir, name);
  const existing = await readFile(file, "utf8").catch(() => null);
  if (existing !== null) {
    if (existing !== content) {
      throw invalid(`${file} already exists with different content; history files must not change (spec server.md section 1)`);
    }
    return false;
  }
  await mkdir(dir, { recursive: true });
  await writeFile(file, content);
  return true;
}

const pretty = (value: unknown): string => JSON.stringify(value, null, 2) + "\n";

// enrollment.json plus its hash-named copy.
export async function publishEnrollment(dir: string, enrollment: Enrollment): Promise<string[]> {
  const written: string[] = [];
  if (await writeOnce(dir, enrollmentFileName(enrollment), pretty(enrollment))) written.push(path.join(dir, enrollmentFileName(enrollment)));
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "enrollment.json"), pretty(enrollment));
  written.push(path.join(dir, "enrollment.json"));
  return written;
}

// The fallback documents listed in the manifest, copied from the built site into hashes/<hash>. Without the site
// directory they cannot be found, and the operator is told what to publish.
export async function publishFallbacks(dir: string, document: ManifestDocument, siteDirectory?: string): Promise<string[]> {
  const hashes = document.manifest.fallback_hashes ?? [];
  if (hashes.length === 0) return [];
  if (siteDirectory === undefined) {
    log(`Warning: publish each fallback document at ${WELL_KNOWN_DIR}/${HASHES_DIR}/<hash> (${hashes.join(", ")}); pass --directory to do it here`);
    return [];
  }
  const scan = await scanDirectory(siteDirectory, { includeDotfiles: true });
  const written: string[] = [];
  for (const hash of hashes) {
    const found = [...scan.files].find(([, h]) => h === hash)?.[0];
    if (found === undefined) throw invalid(`fallback ${hash} of the manifest is not a file in ${siteDirectory}`);
    const content = await readFile(path.join(siteDirectory, found), "utf8");
    if (await writeOnce(path.join(dir, HASHES_DIR), hash, content)) written.push(path.join(dir, HASHES_DIR, hash));
  }
  return written;
}

// bundle.json plus the hash-named manifest file; the previous bundle becomes bundle-prev.json when the enrollment changed.
export async function publishBundle(dir: string, enrollment: Enrollment, document: ManifestDocument, siteDirectory?: string): Promise<string[]> {
  const written: string[] = await publishFallbacks(dir, document, siteDirectory);
  const bundle = { enrollment, manifest: document.manifest, signatures: document.signatures };
  const manifestName = manifestFileName(enrollment, document);
  if (await writeOnce(dir, manifestName, pretty({ manifest: document.manifest, signatures: document.signatures }))) written.push(path.join(dir, manifestName));
  if (await writeOnce(dir, enrollmentFileName(enrollment), pretty(enrollment))) written.push(path.join(dir, enrollmentFileName(enrollment)));
  const current = path.join(dir, "bundle.json");
  const previous = await readFile(current, "utf8").catch(() => null);
  if (previous !== null) {
    const previousHash = enrollmentHash(parseEnrollmentObject(JSON.parse(previous).enrollment));
    if (previousHash !== enrollmentHash(enrollment)) {
      await rename(current, path.join(dir, "bundle-prev.json"));
      written.push(path.join(dir, "bundle-prev.json"));
      log(`Enrollment changed: previous bundle kept as bundle-prev.json until the chain promotes ${enrollmentHash(enrollment)}`);
    }
  }
  await mkdir(dir, { recursive: true });
  await writeFile(current, pretty(bundle));
  written.push(current);
  return written;
}

// Everything that must hold inside the directory, plus what git says changed since `ref`.
export async function checkHistory(dir: string, ref?: string): Promise<string[]> {
  const problems: string[] = [];
  const names = await readdir(dir).catch(() => null);
  if (names === null) {
    return [`${dir} does not exist`];
  }
  // hashes/<hash>: the content must hash to the name.
  for (const name of await readdir(path.join(dir, HASHES_DIR)).catch(() => [] as string[])) {
    const actual = toBase64Url(sha256(await readFile(path.join(dir, HASHES_DIR, name))));
    if (actual !== name) problems.push(`${HASHES_DIR}/${name}: content hashes to ${actual}, not to its name`);
  }
  for (const name of names) {
    const m = HASH_FILE.exec(name);
    if (!m) continue;
    const text = await readFile(path.join(dir, name), "utf8");
    let actual: string;
    try {
      const parsed = JSON.parse(text);
      if (m[1] === "enrollment") {
        actual = enrollmentHash(parseEnrollmentObject(parsed));
      } else {
        const document = parseManifestDocumentObject(parsed);
        const digest = sha256(canonicalizeManifestBody(document));
        actual = m[1] === "manifest.sigsum" ? sha256(digest).toString("hex") : digest.toString("hex");
      }
    } catch (err) {
      problems.push(`${name}: does not parse (${err instanceof Error ? err.message : err})`);
      continue;
    }
    if (actual !== m[2]) problems.push(`${name}: content hashes to ${actual}, not to its name`);
  }
  for (const [pointer, part] of [["enrollment.json", "enrollment"], ["bundle.json", "bundle"], ["bundle-prev.json", "bundle"]] as const) {
    const text = await readFile(path.join(dir, pointer), "utf8").catch(() => null);
    if (text === null) continue;
    try {
      const parsed = JSON.parse(text);
      const enrollment = parseEnrollmentObject(part === "enrollment" ? parsed : parsed.enrollment);
      if (!names.includes(enrollmentFileName(enrollment))) problems.push(`${pointer}: its enrollment has no ${enrollmentFileName(enrollment)}`);
      if (part === "bundle") {
        const document = parseManifestDocumentObject({ manifest: parsed.manifest, signatures: parsed.signatures });
        const expected = manifestFileName(enrollment, document);
        const stored = await readFile(path.join(dir, expected), "utf8").catch(() => null);
        if (stored === null) problems.push(`${pointer}: its manifest has no ${expected}`);
        else if (stored !== pretty({ manifest: parsed.manifest, signatures: parsed.signatures })) problems.push(`${pointer}: ${expected} differs from the manifest and signatures in the bundle`);
        for (const hash of document.manifest.fallback_hashes ?? []) {
          const served = await readFile(path.join(dir, HASHES_DIR, hash)).catch(() => null);
          if (served === null) problems.push(`${pointer}: its manifest lists fallback ${hash} but ${HASHES_DIR}/${hash} is missing`);
        }
      }
    } catch (err) {
      problems.push(`${pointer}: ${err instanceof Error ? err.message : err}`);
    }
  }
  if (ref) {
    for (const [status, file] of await gitChangedSince(ref, path.resolve(dir), path.resolve(dir))) {
      if (HASH_FILE.test(path.basename(file)) && status !== "A") problems.push(`${file}: ${status === "D" ? "deleted" : "modified"} since ${ref}; history files must stay unchanged while the domain is enrolled`);
    }
  }
  return problems;
}
