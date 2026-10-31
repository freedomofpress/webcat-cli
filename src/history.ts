// The well-known directory as an append-only ledger (spec server.md section 1): hash-named files are written once
// and never change; enrollment.json, bundle.json and bundle-prev.json are the current pointers derived from them.
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { type Enrollment, EnrollmentTypes, canonicalizeEnrollment, parseEnrollmentObject } from "./enrollment.js";
import { gitChangedSince } from "./git.js";
import { type ManifestDocument, canonicalizeManifestBody, parseManifestDocumentObject, scanDirectory } from "./manifest.js";
import { causeOf, external, fetchOk, invalid, log, sha256, toBase64Url } from "./utils.js";

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

export function tar(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("tar", args, { stdio: ["ignore", "inherit", "inherit"] });
    child.on("error", (err) => reject(external(`failed to run tar: ${causeOf(err)}`)));
    child.on("exit", (code) => (code === 0 ? resolve() : reject(external(`failed to run tar: exit code ${code}`))));
  });
}

// The release archive is the web root with the well-known directory inside, so the next release can inherit it.
export async function archiveRelease(archive: string, siteDirectory: string, dir: string): Promise<void> {
  const base = path.resolve(dir, "../..");
  const plain = `${archive}.tar`;
  // Two steps: an exclude pattern given with the first directory would also drop the entry appended from the second.
  await tar(["-cf", plain, "-C", siteDirectory, `--exclude=./${WELL_KNOWN_DIR}`, "."]);
  await tar(["-rf", plain, "-C", base, path.relative(base, path.resolve(dir))]);
  await writeFile(archive, gzipSync(await readFile(plain)));
  await rm(plain, { force: true });
}

// Release n inherits the well-known directory from release n-1's archive: hash-named files, fallback documents and the
// bundle pointers. The archive is first checked against the manifest it ships and its own hash-named files, so a
// release only inherits history from a predecessor that was what it claimed.
export async function inheritHistory(dir: string, archiveUrl: string): Promise<string[]> {
  const work = await mkdtemp(path.join(tmpdir(), "webcat-previous-"));
  try {
    const archive = path.join(work, "release.tgz");
    await writeFile(archive, new Uint8Array(await (await fetchOk(archiveUrl)).arrayBuffer()));
    const site = path.join(work, "site");
    await mkdir(site);
    await tar(["-xzf", archive, "-C", site]);
    const previous = path.join(site, WELL_KNOWN_DIR);
    const bundleText = await readFile(path.join(previous, "bundle.json"), "utf8").catch(() => null);
    if (bundleText === null) {
      log(`Warning: ${archiveUrl} carries no ${WELL_KNOWN_DIR}/bundle.json; nothing to inherit`);
      return [];
    }
    const bundle = JSON.parse(bundleText);
    const document = parseManifestDocumentObject({ manifest: bundle.manifest, signatures: bundle.signatures });
    const scan = await scanDirectory(site, { includeDotfiles: true });
    for (const [file, hash] of Object.entries(document.manifest.files)) {
      if (!file.endsWith("/") && scan.files.get(file) !== hash) {
        throw invalid(`${archiveUrl}: ${file} is missing or does not hash as the manifest of release ${document.manifest.version} says; not inheriting its history`);
      }
    }
    const problems = await checkHistory(previous);
    if (problems.length > 0) throw invalid(`${archiveUrl}: ${WELL_KNOWN_DIR} is inconsistent: ${problems.join("; ")}`);
    const written: string[] = [];
    await mkdir(dir, { recursive: true });
    for (const name of await readdir(previous)) {
      const content = await readFile(path.join(previous, name), "utf8").catch(() => null);
      if (content === null) continue;
      if (HASH_FILE.test(name)) {
        if (await writeOnce(dir, name, content)) written.push(path.join(dir, name));
      } else if (name === "bundle.json" || name === "bundle-prev.json") {
        await writeFile(path.join(dir, name), content);
        written.push(path.join(dir, name));
      }
    }
    for (const name of await readdir(path.join(previous, HASHES_DIR)).catch(() => [] as string[])) {
      const content = await readFile(path.join(previous, HASHES_DIR, name), "utf8");
      if (await writeOnce(path.join(dir, HASHES_DIR), name, content)) written.push(path.join(dir, HASHES_DIR, name));
    }
    return written;
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
