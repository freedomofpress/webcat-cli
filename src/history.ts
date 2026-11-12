// The well-known directory as an append-only ledger (spec server.md section 1): hash-named files are written once
// and never change; enrollment.json, bundle.json and bundle-prev.json are the current pointers derived from them.
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { WebcatError, WebcatErrorCode } from "@freedomofpress/webcat/webcat/interfaces/errors";
import { type BundleDocument, parseBundleObject, verifyBundle } from "./bundle.js";
import { enrollmentHashHex } from "./chain.js";
import { type Enrollment, EnrollmentTypes, parseEnrollmentObject } from "./enrollment.js";
import { gitChangedSince } from "./git.js";
import { type ManifestDocument, canonicalizeManifestBody, parseManifestDocumentObject, scanDirectory } from "./manifest.js";
import { causeOf, describeWebcatError, external, fetchOk, invalid, log, sha256, toBase64Url } from "./utils.js";

export const WELL_KNOWN_DIR = ".well-known/webcat";
// History records were valid when published; the CSP rules of the current extension do not decide what is kept.
const RECORD = { policy: false };
export const HASH_FILE = /^(enrollment|manifest\.sigsum|manifest\.sigstore)\.([0-9a-f]{64})\.json$/;
// Each fallback document of a manifest, under its base64url hash (spec manifest.md fallback_hashes).
export const HASHES_DIR = "hashes";

export const enrollmentHash = enrollmentHashHex;
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
  // enrollment.json is what the oracles observe; it must be the enrollment the bundle carries (a migration changes it).
  const pointer = path.join(dir, "enrollment.json");
  if ((await readFile(pointer, "utf8").catch(() => null)) !== pretty(enrollment)) {
    await mkdir(dir, { recursive: true });
    await writeFile(pointer, pretty(enrollment));
    written.push(pointer);
  }
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

// bundle-prev.json serves clients that still hold the old enrollment: the chain's cool-down, then everyone whose list
// has not caught up. Once it has expired no client can accept it, so only then is it removed; its hash-named files
// stay in the history.
export async function dropExpiredPrevious(dir: string): Promise<boolean> {
  const previous = path.join(dir, "bundle-prev.json");
  const text = await readFile(previous, "utf8").catch(() => null);
  if (text === null) return false;
  const result = await verifyBundle(parseBundleObject(JSON.parse(text), previous, RECORD));
  if (!(result instanceof WebcatError && result.code === WebcatErrorCode.Manifest.EXPIRED)) return false;
  await rm(previous);
  return true;
}

// A directory from before the history files existed (the old CLI, or a hand-made deploy) has only the pointers.
// The hash-named files are derived from them: the bundle carries the enrollment and the signed manifest in full.
export async function materializeHistory(dir: string): Promise<string[]> {
  const written: string[] = [];
  for (const name of ["bundle-prev.json", "bundle.json", "enrollment.json"]) {
    const text = await readFile(path.join(dir, name), "utf8").catch(() => null);
    if (text === null) continue;
    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      continue; // a catch-all page or a broken pointer: checkHistory reports it
    }
    try {
      const enrollment = parseEnrollmentObject(name === "enrollment.json" ? parsed : parsed.enrollment);
      if (await writeOnce(dir, enrollmentFileName(enrollment), pretty(enrollment))) written.push(path.join(dir, enrollmentFileName(enrollment)));
      if (name !== "enrollment.json") {
        const document = parseManifestDocumentObject({ manifest: parsed.manifest, signatures: parsed.signatures }, RECORD);
        const manifestName = manifestFileName(enrollment, document);
        if (await writeOnce(dir, manifestName, pretty({ manifest: document.manifest, signatures: document.signatures }))) written.push(path.join(dir, manifestName));
      }
    } catch {
      // not a bundle or enrollment the extension would accept: checkHistory reports it
    }
  }
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
        const document = parseManifestDocumentObject(parsed, RECORD);
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
        const document = parseManifestDocumentObject({ manifest: parsed.manifest, signatures: parsed.signatures }, RECORD);
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

// Downloads and extracts a release archive; the caller removes the directory when done.
export async function fetchArchive(archiveUrl: string): Promise<{ site: string; wellKnown: string; cleanup: () => Promise<void> }> {
  const work = await mkdtemp(path.join(tmpdir(), "webcat-archive-"));
  try {
    const archive = path.join(work, "release.tgz");
    await writeFile(archive, new Uint8Array(await (await fetchOk(archiveUrl)).arrayBuffer()));
    const site = path.join(work, "site");
    await mkdir(site);
    await tar(["-xzf", archive, "-C", site]);
    return { site, wellKnown: path.join(site, WELL_KNOWN_DIR), cleanup: () => rm(work, { recursive: true, force: true }) };
  } catch (err) {
    await rm(work, { recursive: true, force: true });
    throw err;
  }
}

// Spec manifest.md section 3 and auditing.md 3.1: every path in files is in the directory and hashes as the manifest says.
export async function verifyArchiveFiles(site: string, document: ManifestDocument): Promise<string[]> {
  const scan = await scanDirectory(site, { includeDotfiles: true });
  const problems: string[] = [];
  for (const [file, hash] of Object.entries(document.manifest.files)) {
    if (file.endsWith("/")) continue;
    const actual = scan.files.get(file);
    problems.push(...(actual === undefined ? [`${file} is missing`] : actual !== hash ? [`${file} hashes to ${actual}, the manifest says ${hash}`] : []));
  }
  return problems;
}

// The pointers a history is inherited from must be bundles the extension accepted: signed by their own enrollment's
// signers. Only EXPIRED passes among the verifier's errors, since it comes after the signature checks and a history
// legitimately holds releases older than max_age. Returns bundle.json's manifest.
async function assertSignedPointers(dir: string, subject: string): Promise<ManifestDocument> {
  let current: BundleDocument | undefined;
  for (const name of ["bundle.json", "bundle-prev.json"]) {
    const text = await readFile(path.join(dir, name), "utf8").catch(() => null);
    if (text === null) continue;
    const bundle = parseBundleObject(JSON.parse(text), `${subject} ${name}`, RECORD);
    const result = await verifyBundle(bundle);
    if (result instanceof WebcatError && result.code !== WebcatErrorCode.Manifest.EXPIRED) {
      throw invalid(`${subject}: ${name} does not verify under its own enrollment (${describeWebcatError(result)}); not inheriting its history`);
    }
    if (name === "bundle.json") current = bundle;
  }
  if (!current) throw invalid(`${subject}: no bundle.json`);
  return current.manifest;
}

// Release n inherits the well-known directory from release n-1's archive: hash-named files, fallback documents and the
// bundle pointers. The archive is first checked against the manifest it ships and its own hash-named files, so a
// release only inherits history from a predecessor that was what it claimed.
export async function inheritHistory(dir: string, archiveUrl: string): Promise<string[]> {
  const { site, wellKnown: previous, cleanup } = await fetchArchive(archiveUrl);
  try {
    const bundleText = await readFile(path.join(previous, "bundle.json"), "utf8").catch(() => null);
    if (bundleText === null) {
      log(`Warning: ${archiveUrl} carries no ${WELL_KNOWN_DIR}/bundle.json; nothing to inherit`);
      return [];
    }
    const document = await assertSignedPointers(previous, archiveUrl);
    const mismatched = await verifyArchiveFiles(site, document);
    if (mismatched.length > 0) {
      throw invalid(`${archiveUrl}: ${mismatched[0].split(" ")[0]} is missing or does not hash as the manifest of release ${document.manifest.version} says; not inheriting its history`);
    }
    // An archive from before the history files existed only has the pointers; what they carry becomes the history.
    const materialized = await materializeHistory(previous);
    if (materialized.length) log(`${archiveUrl} predates the history files: ${materialized.length} derived from its bundle`);
    const problems = await checkHistory(previous);
    if (problems.length > 0) throw invalid(`${archiveUrl}: ${WELL_KNOWN_DIR} is inconsistent: ${problems.join("; ")}`);
    return await copyHistory(previous, dir); // await: the finally below removes the source once the copy is done, not before
  } finally {
    await cleanup();
  }
}

// Hash-named files and fallbacks are written once; the pointers are taken over as they are.
async function copyHistory(from: string, dir: string): Promise<string[]> {
  const written: string[] = [];
  await mkdir(dir, { recursive: true });
  for (const name of await readdir(from)) {
    const content = await readFile(path.join(from, name), "utf8").catch(() => null);
    if (content === null) continue;
    if (HASH_FILE.test(name)) {
      if (await writeOnce(dir, name, content)) written.push(path.join(dir, name));
    } else if (name === "bundle.json" || name === "bundle-prev.json") {
      await writeFile(path.join(dir, name), content);
      written.push(path.join(dir, name));
    }
  }
  for (const name of await readdir(path.join(from, HASHES_DIR)).catch(() => [] as string[])) {
    const content = await readFile(path.join(from, HASHES_DIR, name), "utf8");
    if (await writeOnce(path.join(dir, HASHES_DIR), name, content)) written.push(path.join(dir, HASHES_DIR, name));
  }
  return written;
}

// The live site as the history source: what it serves under the well-known path, pointers and the hash-named files
// they lead to. The first release with this CLI inherits from here, so the manifest served today stays in the history
// and the previous bundle is there to rotate when the enrollment migrates. With previousVersion, the site must serve
// that release: an older one means a release never reached the site, and its history would be dropped here.
export async function inheritFromSite(dir: string, origin: string, previousVersion?: string): Promise<string[]> {
  const base = `${origin.replace(/\/+$/, "")}/${WELL_KNOWN_DIR}`;
  const work = await mkdtemp(path.join(tmpdir(), "webcat-site-"));
  try {
    const get = async (name: string): Promise<string | null> => {
      const response = await fetch(`${base}/${name}`).catch((err) => {
        throw external(`failed to fetch ${base}/${name}: ${causeOf(err)}`);
      });
      if (!response.ok) return null;
      const text = await response.text();
      try {
        if (typeof JSON.parse(text) !== "object") return null;
      } catch {
        return null; // a catch-all page
      }
      await writeFile(path.join(work, name), text);
      return text;
    };
    const bundle = await get("bundle.json");
    if (bundle === null) throw external(`${base}/bundle.json is not served; nothing to inherit from the site`);
    await get("bundle-prev.json");
    await get("enrollment.json");
    const document = await assertSignedPointers(work, base);
    const version = String(document.manifest.version);
    if (previousVersion !== undefined && version.replace(/^v/, "") !== previousVersion.replace(/^v/, "")) {
      throw invalid(`${base}/bundle.json is version ${version}, the previous release is ${previousVersion}: its history is not on the site. Deploy it, publish its archive, or inherit by hand (history inherit ${origin}) and pass --no-history`);
    }
    await materializeHistory(work);
    // Hash-named files the site already serves for what the pointers name, so a later audit finds the same bytes.
    for (const name of await readdir(work)) {
      if (!HASH_FILE.test(name)) continue;
      const served = await get(name);
      if (served !== null) await writeFile(path.join(work, name), served);
    }
    for (const hash of document.manifest.fallback_hashes ?? []) {
      const response = await fetch(`${base}/${HASHES_DIR}/${hash}`).catch(() => null);
      if (response?.ok) {
        await mkdir(path.join(work, HASHES_DIR), { recursive: true });
        await writeFile(path.join(work, HASHES_DIR, hash), new Uint8Array(await response.arrayBuffer()));
      }
    }
    const problems = await checkHistory(work);
    if (problems.length > 0) throw invalid(`${base}: inconsistent: ${problems.join("; ")}`);
    return await copyHistory(work, dir); // await: the finally below removes the source once the copy is done, not before
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}
