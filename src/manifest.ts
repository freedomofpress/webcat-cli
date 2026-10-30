import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { SerializedBundle } from "@sigstore/bundle";
import type { Manifest, SigsumSignatures } from "@freedomofpress/webcat/webcat/interfaces/bundle";
import { validateCSP, validateManifest } from "@freedomofpress/webcat/webcat/validators";
import { canonicalForm, causeOf, check, ensureObject, hasSchema, invalid, log, readJson, sha256, toBase64Url, validateAll } from "./utils.js";

export type ManifestContent = Manifest;
// The config keeps default_index and default_fallback: they become directory entries in files and fallback_hashes
// (spec manifest.md, schema 1). version may come from the release tag; directory is where the built site lives.
export type ManifestConfig = Omit<ManifestContent, "files" | "timestamp" | "version" | "manifest_schema" | "fallback_hashes"> & {
  version?: string;
  directory?: string;
  default_index: string;
  default_fallback: string;
};
// Manifests with manifest_schema must carry a semantic version; a leading v is accepted.
const SEMVER = /^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;
export type ManifestSignatures = SigsumSignatures | SerializedBundle[];

export interface ManifestDocument {
  manifest: ManifestContent;
  signatures?: ManifestSignatures;
}

export interface DirectoryScanResult {
  files: Map<string, string>;
  wasm: Set<string>;
}

export interface DirectoryScanOptions {
  includeDotfiles?: boolean;
  excludePaths?: string[];
}

export const asLibraryManifest = (manifest: ManifestContent): Manifest => manifest as unknown as Manifest;

const sortedEntries = <T>(record: Record<string, T>): Record<string, T> =>
  Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));

const isRecordOfStrings = (value: unknown): value is Record<string, string> =>
  typeof value === "object" && value !== null && !Array.isArray(value) && Object.values(value).every((v) => typeof v === "string");

// Everything the extension checks on a manifest, plus its CSP rules on every policy string.
export function validateManifestContent(manifest: ManifestContent, subject = "manifest", extra: Array<() => unknown> = []): void {
  const policies = [["default_csp", manifest.default_csp], ...Object.entries(manifest.extra_csp ?? {}).map(([k, v]) => [`extra_csp['${k}']`, v])];
  validateAll([
    () => check(validateManifest(asLibraryManifest(manifest)), subject),
    () => {
      if (hasSchema(manifest) && !SEMVER.test(String(manifest.version))) {
        throw invalid(`${subject}.version must be a semantic version such as 1.4.0, got '${manifest.version}'`);
      }
    },
    ...extra,
    ...policies.map(([field, csp]) => () => {
      if (typeof csp !== "string") {
        throw invalid(`${subject}.${field} must be a CSP string`);
      }
      try {
        validateCSP(csp);
      } catch (err) {
        throw invalid(`${subject}.${field} must be a WEBCAT-compatible CSP: ${causeOf(err)}`);
      }
    }),
  ]);
}

export async function loadManifestConfig(configPath: string): Promise<ManifestConfig> {
  const c = ensureObject(await readJson(configPath, "manifest config"), "manifest config");
  const str = (key: string): string => {
    if (typeof c[key] !== "string" || c[key] === "") {
      throw invalid(`config.${key} must be a non-empty string`);
    }
    return c[key] as string;
  };
  const wasm = c.wasm ?? [];
  const extra_csp = c.extra_csp ?? {};
  const optionalUrl = (key: string, protocols: string[], extra?: (url: string) => string | undefined) => () => {
    if (c[key] === undefined) return;
    let url: URL;
    try {
      url = new URL(str(key));
    } catch (err) {
      throw invalid(`config.${key} must be a URL: ${causeOf(err)}`);
    }
    if (!protocols.includes(url.protocol)) throw invalid(`config.${key} must use ${protocols.join(" or ")}`);
    const problem = extra?.(String(c[key]));
    if (problem) throw invalid(`config.${key} ${problem}`);
  };
  if (c.app !== undefined) log("Warning: config.app is deprecated; set source (git repository URL) and artifact (release archive URL template) instead");
  validateAll([
    optionalUrl("app", ["https:", "http:"]),
    optionalUrl("source", ["https:", "ssh:"]),
    optionalUrl("artifact", ["https:", "http:"], (u) => (u.includes("${version}") ? undefined : "must contain ${version}")),
    ...["default_csp", "default_index", "default_fallback"].map((key) => () => str(key)),
    () => {
      if (c.version !== undefined) str("version");
    },
    () => {
      if (!Array.isArray(wasm) || !wasm.every((w) => typeof w === "string")) {
        throw invalid("config.wasm must be an array of strings");
      }
    },
    () => {
      if (!isRecordOfStrings(extra_csp) || Object.keys(extra_csp).some((k) => !k.startsWith("/"))) {
        throw invalid("config.extra_csp must map '/'-prefixed path prefixes to CSP strings");
      }
    },
  ]);
  // CSP, index and fallback are checked with the extension's rules once the manifest is built.
  if (c.source === undefined && c.artifact === undefined) log("Warning: neither config.source nor config.artifact is set; auditors cannot reproduce or fetch this release");
  return {
    ...(c.app !== undefined ? { app: str("app") } : {}),
    ...(c.source !== undefined ? { source: str("source") } : {}),
    ...(c.artifact !== undefined ? { artifact: str("artifact") } : {}),
    ...(c.version !== undefined ? { version: str("version") } : {}),
    ...(c.directory !== undefined ? { directory: str("directory") } : {}),
    default_csp: str("default_csp"),
    default_index: str("default_index").replace(/^\/+/, ""), // appended to directory paths
    default_fallback: str("default_fallback"),
    wasm: wasm as string[],
    extra_csp: extra_csp as Record<string, string>,
  };
}

export async function scanDirectory(rootDir: string, options: DirectoryScanOptions = {}): Promise<DirectoryScanResult> {
  const result: DirectoryScanResult = { files: new Map(), wasm: new Set() };
  // The well-known directory is never part of the manifest: its content changes after signing.
  const excludePaths = [".well-known/webcat", ...(options.excludePaths ?? [])]
    .map((raw) => raw.trim().replace(/\\/g, "/").replace(/^\.?\/*/, "").replace(/\/+$/, ""))
    .filter(Boolean);
  const isExcluded = (relativePath: string) =>
    excludePaths.some((exclude) => relativePath === exclude || relativePath.startsWith(`${exclude}/`));

  async function walk(currentDir: string, relativePrefix: string): Promise<void> {
    for (const entry of await readdir(currentDir, { withFileTypes: true })) {
      if (!options.includeDotfiles && entry.name.startsWith(".")) {
        continue;
      }
      const relativePath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
      if (isExcluded(relativePath)) {
        continue;
      }
      const entryPath = path.join(currentDir, entry.name);
      // Follow symlinks, as a web server serving the directory would.
      const target = entry.isSymbolicLink() ? await stat(entryPath) : entry;
      if (target.isDirectory()) {
        await walk(entryPath, relativePath);
        continue;
      }
      if (!target.isFile()) {
        continue;
      }
      const encoded = toBase64Url(sha256(await readFile(entryPath)));
      if (path.extname(entry.name).toLowerCase() === ".wasm") {
        result.wasm.add(encoded);
      } else {
        result.files.set(`/${relativePath}`, encoded);
      }
    }
  }

  await walk(path.resolve(rootDir), "");
  return result;
}

// Schema 1 (spec manifest.md): a directory path lists the hash of its index document, the fallback is listed by
// hash, and app, default_index and default_fallback stay out of the manifest.
export function buildManifest(config: ManifestConfig & { version: string }, scan: DirectoryScanResult, timestamp?: string): ManifestContent {
  const files = Object.fromEntries(scan.files);
  const suffix = "/" + config.default_index;
  for (const [filePath, hash] of scan.files) {
    if (filePath.endsWith(suffix)) files[filePath.slice(0, 1 - suffix.length)] ??= hash;
  }
  const fallback = files[config.default_fallback];
  const manifest: ManifestContent = {
    manifest_schema: 1,
    ...(config.source !== undefined ? { source: config.source } : {}),
    ...(config.artifact !== undefined ? { artifact: config.artifact } : {}),
    version: config.version,
    default_csp: config.default_csp,
    files: sortedEntries(files),
    fallback_hashes: fallback === undefined ? [] : [fallback],
    wasm: Array.from(new Set([...config.wasm, ...scan.wasm])).sort(),
    extra_csp: sortedEntries(config.extra_csp),
    ...(timestamp ? { timestamp } : {}),
  };
  validateManifestContent(manifest, "config", [
    () => {
      if (fallback === undefined) throw invalid(`config.default_fallback ${config.default_fallback} is not a file in the directory`);
    },
  ]);
  return manifest;
}

// The file lookup the extension performs (originstate.ts): a manifest without manifest_schema has its
// default_index and default_fallback turned into directory entries and fallback_hashes first.
export function normalizeManifest(manifest: ManifestContent): ManifestContent {
  if (hasSchema(manifest)) return manifest;
  const files = { ...manifest.files };
  if (manifest.default_index) {
    const suffix = "/" + manifest.default_index;
    for (const filePath of Object.keys(manifest.files)) {
      if (filePath.endsWith(suffix)) files[filePath.slice(0, 1 - suffix.length)] ??= manifest.files[filePath];
    }
  }
  const fallback = manifest.default_fallback !== undefined ? manifest.files[manifest.default_fallback] : undefined;
  return { ...manifest, files, fallback_hashes: manifest.fallback_hashes ?? (fallback === undefined ? [] : [fallback]) };
}

function parseManifestSignatures(value: unknown): ManifestSignatures | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  // Legacy manifests wrapped signatures as { sigsum: {...} } or { sigstore: [...] }.
  const wrapped = Array.isArray(value) ? {} : ensureObject(value, "manifest.signatures");
  if ("sigsum" in wrapped && "sigstore" in wrapped) {
    throw invalid("manifest.signatures must not contain both sigsum and sigstore keys");
  }
  const inner = "sigsum" in wrapped ? wrapped.sigsum : "sigstore" in wrapped ? wrapped.sigstore : value;
  if (Array.isArray(inner)) {
    inner.forEach((bundle, i) => ensureObject(bundle, `manifest.signatures[${i}]`));
    return inner as SerializedBundle[];
  }
  if (!isRecordOfStrings(inner)) {
    throw invalid("manifest.signatures must be a list of Sigstore bundles or a map of signer key to Sigsum proof");
  }
  return inner;
}

export function parseManifestDocumentObject(parsed: unknown): ManifestDocument {
  const document = ensureObject(parsed, "manifest");
  const manifest = ensureObject(document.manifest, "manifest.manifest");
  manifest.wasm ??= [];
  manifest.extra_csp ??= {};
  if (!isRecordOfStrings(manifest.extra_csp)) {
    throw invalid("manifest.manifest.extra_csp must map path prefixes to CSP strings");
  }
  validateManifestContent(manifest as unknown as ManifestContent, "manifest.manifest");
  return { manifest: manifest as unknown as ManifestContent, signatures: parseManifestSignatures(document.signatures) };
}

export const loadManifestDocument = async (manifestPath: string): Promise<ManifestDocument> =>
  parseManifestDocumentObject(await readJson(manifestPath, "manifest"));

export function canonicalizeManifestBody(document: ManifestDocument): string {
  try {
    return canonicalForm(document.manifest);
  } catch (err) {
    throw invalid(`manifest.manifest must contain only strings, integers, booleans, null, arrays and objects: ${causeOf(err)}`);
  }
}

export const manifestHash = (document: ManifestDocument): Buffer => sha256(canonicalizeManifestBody(document));
