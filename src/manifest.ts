import { copyFile, mkdir, readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { SerializedBundle } from "@sigstore/bundle";
import type { Manifest, SigsumSignatures } from "@freedomofpress/webcat/webcat/interfaces/bundle";
import { canonicalize } from "@freedomofpress/webcat/webcat/canonicalize";
import { validateCSP, validateManifest } from "@freedomofpress/webcat/webcat/validators";
import { causeOf, check, ensureObject, invalid, readJson, sha256, toBase64Url, validateAll } from "./utils.js";

export type ManifestContent = Manifest;
// What webcat.config.json holds: fallbacks are paths here and hashes in the manifest.
export type ManifestConfig = Omit<ManifestContent, "files" | "timestamp" | "default_index" | "default_fallback" | "fallback_hashes"> & {
  default_index: string;
  fallbacks: string[];
};

// Where each fallback is published under its hash, so auditors can find what the manifest accepts.
export const HASHES_PATH = "/.well-known/webcat/hashes/";
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

// Build output hosts do not serve, so listing it makes the manifest unverifiable (per each host's docs; there is no standard).
const HOST_ONLY_FILES = new Set([
  "/CNAME", "/_config.yml", // GitHub Pages
  "/_headers", "/_redirects", "/netlify.toml", // Netlify, Cloudflare Pages
  "/_routes.json", "/_worker.js", // Cloudflare Pages
  "/vercel.json", // Vercel
  "/firebase.json", // Firebase Hosting
  "/staticwebapp.config.json", // Azure Static Web Apps
  "/customHttp.yml", // AWS Amplify
]);
// Plus any dot segment (.htaccess, ._*, .env, .git/) except .well-known/, which is served on purpose.
export const isHostOnlyFile = (p: string): boolean =>
  HOST_ONLY_FILES.has(p) || p.startsWith("/_next/__private/") || (p.includes("/.") && !p.startsWith("/.well-known/"));

const sortedEntries = <T>(record: Record<string, T>): Record<string, T> =>
  Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));

const isRecordOfStrings = (value: unknown): value is Record<string, string> =>
  typeof value === "object" && value !== null && !Array.isArray(value) && Object.values(value).every((v) => typeof v === "string");

// Everything the extension checks on a manifest, plus its CSP rules on every policy string, plus `more`.
export function validateManifestContent(manifest: ManifestContent, subject = "manifest", more: Array<() => void> = []): void {
  const policies = [["default_csp", manifest.default_csp], ...Object.entries(manifest.extra_csp ?? {}).map(([k, v]) => [`extra_csp['${k}']`, v])];
  validateAll([
    () => check(validateManifest(manifest), subject),
    ...more,
    // Extensions before 3.2.0 require both and reject a manifest whose entries do not resolve (#263).
    () => {
      if (manifest.default_index && !manifest.files[`/${manifest.default_index}`]) {
        throw invalid(`${subject}.default_index must name a file in files, '/${manifest.default_index}' was not found`);
      }
    },
    () => {
      if (manifest.default_fallback && !manifest.files[manifest.default_fallback]) {
        throw invalid(`${subject}.default_fallback must name a file in files, '${manifest.default_fallback}' was not found`);
      }
    },
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
  c.default_index ??= "index.html";
  // default_fallback is the pre-3.2.0 spelling of a single fallback (#263).
  const fallbacks = c.fallbacks ?? (c.default_fallback === undefined ? [`/${String(c.default_index).replace(/^\/+/, "")}`] : [c.default_fallback]);
  validateAll([
    () => {
      try {
        new URL(str("app"));
      } catch (err) {
        throw invalid(`config.app must be a valid URL: ${causeOf(err)}`);
      }
    },
    ...["version", "default_csp", "default_index"].map((key) => () => str(key)),
    () => {
      if (!Array.isArray(fallbacks) || !fallbacks.every((f) => typeof f === "string" && f.startsWith("/"))) {
        throw invalid("config.fallbacks must be an array of '/'-prefixed paths");
      }
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
  return {
    app: str("app"),
    version: str("version"),
    default_csp: str("default_csp"),
    default_index: str("default_index").replace(/^\/+/, ""), // appended to directory paths
    fallbacks: fallbacks as string[],
    wasm: wasm as string[],
    extra_csp: extra_csp as Record<string, string>,
  };
}

export async function scanDirectory(rootDir: string, options: DirectoryScanOptions = {}): Promise<DirectoryScanResult> {
  const result: DirectoryScanResult = { files: new Map(), wasm: new Set() };
  // What init writes next to the site, never meant to be served; keys/ holds private keys.
  const excludePaths = ["webcat.config.json", "trust_policy", "keys", ...(options.excludePaths ?? [])]
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

// A 3.2.0 manifest (directory keys, fallback_hashes) that extensions before 3.2.0 still read through
// default_index and default_fallback (#263); drop those two once such extensions are gone.
// shortcut: every index file is listed next to its directory key, as pre-3.2.0 extensions resolve "/"
// through "/index.html"; when the two legacy fields go, add a config switch to list the directory key only.
export function buildManifest(config: ManifestConfig, scan: DirectoryScanResult, timestamp?: string): ManifestContent {
  const files = Object.fromEntries(scan.files);
  const suffix = `/${config.default_index}`;
  for (const p of Object.keys(files)) {
    if (p.endsWith(suffix)) files[p.slice(0, 1 - suffix.length)] ??= files[p];
  }
  const fallbacks = config.fallbacks.filter((p) => files[p]); // the missing ones are reported below
  const fallback_hashes = fallbacks.map((p) => files[p]);
  const manifest: ManifestContent = {
    app: config.app,
    version: config.version,
    default_csp: config.default_csp,
    files: sortedEntries(files),
    ...(fallback_hashes.length ? { fallback_hashes } : {}),
    default_index: config.default_index,
    ...(fallbacks.length ? { default_fallback: fallbacks[0] } : {}),
    wasm: Array.from(new Set([...config.wasm, ...scan.wasm])).sort(),
    extra_csp: sortedEntries(config.extra_csp),
    ...(timestamp ? { timestamp } : {}),
  };
  validateManifestContent(
    manifest,
    "config",
    config.fallbacks.map((p) => () => {
      if (!files[p]) throw invalid(`config.fallbacks must name scanned files, '${p}' was not found`);
    }),
  );
  return manifest;
}

// Copies each fallback to <directory>/.well-known/webcat/hashes/<hash>; returns the paths written.
export async function writeFallbackCopies(directory: string, config: ManifestConfig, manifest: ManifestContent): Promise<string[]> {
  const written: string[] = [];
  for (const p of config.fallbacks) {
    const target = `${HASHES_PATH}${manifest.files[p]}`;
    await mkdir(path.join(directory, HASHES_PATH), { recursive: true });
    await copyFile(path.join(directory, p), path.join(directory, target));
    written.push(target);
  }
  return written;
}

// The manifest as a 3.2.0 extension reads it: legacy default_index and default_fallback rewritten
// into directory keys and fallback_hashes, explicit values winning.
export function effectiveManifest(manifest: ManifestContent): ManifestContent {
  const files = { ...manifest.files };
  if (manifest.default_index) {
    const suffix = `/${manifest.default_index}`;
    for (const p of Object.keys(files)) {
      if (p.endsWith(suffix)) files[p.slice(0, 1 - suffix.length)] ??= files[p];
    }
  }
  const fallback_hashes = manifest.fallback_hashes ?? (manifest.default_fallback ? [manifest.files[manifest.default_fallback]].filter(Boolean) : []);
  return { ...manifest, files, fallback_hashes };
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
  const canonical = canonicalize(document.manifest);
  if (canonical === null) {
    throw invalid("manifest.manifest must contain only strings, integers, booleans, null, arrays and objects");
  }
  return canonical;
}

export const manifestHash = (document: ManifestDocument): Buffer => sha256(canonicalizeManifestBody(document));
