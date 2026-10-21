import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import type { SerializedBundle } from "@sigstore/bundle";
import type { Manifest, SigsumSignatures } from "@freedomofpress/webcat/webcat/interfaces/bundle";
import { canonicalize } from "@freedomofpress/webcat/webcat/canonicalize";
import { validateCSP, validateManifest } from "@freedomofpress/webcat/webcat/validators";
import { causeOf, check, ensureObject, invalid, readJson, sha256, toBase64Url, validateAll } from "./utils.js";

// The CLI writes `app` where the library's interface says `name`; the extension reads neither.
export type ManifestContent = Omit<Manifest, "name"> & { app: string };
export type ManifestConfig = Omit<ManifestContent, "files" | "timestamp">;
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

export const asLibraryManifest = (manifest: ManifestContent): Manifest => manifest as unknown as Manifest;

const sortedEntries = <T>(record: Record<string, T>): Record<string, T> =>
  Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));

const isRecordOfStrings = (value: unknown): value is Record<string, string> =>
  typeof value === "object" && value !== null && !Array.isArray(value) && Object.values(value).every((v) => typeof v === "string");

// Everything the extension checks on a manifest, plus its CSP rules on every policy string.
export function validateManifestContent(manifest: ManifestContent, subject = "manifest"): void {
  const policies = [["default_csp", manifest.default_csp], ...Object.entries(manifest.extra_csp ?? {}).map(([k, v]) => [`extra_csp['${k}']`, v])];
  validateAll([
    () => check(validateManifest(asLibraryManifest(manifest)), subject),
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
  validateAll([
    () => {
      try {
        new URL(str("app"));
      } catch (err) {
        throw invalid(`config.app must be a valid URL: ${causeOf(err)}`);
      }
    },
    ...["version", "default_csp", "default_index", "default_fallback"].map((key) => () => str(key)),
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
    default_fallback: str("default_fallback"),
    wasm: wasm as string[],
    extra_csp: extra_csp as Record<string, string>,
  };
}

export async function scanDirectory(rootDir: string, options: DirectoryScanOptions = {}): Promise<DirectoryScanResult> {
  const result: DirectoryScanResult = { files: new Map(), wasm: new Set() };
  const excludePaths = (options.excludePaths ?? [])
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

export function buildManifest(config: ManifestConfig, scan: DirectoryScanResult, timestamp?: string): ManifestContent {
  const manifest: ManifestContent = {
    app: config.app,
    version: config.version,
    default_csp: config.default_csp,
    files: sortedEntries(Object.fromEntries(scan.files)),
    default_index: config.default_index,
    default_fallback: config.default_fallback,
    wasm: Array.from(new Set([...config.wasm, ...scan.wasm])).sort(),
    extra_csp: sortedEntries(config.extra_csp),
    ...(timestamp ? { timestamp } : {}),
  };
  validateManifestContent(manifest, "config");
  return manifest;
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
