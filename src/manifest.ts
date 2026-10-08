import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import type { SerializedBundle } from "@sigstore/bundle";
import { canonicalize } from "./canonicalize.js";
import {
  causeOf,
  ensureAbsolutePath,
  ensureNonEmptyString,
  ensureObject,
  ensureRecordOfStrings,
  invalid,
  readJson,
  sha256,
  toBase64Url,
} from "./utils.js";

export interface ManifestConfig {
  app: string;
  version: string;
  default_csp: string;
  default_index: string;
  default_fallback: string;
  wasm: string[];
  extra_csp: Record<string, string>;
}

export interface ManifestContent extends ManifestConfig {
  files: Record<string, string>;
  timestamp?: string;
}

export type ManifestSignatures = Record<string, string> | SerializedBundle[];

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

const sortedEntries = <T>(record: Record<string, T>): Record<string, T> =>
  Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));

export async function loadManifestConfig(configPath: string): Promise<ManifestConfig> {
  const parsed = ensureObject(await readJson(configPath, "manifest config"), "manifest config");

  const app = ensureNonEmptyString(parsed.app, "config.app");
  try {
    new URL(app);
  } catch (err) {
    throw invalid(`config.app must be a valid URL: ${causeOf(err)}`);
  }

  let wasm: string[] = [];
  if (parsed.wasm !== undefined) {
    if (!Array.isArray(parsed.wasm)) {
      throw invalid("config.wasm must be an array of strings");
    }
    wasm = parsed.wasm.map((value, index) => ensureNonEmptyString(value, `config.wasm[${index}]`));
  }

  const extraCsp = ensureRecordOfStrings(parsed.extra_csp ?? {}, "config.extra_csp");
  for (const key of Object.keys(extraCsp)) {
    if (!key.startsWith("/")) {
      throw invalid(`config.extra_csp keys must start with '/', got '${key}'`);
    }
  }

  return {
    app,
    version: ensureNonEmptyString(parsed.version, "config.version"),
    default_csp: ensureNonEmptyString(parsed.default_csp, "config.default_csp"),
    // default_index is appended to directory paths, so it must not carry a leading slash.
    default_index: ensureNonEmptyString(parsed.default_index, "config.default_index").replace(/^\/+/, ""),
    default_fallback: ensureAbsolutePath(parsed.default_fallback, "config.default_fallback"),
    wasm,
    extra_csp: extraCsp,
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
      if (entry.isDirectory()) {
        await walk(entryPath, relativePath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      const manifestPath = `/${relativePath}`;
      const contents = await readFile(entryPath);
      const encoded = toBase64Url(sha256(contents));
      const isWasm = path.extname(entry.name).toLowerCase() === ".wasm";
      if (isWasm) {
        result.wasm.add(encoded);
      } else {
        result.files.set(manifestPath, encoded);
      }
    }
  }

  await walk(path.resolve(rootDir), "");
  return result;
}

export function buildManifest(config: ManifestConfig, scan: DirectoryScanResult, timestamp?: string): ManifestContent {
  if (!scan.files.has(`/${config.default_index}`)) {
    throw invalid(`config.default_index must name a scanned file, '${config.default_index}' was not found`);
  }
  if (!scan.files.has(config.default_fallback)) {
    throw invalid(`config.default_fallback must name a scanned file, '${config.default_fallback}' was not found`);
  }
  return {
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
}

function parseBundleList(value: unknown, name: string): SerializedBundle[] {
  if (!Array.isArray(value)) {
    throw invalid(`${name} must be an array`);
  }
  value.forEach((entry, index) => ensureObject(entry, `${name}[${index}]`));
  return value as SerializedBundle[];
}

function parseManifestSignatures(value: any): ManifestSignatures | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (Array.isArray(value)) {
    return parseBundleList(value, "signatures");
  }
  ensureObject(value, "signatures");
  const hasSigsum = Object.hasOwn(value, "sigsum");
  const hasSigstore = Object.hasOwn(value, "sigstore");
  if (hasSigsum && hasSigstore) {
    throw invalid("manifest.signatures must not contain both sigsum and sigstore keys");
  }
  if (hasSigsum) {
    return ensureRecordOfStrings(value.sigsum ?? {}, "signatures.sigsum");
  }
  if (hasSigstore) {
    return parseBundleList(value.sigstore, "signatures.sigstore");
  }
  return ensureRecordOfStrings(value, "signatures");
}

export function parseManifestDocumentObject(parsed: any): ManifestDocument {
  ensureObject(parsed, "manifest");
  const manifest = ensureObject(parsed.manifest, "manifest.manifest");
  manifest.files = ensureRecordOfStrings(manifest.files, "manifest.manifest.files");
  manifest.wasm ??= [];
  if (!Array.isArray(manifest.wasm)) {
    throw invalid("manifest.manifest.wasm must be an array");
  }
  manifest.extra_csp = ensureRecordOfStrings(manifest.extra_csp ?? {}, "manifest.manifest.extra_csp");
  if (manifest.timestamp !== undefined) {
    ensureNonEmptyString(manifest.timestamp, "manifest.manifest.timestamp");
  }
  parsed.signatures = parseManifestSignatures(parsed.signatures);
  return parsed as ManifestDocument;
}

export const loadManifestDocument = async (manifestPath: string): Promise<ManifestDocument> =>
  parseManifestDocumentObject(await readJson(manifestPath, "manifest"));

export const canonicalizeManifestBody = (document: ManifestDocument): string => canonicalize(document.manifest);

export const manifestHash = (document: ManifestDocument): Buffer => sha256(canonicalizeManifestBody(document));
