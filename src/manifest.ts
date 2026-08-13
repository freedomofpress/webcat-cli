import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import type { SerializedBundle } from "@sigstore/bundle";
import { canonicalize } from "./canonicalize.js";
import {
  ensureAbsolutePath,
  ensureNonEmptyString,
  ensureRecordOfStrings,
  toBase64Url,
} from "./utils.js";
import { validateCSP } from "webcat/webcat/validators";

const WASM_EXTENSION = ".wasm";

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

export interface ManifestDocument {
  manifest: ManifestContent;
  signatures?: ManifestSignatures;
}

export type ManifestSignatures = Record<string, string> | SerializedBundle[];

export interface DirectoryScanResult {
  files: Map<string, string>;
  wasm: Set<string>;
}

export interface DirectoryScanOptions {
  includeDotfiles?: boolean;
  excludePaths?: string[];
}

export async function loadManifestConfig(configPath: string): Promise<ManifestConfig> {
  const raw = await readFile(configPath, "utf8");
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse manifest config JSON: ${err.message}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("manifest config must be a JSON object");
  }

  const app = ensureNonEmptyString(parsed.app, "config.app");
  try {
    new URL(app);
  } catch (err: any) {
    throw new Error(`config.app must be a valid URL: ${err.message}`);
  }

  const version = ensureNonEmptyString(parsed.version, "config.version");
  const defaultCsp = ensureNonEmptyString(parsed.default_csp, "config.default_csp");
  try {
    await validateCSP(parsed.default_csp, new Set());
  } catch(err: any) {
    throw new Error(`config.default_csp: ${err.message}`)
  }
  // Remove leading / to default_index. It is automatically appended to dirs whcih
  // have a ending /
  let defaultIndex = ensureNonEmptyString(parsed.default_index, "config.default_index");
  defaultIndex = defaultIndex.replace(/^\/+/, ""); // optional: normalize if user wrote "/index.html"
  const defaultFallback = ensureAbsolutePath(parsed.default_fallback, "config.default_fallback");

  let wasmList: string[] = [];
  if (parsed.wasm === undefined) {
    wasmList = [];
  } else if (!Array.isArray(parsed.wasm)) {
    throw new Error("config.wasm must be an array of strings");
  } else {
    wasmList = parsed.wasm.map((value: any, index: number) => {
      if (typeof value !== "string" || value.trim().length === 0) {
        throw new Error(`config.wasm[${index}] must be a non-empty string`);
      }
      return value.trim();
    });
  }

  const extraCspRaw = parsed.extra_csp ?? {};
  const extraCspRecord = ensureRecordOfStrings(extraCspRaw, "config.extra_csp");
  for (const key of Object.keys(extraCspRecord)) {
    if (!key.startsWith("/")) {
      throw new Error(`config.extra_csp keys must start with '/': ${key}`);
    }
    try {
      await validateCSP(extraCspRecord[key], new Set());
    } catch (err: any) {
      throw new Error(`config.extra_csp["${key}"]: ${err.message}`);
    }
  }

  return {
    app,
    version,
    default_csp: defaultCsp,
    default_index: defaultIndex,
    default_fallback: defaultFallback,
    wasm: wasmList,
    extra_csp: extraCspRecord,
  };
}

export async function scanDirectory(
  rootDir: string,
  options: DirectoryScanOptions = {},
): Promise<DirectoryScanResult> {
  const absoluteRoot = path.resolve(rootDir);
  const result: DirectoryScanResult = {
    files: new Map(),
    wasm: new Set(),
  };
  const includeDotfiles = options.includeDotfiles ?? false;
  const excludePaths = (options.excludePaths ?? [])
    .map((raw) => raw.trim())
    .filter(Boolean)
    .map((raw) => raw.replace(/\\/g, "/"))
    .map((raw) => raw.replace(/^\.?\/*/, ""))
    .map((raw) => raw.replace(/\/+$/, ""));

  const shouldExclude = (relativePath: string): boolean => {
    if (excludePaths.length === 0) {
      return false;
    }
    const normalized = relativePath.replace(/\\/g, "/");
    return excludePaths.some((exclude) => normalized === exclude || normalized.startsWith(`${exclude}/`));
  };

  async function walk(currentDir: string, relativePrefix: string): Promise<void> {
    const entries = await readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!includeDotfiles && entry.name.startsWith(".")) {
        continue;
      }
      const relativePath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;
      if (shouldExclude(relativePath)) {
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
      const digest = createHash("sha256").update(contents).digest();
      const encoded = toBase64Url(digest);
      if (path.extname(entry.name).toLowerCase() === WASM_EXTENSION) {
        result.wasm.add(encoded);
      } else {
        result.files.set(manifestPath, encoded);
      }
    }
  }

  await walk(absoluteRoot, "");
  return result;
}

export function parseManifestDocumentObject(parsed: any): ManifestDocument {
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("manifest file must contain a JSON object");
  }
  if (typeof parsed.manifest !== "object" || parsed.manifest === null || Array.isArray(parsed.manifest)) {
    throw new Error("manifest file must include a 'manifest' object");
  }
  parsed.signatures = parseManifestSignatures(parsed.signatures);
  const manifest = parsed.manifest;
  if (typeof manifest.files !== "object" || manifest.files === null || Array.isArray(manifest.files)) {
    throw new Error("manifest.manifest.files must be an object");
  }
  if (manifest.wasm === undefined) {
    manifest.wasm = [];
  } else if (!Array.isArray(manifest.wasm)) {
    throw new Error("manifest.manifest.wasm must be an array");
  }
  if (manifest.extra_csp === undefined) {
    manifest.extra_csp = {};
  } else if (typeof manifest.extra_csp !== "object" || manifest.extra_csp === null || Array.isArray(manifest.extra_csp)) {
    throw new Error("manifest.manifest.extra_csp must be an object");
  }
  if (manifest.timestamp !== undefined) {
    if (typeof manifest.timestamp !== "string" || manifest.timestamp.length === 0) {
      throw new Error("manifest.manifest.timestamp must be a string");
    }
  }
  return parsed as ManifestDocument;
}

function parseManifestSignatures(value: any): ManifestSignatures | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (Array.isArray(value)) {
    value.forEach((entry: any, index: number) => {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        throw new Error(`signatures[${index}] must be an object`);
      }
    });
    return value as SerializedBundle[];
  }
  if (typeof value !== "object") {
    throw new Error("signatures must be an object or array");
  }

  const hasSigsum = Object.prototype.hasOwnProperty.call(value, "sigsum");
  const hasSigstore = Object.prototype.hasOwnProperty.call(value, "sigstore");

  if (!hasSigsum && !hasSigstore) {
    return ensureRecordOfStrings(value, "signatures");
  }

  if (hasSigsum && hasSigstore) {
    throw new Error("signatures cannot include both sigsum and sigstore keys");
  }
  if (hasSigsum) {
    return ensureRecordOfStrings(value.sigsum ?? {}, "signatures.sigsum");
  }
  if (!Array.isArray(value.sigstore)) {
    throw new Error("signatures.sigstore must be an array");
  }
  value.sigstore.forEach((entry: any, index: number) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`signatures.sigstore[${index}] must be an object`);
    }
  });
  return value.sigstore as SerializedBundle[];
}

export async function loadManifestDocument(manifestPath: string): Promise<ManifestDocument> {
  const raw = await readFile(manifestPath, "utf8");
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse manifest JSON: ${err.message}`);
  }
  return parseManifestDocumentObject(parsed);
}

export function canonicalizeManifestBody(document: ManifestDocument): string {
  return canonicalize(document.manifest);
}
