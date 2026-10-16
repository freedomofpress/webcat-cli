import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { WebcatError } from "@freedomofpress/webcat/webcat/interfaces/errors";

// Error contract
// - exit 1: the command ran and the answer is negative (verification failed); set via process.exitCode
// - exit 2: invalid input, fix the command line or the file  -> throw invalid(...)
// - exit 3: an external service, tool or the environment failed -> throw external(...)
// Message shape, always lowercase except proper nouns (Sigsum, Sigstore, OIDC, TUF, CAS, URL, OID, SAN, JSON):
//   "<subject> must <rule>"             validation       subject = CLI flag (--max-age) or JSON path from the file role (enrollment.max_age, config.app)
//   "<subject> is required for <ctx>"   missing input
//   "<role> file not found: <path>"     missing file
//   "failed to <do>: <cause>"           external failure
export class CliError extends Error {
  constructor(message: string, readonly exitCode: 2 | 3) {
    super(message);
  }
}
export const invalid = (message: string): CliError => new CliError(message, 2);
export const external = (message: string): CliError => new CliError(message, 3);
export const causeOf = (err: unknown): string =>
  err instanceof Error ? (err.cause instanceof Error ? `${err.message}: ${err.cause.message}` : err.message) : String(err);

// Runs every check and reports all invalid-input problems together, instead of one per run.
// Anything other than an exit-2 error propagates immediately.
export function validateAll(checks: Array<() => unknown>): void {
  const problems: string[] = [];
  for (const run of checks) {
    try {
      run();
    } catch (err) {
      if (!(err instanceof CliError) || err.exitCode !== 2) {
        throw err;
      }
      problems.push(err.message);
    }
  }
  if (problems.length === 1) {
    throw invalid(problems[0]);
  }
  if (problems.length > 1) {
    throw invalid(`${problems.length} problems:\n  - ${problems.join("\n  - ")}`);
  }
}

// fetch that turns transport errors and non-2xx answers into exit-3 errors naming the URL.
export async function fetchOk(url: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(url, init).catch((err) => {
    throw external(`failed to fetch ${url}: ${causeOf(err)}`);
  });
  if (!response.ok) {
    throw external(`failed to fetch ${url}: HTTP ${response.status} ${response.statusText}`);
  }
  return response;
}
export const fetchJson = (url: string, init?: RequestInit): Promise<any> =>
  fetchOk(url, init).then((r) =>
    r.json().catch((err) => {
      throw external(`failed to fetch ${url}: not valid JSON: ${causeOf(err)}`);
    }),
  );

// Validation itself comes from @freedomofpress/webcat, the extension's own validators, so the CLI
// accepts exactly what browsers accept. Its errors carry a code (ERR_WEBCAT_...) plus details.
export const describeWebcatError = (err: WebcatError): string => (err.details?.length ? `${err.code} (${err.details.join(", ")})` : err.code);
export function check(err: WebcatError | null, subject: string): void {
  if (err) {
    throw invalid(`${subject}: ${describeWebcatError(err)}`);
  }
}
// The library reports per-bundle Sigstore exceptions through console.log; keep stdout pipeable.
export async function withConsoleOnStderr<T>(fn: () => Promise<T>): Promise<T> {
  const original = console.log;
  console.log = (...args: unknown[]) => log(args.map(String).join(" "));
  try {
    return await fn();
  } finally {
    console.log = original;
  }
}

const WEEK_SECONDS = 7 * 24 * 60 * 60;
const YEAR_SECONDS = 365 * 24 * 60 * 60;
const HEX_RE = /^[0-9a-fA-F]+$/;
export const OID_RE = /^\d+(?:\.\d+)+$/;

export const sha256 = (data: Uint8Array | string): Buffer => createHash("sha256").update(data).digest();
export const toBase64Url = (input: Uint8Array): string => Buffer.from(input).toString("base64url");
export const hexToBase64Url = (hex: string): string => Buffer.from(hex, "hex").toString("base64url");

export const readText = (filePath: string, label: string): Promise<string> =>
  readFile(filePath, "utf8").catch((err) => {
    throw err.code === "ENOENT" ? invalid(`${label} file not found: ${filePath}`) : external(`failed to read ${label} file ${filePath}: ${err.message}`);
  });

export async function readJson(filePath: string, label: string): Promise<any> {
  const raw = await readText(filePath, label);
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw invalid(`${label} file ${filePath} is not valid JSON: ${causeOf(err)}`);
  }
}

// Artifacts go to --output or stdout; diagnostics go to stderr so stdout stays pipeable JSON.
export async function writeOutput(filePath: string | undefined, contents: string): Promise<void> {
  if (filePath) {
    await writeFile(filePath, contents);
  } else {
    process.stdout.write(contents + "\n");
  }
}

export const log = (message: string): void => void process.stderr.write(message + "\n");

export function decodeKeyMaterial(value: string, name: string): Buffer {
  const trimmed = value.trim();
  let bytes: Buffer;
  if (HEX_RE.test(trimmed)) {
    if (trimmed.length % 2 !== 0) {
      throw invalid(`${name} must contain an even number of hex characters`);
    }
    bytes = Buffer.from(trimmed, "hex");
  } else {
    bytes = Buffer.from(trimmed, "base64url"); // accepts both base64 and base64url alphabets
  }
  if (bytes.length !== 32) {
    throw invalid(`${name} must be a 32-byte ed25519 public key in hex or base64`);
  }
  return bytes;
}

export function parseInteger(value: number | string, name: string): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw invalid(`${name} must be a non-negative integer`);
  }
  return n;
}

export function validateMaxAge(maxAge: number, name: string): void {
  if (maxAge <= WEEK_SECONDS || maxAge >= YEAR_SECONDS) {
    throw invalid(`${name} must be between one week and one year, in seconds`);
  }
}

export function validateCasUrl(urlString: string, name: string): void {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch (err) {
    throw invalid(`${name} must be a valid URL: ${causeOf(err)}`);
  }
  if (parsed.protocol !== "https:") {
    throw invalid(`${name} must use https://`);
  }
}

export function ensureObject(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalid(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

export const hashPolicyBytes = (encodedPolicy: string): string => toBase64Url(sha256(Buffer.from(encodedPolicy, "base64url")));
