import { readFile } from "node:fs/promises";
import {
  decodeKeyMaterial,
  ensureObject,
  ensureRecordOfStrings,
  ensureNonEmptyString,
  parseInteger,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "./utils.js";

export type EnrollmentType = "sigsum" | "sigstore";

export interface SigsumEnrollmentInput {
  type: "sigsum";
  policy: string;
  signers: string[];
  threshold: number;
  max_age: number;
  cas_url: string;
  logs?: Record<string, string>;
}

export interface SigstoreEnrollmentInput {
  type: "sigstore";
  trusted_root: Record<string, unknown>;
  claims: Record<string, string>;
  max_age: number;
}

export type EnrollmentInput = SigsumEnrollmentInput | SigstoreEnrollmentInput;

export interface SigsumEnrollmentOptions {
  type?: "sigsum";
  policy: string;
  signers: string[];
  threshold: number | string;
  maxAge: number | string;
  casUrl: string;
  logs?: Record<string, string>;
}

export interface SigstoreEnrollmentOptions {
  type: "sigstore";
  trustedRoot: Record<string, unknown>;
  claims: Record<string, string>;
  maxAge: number | string;
}

export type EnrollmentOptions = SigsumEnrollmentOptions | SigstoreEnrollmentOptions;

export function parseSignerKey(value: string): string {
  return toBase64Url(decodeKeyMaterial(value, "signer keys"));
}

export function buildEnrollmentObject(options: EnrollmentOptions): EnrollmentInput {
  const type = options.type ?? "sigsum";
  if (type === "sigstore") {
    const sigstoreOptions = options as SigstoreEnrollmentOptions;
    const parsedMaxAge = parseInteger(sigstoreOptions.maxAge, "max-age");
    validateMaxAge(parsedMaxAge);
    return {
      type,
      trusted_root: ensureObject(sigstoreOptions.trustedRoot, "trusted_root"),
      claims: normalizeSigstoreClaims(sigstoreOptions.claims, "claims"),
      max_age: parsedMaxAge,
    };
  }

  const { policy, signers, threshold, maxAge, casUrl, logs } = options as SigsumEnrollmentOptions;
  if (signers.length === 0) {
    throw new Error("at least one signer must be provided");
  }

  const normalized = signers.map(parseSignerKey);
  const unique = Array.from(new Set(normalized));
  if (unique.length !== normalized.length) {
    throw new Error("duplicate signer keys detected");
  }

  const parsedThreshold = parseInteger(threshold, "threshold");
  if (parsedThreshold === 0) {
    throw new Error("threshold must be at least 1");
  }
  if (parsedThreshold > unique.length) {
    throw new Error("threshold cannot exceed number of signers");
  }

  const parsedMaxAge = parseInteger(maxAge, "max-age");
  validateMaxAge(parsedMaxAge);
  validateCasUrl(casUrl);

  const normalizedLogs = logs ? ensureRecordOfStrings(logs, "logs") : undefined;

  return {
    type: "sigsum",
    policy,
    signers: unique,
    threshold: parsedThreshold,
    max_age: parsedMaxAge,
    cas_url: casUrl,
    ...(normalizedLogs ? { logs: normalizedLogs } : {}),
  };
}

export function parseEnrollmentObject(parsed: any): EnrollmentInput {
  const typeValue = parsed.type ?? "sigsum";
  if (typeValue !== "sigsum" && typeValue !== "sigstore") {
    throw new Error("enrollment.type must be 'sigsum' or 'sigstore'");
  }

  if (typeValue === "sigstore") {
    const maxAge = parseInteger(parsed.max_age, "max-age");
    validateMaxAge(maxAge);
    return {
      type: "sigstore",
      trusted_root: ensureObject(parsed.trusted_root, "enrollment.trusted_root"),
      claims: normalizeSigstoreClaims(parsed.claims, "enrollment.claims"),
      max_age: maxAge,
    };
  }

  if (typeof parsed.policy !== "string" || parsed.policy.length === 0) {
    throw new Error("enrollment.policy must be a base64url string");
  }
  if (!Array.isArray(parsed.signers)) {
    throw new Error("enrollment.signers must be an array");
  }
  if (parsed.signers.some((s: any) => typeof s !== "string" || s.length === 0)) {
    throw new Error("each signer must be a non-empty string");
  }
  const unique = new Set(parsed.signers);
  if (unique.size !== parsed.signers.length) {
    throw new Error("duplicate signer keys detected in enrollment");
  }

  const threshold = parseInteger(parsed.threshold, "threshold");
  if (threshold === 0) {
    throw new Error("threshold must be at least 1");
  }
  if (threshold > parsed.signers.length) {
    throw new Error("threshold cannot exceed number of signers");
  }

  const maxAge = parseInteger(parsed.max_age, "max-age");
  validateMaxAge(maxAge);
  validateCasUrl(parsed.cas_url);

  const normalizedLogs =
    parsed.logs !== undefined ? ensureRecordOfStrings(parsed.logs, "enrollment.logs") : undefined;

  return {
    type: "sigsum",
    policy: parsed.policy,
    signers: parsed.signers,
    threshold,
    max_age: maxAge,
    cas_url: parsed.cas_url,
    ...(normalizedLogs ? { logs: normalizedLogs } : {}),
  };
}

function normalizeSigstoreClaims(
  value: unknown,
  fieldName: string,
): Record<string, string> {
  const claims = ensureRecordOfStrings(value, fieldName);
  for (const oid of Object.keys(claims)) {
    if (!/^\d+(?:\.\d+)+$/.test(oid)) {
      throw new Error(`${fieldName} keys must be valid OID strings`);
    }
  }
  return claims;
}

export async function loadEnrollment(path: string): Promise<EnrollmentInput> {
  const raw = await readFile(path, "utf8");
  let parsed: any;

  try {
    parsed = JSON.parse(raw);
  } catch (err: any) {
    throw new Error(`failed to parse enrollment JSON: ${err.message}`);
  }

  return parseEnrollmentObject(parsed);
}
