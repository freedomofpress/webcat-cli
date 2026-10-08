import {
  OID_RE,
  decodeKeyMaterial,
  ensureObject,
  ensureRecordOfStrings,
  invalid,
  parseInteger,
  readJson,
  toBase64Url,
  validateCasUrl,
  validateMaxAge,
} from "./utils.js";

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

export const parseSignerKey = (value: string): string => toBase64Url(decodeKeyMaterial(value, "--signer"));

function parseThreshold(value: number | string, signerCount: number): number {
  const threshold = parseInteger(value, "enrollment.threshold");
  if (threshold < 1 || threshold > signerCount) {
    throw invalid(`enrollment.threshold must be between 1 and the number of signers (${signerCount})`);
  }
  return threshold;
}

function parseMaxAge(value: number | string): number {
  const maxAge = parseInteger(value, "enrollment.max_age");
  validateMaxAge(maxAge, "enrollment.max_age");
  return maxAge;
}

function parseClaims(value: unknown): Record<string, string> {
  const claims = ensureRecordOfStrings(value, "enrollment.claims");
  if (Object.keys(claims).some((oid) => !OID_RE.test(oid))) {
    throw invalid("enrollment.claims keys must be OIDs");
  }
  return claims;
}

// CLI-flag shape (camelCase, signer keys in any encoding) -> validated enrollment.
export function buildEnrollmentObject(
  o:
    | { type?: "sigsum"; policy: string; signers: string[]; threshold: number | string; maxAge: number | string; casUrl: string; logs?: Record<string, string> }
    | { type: "sigstore"; trustedRoot: unknown; claims: unknown; maxAge: number | string },
): EnrollmentInput {
  return parseEnrollmentObject(
    o.type === "sigstore"
      ? { type: "sigstore", trusted_root: o.trustedRoot, claims: o.claims, max_age: o.maxAge }
      : { type: "sigsum", policy: o.policy, signers: o.signers.map(parseSignerKey), threshold: o.threshold, max_age: o.maxAge, cas_url: o.casUrl, logs: o.logs },
  );
}

export function parseEnrollmentObject(parsed: any): EnrollmentInput {
  ensureObject(parsed, "enrollment");
  const type = parsed.type ?? "sigsum";
  if (type === "sigstore") {
    return {
      type: "sigstore",
      trusted_root: ensureObject(parsed.trusted_root, "enrollment.trusted_root"),
      claims: parseClaims(parsed.claims),
      max_age: parseMaxAge(parsed.max_age),
    };
  }
  if (type !== "sigsum") {
    throw invalid("enrollment.type must be 'sigsum' or 'sigstore'");
  }

  if (typeof parsed.policy !== "string" || parsed.policy.length === 0) {
    throw invalid("enrollment.policy must be a base64url string");
  }
  if (!Array.isArray(parsed.signers) || parsed.signers.length === 0) {
    throw invalid("enrollment.signers must contain at least one signer");
  }
  if (parsed.signers.some((s: unknown) => typeof s !== "string" || s.length === 0)) {
    throw invalid("enrollment.signers entries must be non-empty strings");
  }
  if (new Set(parsed.signers).size !== parsed.signers.length) {
    throw invalid("enrollment.signers must not contain duplicates");
  }
  validateCasUrl(parsed.cas_url, "enrollment.cas_url");

  return {
    type: "sigsum",
    policy: parsed.policy,
    signers: parsed.signers,
    threshold: parseThreshold(parsed.threshold, parsed.signers.length),
    max_age: parseMaxAge(parsed.max_age),
    cas_url: parsed.cas_url,
    ...(parsed.logs !== undefined ? { logs: ensureRecordOfStrings(parsed.logs, "enrollment.logs") } : {}),
  };
}

export const loadEnrollment = async (path: string): Promise<EnrollmentInput> =>
  parseEnrollmentObject(await readJson(path, "enrollment"));
