import { EnrollmentTypes, type Enrollment, type SigsumEnrollment, type SigstoreEnrollment } from "@freedomofpress/webcat/webcat/interfaces/bundle";
import { canonicalize } from "@freedomofpress/webcat/webcat/canonicalize";
import { validateSigstoreEnrollment, validateSigsumEnrollment } from "@freedomofpress/webcat/webcat/validators";
import { parseCompiledPolicy } from "@freedomofpress/sigsum/dist/compiledPolicy.js";
import {
  OID_RE,
  causeOf,
  check,
  decodeKeyMaterial,
  ensureObject,
  invalid,
  parseInteger,
  readJson,
  toBase64Url,
  validateAll,
  validateCasUrl,
  validateMaxAge,
} from "./utils.js";

// Log keys inside a compiled policy, base64url like the keys of enrollment.logs; an Error when the policy does not parse.
function compiledPolicyLogs(policy: unknown): string[] | Error {
  if (typeof policy !== "string" || policy.length === 0) {
    return []; // the library reports the malformed policy itself
  }
  try {
    return parseCompiledPolicy(new Uint8Array(Buffer.from(policy, "base64url"))).logsRaw.map(toBase64Url);
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  }
}

export { EnrollmentTypes, type Enrollment, type SigsumEnrollment, type SigstoreEnrollment };

export const parseSignerKey = (value: string): string => toBase64Url(decodeKeyMaterial(value, "--signer"));

// CLI-flag shape (camelCase, signer keys in any encoding) -> validated enrollment.
export function buildEnrollmentObject(
  o:
    | { type?: "sigsum"; policy: string; signers: string[]; threshold: number | string; maxAge: number | string; casUrl: string; logs?: Record<string, string> }
    | { type: "sigstore"; trustedRoot: unknown; claims: unknown; maxAge: number | string },
): Enrollment {
  const max_age = parseInteger(o.maxAge, "--max-age");
  return parseEnrollmentObject(
    o.type === "sigstore"
      ? { type: "sigstore", trusted_root: o.trustedRoot, claims: o.claims, max_age }
      : { type: "sigsum", policy: o.policy, signers: o.signers.map(parseSignerKey), threshold: parseInteger(o.threshold, "--threshold"), max_age, cas_url: o.casUrl, logs: o.logs },
  );
}

// The extension's validators decide what an enrollment is. The CLI only adds authoring guards the
// extension has no reason to enforce: key encoding, duplicate signers, OID claim keys, CAS URL, max_age range.
export function parseEnrollmentObject(parsed: unknown): Enrollment {
  const e = ensureObject(parsed, "enrollment");
  const type = e.type ?? EnrollmentTypes.Sigsum; // legacy enrollments predate the type field
  if (type === EnrollmentTypes.Sigstore) {
    const enrollment = { ...e, type } as SigstoreEnrollment;
    validateAll([
      () => check(validateSigstoreEnrollment(enrollment), "enrollment"),
      () => {
        if (Object.keys(enrollment.claims ?? {}).some((oid) => !OID_RE.test(oid))) {
          throw invalid("enrollment.claims keys must be OIDs");
        }
      },
      () => validateMaxAge(enrollment.max_age, "enrollment.max_age"),
    ]);
    return enrollment;
  }
  if (type !== EnrollmentTypes.Sigsum) {
    throw invalid("enrollment.type must be 'sigsum' or 'sigstore'");
  }
  const enrollment = { ...e, type } as SigsumEnrollment;
  const signers = Array.isArray(enrollment.signers) ? enrollment.signers : [];
  // The compiled policy is what browsers enforce; enrollment.logs only tells auditors where those logs live. Keep them in step.
  const policyLogs = compiledPolicyLogs(enrollment.policy);
  const listedLogs = typeof enrollment.logs === "object" && enrollment.logs !== null ? Object.entries(enrollment.logs) : [];
  validateAll([
    () => check(validateSigsumEnrollment(enrollment), "enrollment"),
    () => {
      if (policyLogs instanceof Error) {
        throw invalid(`enrollment.policy must be a compiled Sigsum policy: ${causeOf(policyLogs)}`);
      }
    },
    ...(Array.isArray(policyLogs)
      ? policyLogs
          .filter((key) => !listedLogs.some(([k]) => k === key))
          .map((key) => () => {
            throw invalid(`enrollment.logs must give the URL of log ${key}, which the policy trusts`);
          })
      : []),
    ...listedLogs.map(([key, url]) => () => {
      if (Array.isArray(policyLogs) && !policyLogs.includes(key)) {
        throw invalid(`enrollment.logs lists ${key}, which is not a log in the policy`);
      }
      try {
        new URL(String(url));
      } catch (err) {
        throw invalid(`enrollment.logs[${key}] must be a URL: ${causeOf(err)}`);
      }
    }),
    ...signers.map((signer, i) => () => decodeKeyMaterial(String(signer), `enrollment.signers[${i}]`)),
    () => {
      if (new Set(signers).size !== signers.length) {
        throw invalid("enrollment.signers must not contain duplicates");
      }
    },
    () => validateCasUrl(String(enrollment.cas_url), "enrollment.cas_url"),
    () => validateMaxAge(enrollment.max_age, "enrollment.max_age"),
  ]);
  return enrollment;
}

// Same canonical form the oracles and the extension hash.
export const canonicalizeEnrollment = (enrollment: Enrollment): string => canonicalize(enrollment)!; // validated enrollments are plain JSON

export const loadEnrollment = async (path: string): Promise<Enrollment> => parseEnrollmentObject(await readJson(path, "enrollment"));
