import { EnrollmentTypes, type Enrollment, type SigsumEnrollment, type SigstoreEnrollment } from "@freedomofpress/webcat/webcat/interfaces/bundle";
import { canonicalize } from "@freedomofpress/webcat/webcat/canonicalize";
import { validateSigstoreEnrollment, validateSigsumEnrollment } from "@freedomofpress/webcat/webcat/validators";
import { OID_RE, check, decodeKeyMaterial, ensureObject, invalid, parseInteger, readJson, toBase64Url, validateCasUrl, validateMaxAge } from "./utils.js";

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
    check(validateSigstoreEnrollment(enrollment), "enrollment");
    if (Object.keys(enrollment.claims).some((oid) => !OID_RE.test(oid))) {
      throw invalid("enrollment.claims keys must be OIDs");
    }
    validateMaxAge(enrollment.max_age, "enrollment.max_age");
    return enrollment;
  }
  if (type !== EnrollmentTypes.Sigsum) {
    throw invalid("enrollment.type must be 'sigsum' or 'sigstore'");
  }
  const enrollment = { ...e, type } as SigsumEnrollment;
  check(validateSigsumEnrollment(enrollment), "enrollment");
  for (const signer of enrollment.signers) {
    decodeKeyMaterial(signer, "enrollment.signers");
  }
  if (new Set(enrollment.signers).size !== enrollment.signers.length) {
    throw invalid("enrollment.signers must not contain duplicates");
  }
  validateCasUrl(enrollment.cas_url, "enrollment.cas_url");
  validateMaxAge(enrollment.max_age, "enrollment.max_age");
  return enrollment;
}

// Same canonical form the oracles and the extension hash.
export const canonicalizeEnrollment = (enrollment: Enrollment): string => canonicalize(enrollment)!; // validated enrollments are plain JSON

export const loadEnrollment = async (path: string): Promise<Enrollment> => parseEnrollmentObject(await readJson(path, "enrollment"));
