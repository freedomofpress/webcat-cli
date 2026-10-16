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
  readText,
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

// The raw 32-byte key inside an OpenSSH "ssh-ed25519 <base64> comment" line, as a base64url enrollment signer.
export function signerFromOpenSsh(line: string): string {
  const [type, blob] = line.trim().split(/\s+/);
  const raw = type === "ssh-ed25519" && blob ? Buffer.from(blob, "base64") : Buffer.alloc(0);
  if (raw.length !== 51) {
    throw invalid(`expected an OpenSSH ed25519 public key line, got '${line.trim().slice(0, 40)}'`);
  }
  return toBase64Url(raw.subarray(-32)); // string "ssh-ed25519" + 32-byte key, both length-prefixed
}

// --signer values: hex, base64, or the path of an OpenSSH .pub file (e.g. a hardware key reachable through ssh-agent).
export const signerFromValue = async (value: string): Promise<string> =>
  value.endsWith(".pub") ? signerFromOpenSsh(await readText(value, "signer public key")) : parseSignerKey(value);

// CLI-flag shape (camelCase, signers as hex, base64 or OpenSSH .pub paths) -> validated enrollment.
export async function buildEnrollmentObject(
  o:
    | { type?: "sigsum"; policy: string; signers: string[]; threshold: number | string; maxAge: number | string; casUrl: string; logs?: Record<string, string> }
    | { type: "sigstore"; trustedRoot: unknown; claims: unknown; maxAge: number | string },
): Promise<Enrollment> {
  const max_age = parseInteger(o.maxAge, "--max-age");
  if (o.type === "sigstore") {
    return parseEnrollmentObject({ type: "sigstore", trusted_root: o.trustedRoot, claims: o.claims, max_age }, { authoring: true });
  }
  const signers = await Promise.all(o.signers.map(signerFromValue));
  return parseEnrollmentObject({ type: "sigsum", policy: o.policy, signers, threshold: parseInteger(o.threshold, "--threshold"), max_age, cas_url: o.casUrl, logs: o.logs }, { authoring: true });
}

// The extension's validators decide what an enrollment is; that is all that is checked on anything read from disk or
// the network, so the CLI accepts exactly what browsers accept. When authoring (create, init) the CLI adds guards the
// extension has no reason to enforce: key encoding, duplicate signers, OID claim keys, CAS URL, max_age range, logs <-> policy.
export function parseEnrollmentObject(parsed: unknown, { authoring = false } = {}): Enrollment {
  const e = ensureObject(parsed, "enrollment");
  if (e.type !== EnrollmentTypes.Sigsum && e.type !== EnrollmentTypes.Sigstore) {
    throw invalid("enrollment.type must be 'sigsum' or 'sigstore'; browsers reject enrollments without it");
  }
  const encodable = () => {
    if (canonicalize(e) === null) {
      throw invalid("enrollment must contain only strings, integers, booleans, null, arrays and objects");
    }
  };
  if (e.type === EnrollmentTypes.Sigstore) {
    const enrollment = e as unknown as SigstoreEnrollment;
    validateAll([
      () => check(validateSigstoreEnrollment(enrollment), "enrollment"),
      encodable,
      ...(authoring
        ? [
            () => {
              if (Object.keys(enrollment.claims ?? {}).some((oid) => !OID_RE.test(oid))) {
                throw invalid("enrollment.claims keys must be OIDs");
              }
            },
            () => validateMaxAge(enrollment.max_age, "enrollment.max_age"),
          ]
        : []),
    ]);
    return enrollment;
  }
  const enrollment = e as unknown as SigsumEnrollment;
  const signers = Array.isArray(enrollment.signers) ? enrollment.signers : [];
  const policyLogs = authoring ? compiledPolicyLogs(enrollment.policy) : [];
  const listedLogs = typeof enrollment.logs === "object" && enrollment.logs !== null ? Object.entries(enrollment.logs) : [];
  validateAll([
    () => check(validateSigsumEnrollment(enrollment), "enrollment"),
    encodable,
    ...(authoring
      ? [
          ...signers.map((signer, i) => () => decodeKeyMaterial(String(signer), `enrollment.signers[${i}]`)),
          () => {
            if (new Set(signers).size !== signers.length) {
              throw invalid("enrollment.signers must not contain duplicates");
            }
          },
          () => validateCasUrl(String(enrollment.cas_url), "enrollment.cas_url"),
          () => validateMaxAge(enrollment.max_age, "enrollment.max_age"),
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
        ]
      : []),
  ]);
  return enrollment;
}

// Same canonical form the oracles and the extension hash.
export function canonicalizeEnrollment(enrollment: Enrollment): string {
  const canonical = canonicalize(enrollment);
  if (canonical === null) {
    throw invalid("enrollment must contain only strings, integers, booleans, null, arrays and objects");
  }
  return canonical;
}

export const loadEnrollment = async (path: string): Promise<Enrollment> => parseEnrollmentObject(await readJson(path, "enrollment"));
