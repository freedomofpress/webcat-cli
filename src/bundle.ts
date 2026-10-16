import type { WebcatError } from "@freedomofpress/webcat/webcat/interfaces/errors";
import { verifySigstoreManifest, verifySigsumManifest } from "@freedomofpress/webcat/webcat/validators";
import { type Enrollment, EnrollmentTypes, parseEnrollmentObject } from "./enrollment.js";
import { ManifestDocument, asLibraryManifest, parseManifestDocumentObject } from "./manifest.js";
import { ensureObject, invalid, readJson, validateAll, withConsoleOnStderr } from "./utils.js";

export interface BundleDocument {
  enrollment: Enrollment;
  manifest: ManifestDocument;
}

export function parseBundleObject(parsed: unknown, subject = "bundle"): BundleDocument {
  const bundle = ensureObject(parsed, subject);
  validateAll(
    ["enrollment", "manifest", "signatures"].map((key) => () => {
      if (!bundle[key]) {
        throw invalid(`${subject}.${key} is required`);
      }
    }),
  );
  return {
    enrollment: parseEnrollmentObject(bundle.enrollment),
    manifest: parseManifestDocumentObject({ manifest: bundle.manifest, signatures: bundle.signatures }),
  };
}

export const loadBundleDocument = async (bundlePath: string): Promise<BundleDocument> => parseBundleObject(await readJson(bundlePath, "bundle"));

// A verified manifest expires at validUntil (unix seconds); a re-sign is due well before that.
export const RESIGN_WARNING_DAYS = 30;
export function describeValidity(validUntil: number): string {
  const days = Math.floor((validUntil * 1000 - Date.now()) / 86_400_000);
  const until = `valid until ${new Date(validUntil * 1000).toISOString()}, ${days} days left`;
  return days < RESIGN_WARNING_DAYS ? `${until}, WARNING: re-sign and redeploy before it expires` : until;
}

// The extension's own verifiers decide: a WebcatError, or the unix time until which the manifest stays valid.
export async function verifyBundle({ enrollment, manifest: document }: BundleDocument): Promise<WebcatError | number> {
  const sigsum = enrollment.type === EnrollmentTypes.Sigsum;
  const signatures = document.signatures ?? (sigsum ? {} : []);
  if (Array.isArray(signatures) === sigsum) {
    throw invalid(`manifest.signatures contains ${sigsum ? "Sigstore bundles" : "sigsum proofs"} but enrollment.type is ${enrollment.type}`);
  }
  const manifest = asLibraryManifest(document.manifest);
  return sigsum
    ? verifySigsumManifest(enrollment, manifest, signatures as Record<string, string>)
    : withConsoleOnStderr(() => verifySigstoreManifest(enrollment, manifest, signatures as any[]));
}
