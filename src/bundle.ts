import { EnrollmentInput, parseEnrollmentObject } from "./enrollment.js";
import { ManifestDocument, parseManifestDocumentObject } from "./manifest.js";
import { ensureObject, invalid, readJson } from "./utils.js";

export interface BundleDocument {
  enrollment: EnrollmentInput;
  manifest: ManifestDocument;
}

export async function loadBundleDocument(bundlePath: string): Promise<BundleDocument> {
  const parsed = ensureObject(await readJson(bundlePath, "bundle"), "bundle");
  for (const key of ["enrollment", "manifest", "signatures"]) {
    if (!parsed[key]) {
      throw invalid(`bundle.${key} is required`);
    }
  }
  return {
    enrollment: parseEnrollmentObject(parsed.enrollment),
    manifest: parseManifestDocumentObject({ manifest: parsed.manifest, signatures: parsed.signatures }),
  };
}
